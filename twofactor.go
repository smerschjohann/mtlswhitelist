package mtlswhitelist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Session payload: "identity:nonce:timestamp"
const sessionPayloadVersion = "v1"

func (a *MTlsOrWhitelist) is2FAAuthenticated(req *http.Request) bool {
	cookie, err := req.Cookie(a.rawConfig.TwoFactor.CookieName)
	if err != nil {
		return false
	}
	payload, ok := a.verifyValue(cookie.Value)
	if !ok {
		return false
	}

	parts := strings.Split(payload, "|")
	if len(parts) != 4 || parts[0] != sessionPayloadVersion {
		return false
	}

	identity := parts[1]
	// parts[2] is nonce
	timestampStr := parts[3]

	// Verify identity matches current request (case-insensitive)
	_, canonicalID, ok := a.getUserData(req)
	if !ok || identity != canonicalID {
		return false
	}

	// Verify timestamp
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil || time.Since(timestamp) > 24*time.Hour {
		return false
	}

	return true
}

func (a *MTlsOrWhitelist) signValue(value string) string {
	if a.rawConfig.TwoFactor.CookieKey == "" {
		panic("TwoFactor enabled but cookieKey is empty")
	}

	mac := hmac.New(sha256.New, []byte(a.rawConfig.TwoFactor.CookieKey))
	mac.Write([]byte(value))
	signature := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature) + "." + value
}

func (a *MTlsOrWhitelist) verifyValue(signedValue string) (string, bool) {
	if a.rawConfig.TwoFactor.CookieKey == "" {
		return "", false
	}
	parts := strings.SplitN(signedValue, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	sig, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	value := parts[1]
	mac := hmac.New(sha256.New, []byte(a.rawConfig.TwoFactor.CookieKey))
	mac.Write([]byte(value))
	expectedSig := mac.Sum(nil)
	if hmac.Equal(sig, expectedSig) {
		return value, true
	}
	return "", false
}

func (a *MTlsOrWhitelist) getSessionPayload(identity string) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		// Should never happen with crypto/rand
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	return fmt.Sprintf("%s|%s|%s|%s", sessionPayloadVersion, identity, nonceB64, time.Now().Format(time.RFC3339))
}

func (a *MTlsOrWhitelist) getUserData(req *http.Request) (data []string, canonicalID string, ok bool) {
	// 1. Detect base identities
	identities := []string{}
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		identities = append(identities, req.TLS.PeerCertificates[0].Subject.CommonName)
		identities = append(identities, req.TLS.PeerCertificates[0].SerialNumber.String())
	}
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		clientIP = req.RemoteAddr
	}
	identities = append(identities, clientIP)
	

	// 2. Try matching
	for _, id := range identities {
		// Exact/Case-insensitive matching
		for key, val := range a.rawConfig.TwoFactor.Users {
			if strings.EqualFold(key, id) {
				return a.convertUserData(val), key, true
			}
		}
	}

	// 3. Try IP range matching
	ip := net.ParseIP(clientIP)
	if ip != nil {
		for key, val := range a.rawConfig.TwoFactor.Users {
			if strings.Contains(key, "/") {
				_, ipNet, err := net.ParseCIDR(key)
				if err == nil && ipNet.Contains(ip) {
					return a.convertUserData(val), key, true
				}
			}
		}
	}

	return nil, "", false
}

func (a *MTlsOrWhitelist) convertUserData(val interface{}) []string {
	var result []string
	
	processItem := func(item interface{}) {
		if item == nil {
			return
		}

		// Handle many map types that Yaegi might use
		itemMap := make(map[string]interface{})
		isMap := false
		
		switch v := item.(type) {
		case string:
			trimmed := strings.Trim(strings.TrimSpace(v), "\"'")
			result = append(result, trimmed)
			return
		case []byte:
			s := string(v)
			trimmed := strings.Trim(strings.TrimSpace(s), "\"'")
			result = append(result, trimmed)
			return
		case map[string]interface{}:
			itemMap = v
			isMap = true
		case map[interface{}]interface{}:
			for mk, mv := range v {
				itemMap[fmt.Sprintf("%v", mk)] = mv
			}
			isMap = true
		}

		if isMap {
			// Check for TOTP-in-map format first
			if totp, ok := itemMap["totp"].(string); ok {
				trimmed := strings.Trim(strings.TrimSpace(totp), "\"'")
				result = append(result, trimmed)
				return
			}
			if secret, ok := itemMap["secret"].(string); ok {
				trimmed := strings.Trim(strings.TrimSpace(secret), "\"'")
				result = append(result, trimmed)
				return
			}

			// Otherwise, treat as Passkey (marshal)
			cleaned := a.cleanUpForJSON(item)
			b, err := json.Marshal(cleaned)
			if err == nil {
				result = append(result, string(b))
			}
			return
		}

		// Fallback for other possible types
		s := fmt.Sprintf("%v", item)
		if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "map[") {
			// Looks like a map/struct that wasn't caught by type switch
			cleaned := a.cleanUpForJSON(item)
			b, _ := json.Marshal(cleaned)
			result = append(result, string(b))
		} else {
			trimmed := strings.Trim(strings.TrimSpace(s), "\"'")
			result = append(result, trimmed)
		}
	}

	switch v := val.(type) {
	case []interface{}:
		for _, item := range v {
			processItem(item)
		}
	default:
		processItem(val)
	}

	return result
}

func (a *MTlsOrWhitelist) cleanUpForJSON(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[fmt.Sprintf("%v", k)] = a.cleanUpForJSON(v)
		}
		return m2
	case map[string]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k] = a.cleanUpForJSON(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = a.cleanUpForJSON(v)
		}
	}
	return i
}

func (a *MTlsOrWhitelist) redirectTo2FA(rw http.ResponseWriter, req *http.Request) {
	// For API requests or similar, we might want to return 401 instead of redirecting
	// For now, let's redirect to the login page
	loginURL := a.rawConfig.TwoFactor.PathPrefix + "login?redirect=" + req.URL.String()
	http.Redirect(rw, req, loginURL, http.StatusFound)
}

func (a *MTlsOrWhitelist) Serve2FA(rw http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if strings.HasSuffix(path, "/login") {
		a.serveLoginPage(rw, req)
		return
	}
	if strings.HasSuffix(path, "/register") {
		a.serveRegisterPage(rw, req)
		return
	}
	if strings.HasSuffix(path, "/verify-totp") {
		a.handleVerifyTOTP(rw, req)
		return
	}
	if strings.HasSuffix(path, "/webauthn/challenge") {
		a.handleWebAuthnChallenge(rw, req)
		return
	}
	if strings.HasSuffix(path, "/webauthn/verify") {
		a.handleWebAuthnVerify(rw, req)
		return
	}
	http.NotFound(rw, req)
}


func (a *MTlsOrWhitelist) handleVerifyTOTP(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "invalid form", http.StatusBadRequest)
		return
	}

	code := strings.TrimSpace(req.FormValue("code"))
	redirect := req.FormValue("redirect")

	// Identify user
	secrets, canonicalID, ok := a.getUserData(req)

	if ok {
		valid := false
		for _, secret := range secrets {
			if a.VerifyTOTP(code, secret) {
				valid = true
				break
			}
		}

		if valid {
			payload := a.getSessionPayload(canonicalID)
			http.SetCookie(rw, &http.Cookie{
				Name:     a.rawConfig.TwoFactor.CookieName,
				Value:    a.signValue(payload),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
			http.Redirect(rw, req, redirect, http.StatusFound)
			return
		}
	}
	
	http.Error(rw, "Invalid code", http.StatusUnauthorized)
}

func (a *MTlsOrWhitelist) VerifyTOTP(code string, secret string) bool {
	// Secret might be padded base32
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
	}
	if err != nil {
		return false
	}

	// Hotp(K, T) = Truncate(HMAC-SHA-1(K, T))
	// T = (Current Time - T0) / X
	t := time.Now().Unix() / 30
	c0 := a.getOTP(key, t)
	cm1 := a.getOTP(key, t-1)
	cp1 := a.getOTP(key, t+1)
	cm2 := a.getOTP(key, t-2)
	cp2 := a.getOTP(key, t+2)

	res := (c0 == code || cm1 == code || cp1 == code || cm2 == code || cp2 == code)
	if !res {
		fmt.Printf("TOTP verification failed. Code: %s, Expected: [%s, %s, %s, %s, %s], Server Time: %s, Secret: %s...\n", code, cm2, cm1, c0, cp1, cp2, time.Now().Format(time.RFC3339), secret[:5])
	}
	return res
}

func (a *MTlsOrWhitelist) getOTP(key []byte, t int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binaryCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	otp := binaryCode % 1000000
	return fmt.Sprintf("%06d", otp)
}


func (a *MTlsOrWhitelist) checkTOTP(key []byte, t int64, code string) bool {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binaryCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	otp := binaryCode % 1000000
	return fmt.Sprintf("%06d", otp) == code
}

func (a *MTlsOrWhitelist) handleWebAuthnChallenge(rw http.ResponseWriter, req *http.Request) {
	// Identify user
	userDataList, canonicalID, ok := a.getUserData(req)
	if !ok {
		http.Error(rw, "User not found for 2FA", http.StatusForbidden)
		return
	}

	var allowCredentials []map[string]interface{}
	for _, data := range userDataList {
		var passkey map[string]interface{}
		err := json.Unmarshal([]byte(data), &passkey)
		if err == nil {
			if credID, ok := passkey["credentialId"].(string); ok {
				allowCredentials = append(allowCredentials, map[string]interface{}{
					"type": "public-key",
					"id":   credID,
				})
			}
		}
	}

	if len(allowCredentials) == 0 {
		http.Error(rw, "No passkey registered for user", http.StatusForbidden)
		return
	}

	// Generate random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)
	// Payload for challenge cookie: "challenge|identity|timestamp"
	payload := fmt.Sprintf("%s|%s|%s", challengeB64, canonicalID, time.Now().Format(time.RFC3339))

	// Store signed challenge in cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     "webauthn_challenge",
		Value:    a.signValue(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(5 * time.Minute),
	})

	options := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge":        challengeB64,
			"rpId":             a.rawConfig.TwoFactor.RPID,
			"allowCredentials": allowCredentials,
			"userVerification": "preferred",
			"timeout":          60000,
		},
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(options)
}

func (a *MTlsOrWhitelist) handleWebAuthnVerify(rw http.ResponseWriter, req *http.Request) {
	var verifyReq WebAuthnVerifyRequest
	if err := json.NewDecoder(req.Body).Decode(&verifyReq); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}

	// 1. Verify challenge
	challengeCookie, err := req.Cookie("webauthn_challenge")
	if err != nil {
		http.Error(rw, "missing challenge", http.StatusForbidden)
		return
	}

	// Delete challenge cookie after reading it
	http.SetCookie(rw, &http.Cookie{
		Name:     "webauthn_challenge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	payload, ok := a.verifyValue(challengeCookie.Value)
	if !ok {
		http.Error(rw, "invalid challenge signature", http.StatusForbidden)
		return
	}

	parts := strings.Split(payload, "|")
	if len(parts) != 3 {
		http.Error(rw, "invalid challenge payload", http.StatusForbidden)
		return
	}
	challengeB64 := parts[0]
	challengeIdentity := parts[1]
	challengeTimestampStr := parts[2]

	// 2. Identify current user
	userDataList, canonicalID, ok := a.getUserData(req)
	if !ok {
		http.Error(rw, "user not found", http.StatusForbidden)
		return
	}

	// Verify challenge identity matches current
	if challengeIdentity != canonicalID {
		http.Error(rw, "challenge identity mismatch", http.StatusForbidden)
		return
	}

	// Verify challenge timestamp
	challengeTimestamp, err := time.Parse(time.RFC3339, challengeTimestampStr)
	if err != nil || time.Since(challengeTimestamp) > 5*time.Minute {
		http.Error(rw, "challenge expired", http.StatusForbidden)
		return
	}

	// 3. Parse and verify clientDataJSON
	clientDataBytes, _ := base64.StdEncoding.DecodeString(verifyReq.Response.ClientDataJSON)
	var clientData ClientDataJSON
	json.Unmarshal(clientDataBytes, &clientData)

	if clientData.Type != "webauthn.get" {
		http.Error(rw, "invalid type", http.StatusForbidden)
		return
	}
	// Challenges in clientDataJSON are base64url encoded
	clientChallengeBytes, _ := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if len(clientChallengeBytes) == 0 {
		clientChallengeBytes, _ = base64.StdEncoding.DecodeString(clientData.Challenge)
	}
	cookieChallengeBytes, _ := base64.StdEncoding.DecodeString(challengeB64)

	if !bytes.Equal(clientChallengeBytes, cookieChallengeBytes) {
		http.Error(rw, "challenge mismatch", http.StatusForbidden)
		return
	}

	// 4. Try to verify against any of the user's registered passkeys
	authDataBytes, _ := base64.StdEncoding.DecodeString(verifyReq.Response.AuthenticatorData)
	clientDataHash := sha256.Sum256(clientDataBytes)
	signedData := append(authDataBytes, clientDataHash[:]...)
	signature, _ := base64.StdEncoding.DecodeString(verifyReq.Response.Signature)
	dataHash := sha256.Sum256(signedData)

	for _, userData := range userDataList {
		var passkey map[string]interface{}
		err = json.Unmarshal([]byte(userData), &passkey)
		if err != nil {
			continue
		}

		// Double check algorithm if provided
		alg := -7 // Default ES256
		if v, ok := passkey["alg"]; ok {
			switch tv := v.(type) {
			case int:
				alg = tv
			case float64:
				alg = int(tv)
			case string:
				if i, err := strconv.Atoi(tv); err == nil {
					alg = i
				}
			}
		}
		if alg != -7 {
			continue
		}

		publicKeyB64, _ := passkey["publicKey"].(string)
		pubKeyBytes, _ := base64.StdEncoding.DecodeString(publicKeyB64)
		pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			continue
		}

		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}

		if ecdsa.VerifyASN1(ecdsaPubKey, dataHash[:], signature) {
			// Success!
			sessionPayload := a.getSessionPayload(canonicalID)
			http.SetCookie(rw, &http.Cookie{
				Name:     a.rawConfig.TwoFactor.CookieName,
				Value:    a.signValue(sessionPayload),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
			rw.WriteHeader(http.StatusOK)
			return
		}
	}

	http.Error(rw, "passkey verification failed", http.StatusForbidden)
}



type WebAuthnVerifyRequest struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

type ClientDataJSON struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}




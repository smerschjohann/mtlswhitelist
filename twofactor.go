package mtlswhitelist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA1 is required for TOTP
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

// Session payload: "identity:nonce:timestamp".
const (
	sessionPayloadVersion = "v1"
	nonceSize             = 16
	secretSize            = 20
	challengeSize         = 32
	maxTimeDrift          = 24 * time.Hour
	challengeExpiry       = 5 * time.Minute
	totpTimeHeader        = 8
	totpMod               = 1000000
	totpStep              = 30
	webAuthnTimeout       = 60000
)

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
	if err != nil || time.Since(timestamp) > maxTimeDrift {
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
	parts := strings.SplitN(signedValue, ".", 2) //nolint:mnd
	if len(parts) != 2 {                         //nolint:mnd
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
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	return fmt.Sprintf("%s|%s|%s|%s", sessionPayloadVersion, identity, nonceB64, time.Now().Format(time.RFC3339))
}

func (a *MTlsOrWhitelist) getUserData(req *http.Request) ([]string, string, bool) {
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

		// Handle simple types first
		switch v := item.(type) {
		case string:
			result = append(result, strings.Trim(strings.TrimSpace(v), "\"'"))
			return
		case []byte:
			result = append(result, strings.Trim(strings.TrimSpace(string(v)), "\"'"))
			return
		}

		// Handle map types (Yaegi support)
		itemMap, isMap := a.extractMap(item)
		if isMap {
			if s, found := a.extractSecret(itemMap); found {
				result = append(result, s)
				return
			}

			// Treat as Passkey
			if b, err := json.Marshal(a.cleanUpForJSON(item)); err == nil {
				result = append(result, string(b))
			}
			return
		}

		// Fallback for other types
		s := fmt.Sprintf("%v", item)
		if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "map[") {
			if b, err := json.Marshal(a.cleanUpForJSON(item)); err == nil {
				result = append(result, string(b))
			}
		} else {
			result = append(result, strings.Trim(strings.TrimSpace(s), "\"'"))
		}
	}

	if v, ok := val.([]interface{}); ok {
		for _, item := range v {
			processItem(item)
		}
	} else {
		processItem(val)
	}

	return result
}

func (a *MTlsOrWhitelist) extractMap(item interface{}) (map[string]interface{}, bool) {
	switch v := item.(type) {
	case map[string]interface{}:
		return v, true
	case map[interface{}]interface{}:
		itemMap := make(map[string]interface{})
		for mk, mv := range v {
			itemMap[fmt.Sprintf("%v", mk)] = mv
		}
		return itemMap, true
	default:
		return nil, false
	}
}

func (a *MTlsOrWhitelist) extractSecret(itemMap map[string]interface{}) (string, bool) {
	if totp, ok := itemMap["totp"].(string); ok {
		return strings.Trim(strings.TrimSpace(totp), "\"'"), true
	}
	if secret, ok := itemMap["secret"].(string); ok {
		return strings.Trim(strings.TrimSpace(secret), "\"'"), true
	}
	return "", false
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
				Expires:  time.Now().Add(maxTimeDrift),
			})
			http.Redirect(rw, req, redirect, http.StatusFound)
			return
		}
	}

	http.Error(rw, "Invalid code", http.StatusUnauthorized)
}

func (a *MTlsOrWhitelist) VerifyTOTP(code, secret string) bool {
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
	t := time.Now().Unix() / totpStep
	c0 := a.getOTP(key, t)
	cm1 := a.getOTP(key, t-1)
	cp1 := a.getOTP(key, t+1)
	cm2 := a.getOTP(key, t-2) //nolint:mnd
	cp2 := a.getOTP(key, t+2) //nolint:mnd

	res := (c0 == code || cm1 == code || cp1 == code || cm2 == code || cp2 == code)
	if !res {
		fmt.Printf("TOTP verification failed. Code: %s, Expected: [%s, %s, %s, %s, %s], Server Time: %s, Secret: %s...\n", code, cm2, cm1, c0, cp1, cp2, time.Now().Format(time.RFC3339), secret[:5])
	}
	return res
}

func (a *MTlsOrWhitelist) getOTP(key []byte, t int64) string {
	buf := make([]byte, totpTimeHeader)
	binary.BigEndian.PutUint64(buf, uint64(t)) // #nosec G115

	// #nosec G505 -- SHA1 is used for TOTP (RFC 6238) which is the industry standard
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf                //nolint:mnd
	binaryCode := (uint32(sum[offset])&0x7f)<<24 | //nolint:mnd
		(uint32(sum[offset+1])&0xff)<<16 | //nolint:mnd
		(uint32(sum[offset+2])&0xff)<<8 | //nolint:mnd
		(uint32(sum[offset+3]) & 0xff) //nolint:mnd

	otp := binaryCode % totpMod
	return fmt.Sprintf("%06d", otp)
}

func (a *MTlsOrWhitelist) checkTOTP(key []byte, t int64, code string) bool {
	buf := make([]byte, totpTimeHeader)
	binary.BigEndian.PutUint64(buf, uint64(t)) // #nosec G115

	// #nosec G505 -- SHA1 is used for TOTP (RFC 6238) which is the industry standard
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf                //nolint:mnd
	binaryCode := (uint32(sum[offset])&0x7f)<<24 | //nolint:mnd
		(uint32(sum[offset+1])&0xff)<<16 | //nolint:mnd
		(uint32(sum[offset+2])&0xff)<<8 | //nolint:mnd
		(uint32(sum[offset+3]) & 0xff) //nolint:mnd

	otp := binaryCode % totpMod
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
	challenge := make([]byte, challengeSize)
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
		Expires:  time.Now().Add(challengeExpiry),
	})

	options := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge":        challengeB64,
			"rpId":             a.rawConfig.TwoFactor.RPID,
			"allowCredentials": allowCredentials,
			"userVerification": "preferred",
			"timeout":          webAuthnTimeout,
		},
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(options); err != nil {
		fmt.Printf("Error encoding WebAuthn challenge: %v\n", err)
	}
}

func (a *MTlsOrWhitelist) handleWebAuthnVerify(rw http.ResponseWriter, req *http.Request) {
	var verifyReq WebAuthnVerifyRequest
	if err := json.NewDecoder(req.Body).Decode(&verifyReq); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}

	// 1. Verify challenge
	challengeB64, canonicalID, ok := a.verifyWebAuthnChallenge(rw, req)
	if !ok {
		return
	}

	// 2. Parse and verify clientDataJSON
	clientDataBytes, err := base64.StdEncoding.DecodeString(verifyReq.Response.ClientDataJSON)
	if err != nil {
		http.Error(rw, "invalid clientDataJSON", http.StatusForbidden)
		return
	}

	var clientData ClientDataJSON
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		http.Error(rw, "invalid clientDataJSON", http.StatusForbidden)
		return
	}

	if !a.verifyClientData(rw, &clientData, challengeB64) {
		return
	}

	// 3. Try to verify against any of the user's registered passkeys
	if a.verifyPasskeyResponse(rw, req, &verifyReq, clientDataBytes, canonicalID) {
		return
	}

	http.Error(rw, "passkey verification failed", http.StatusForbidden)
}

func (a *MTlsOrWhitelist) verifyWebAuthnChallenge(rw http.ResponseWriter, req *http.Request) (string, string, bool) {
	challengeCookie, err := req.Cookie("webauthn_challenge")
	if err != nil {
		http.Error(rw, "missing challenge", http.StatusForbidden)
		return "", "", false
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
		return "", "", false
	}

	parts := strings.Split(payload, "|")
	if len(parts) != 3 { //nolint:mnd
		http.Error(rw, "invalid challenge payload", http.StatusForbidden)
		return "", "", false
	}

	challengeTimestamp, err := time.Parse(time.RFC3339, parts[2])
	if err != nil || time.Since(challengeTimestamp) > challengeExpiry {
		http.Error(rw, "challenge expired", http.StatusForbidden)
		return "", "", false
	}

	// Identify current user
	_, canonicalID, ok := a.getUserData(req)
	if !ok || parts[1] != canonicalID {
		http.Error(rw, "user mismatch or not found", http.StatusForbidden)
		return "", "", false
	}

	return parts[0], canonicalID, true
}

func (a *MTlsOrWhitelist) verifyClientData(rw http.ResponseWriter, clientData *ClientDataJSON, challengeB64 string) bool {
	if clientData.Type != "webauthn.get" {
		http.Error(rw, "invalid type", http.StatusForbidden)
		return false
	}

	clientChallengeBytes, _ := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if len(clientChallengeBytes) == 0 {
		clientChallengeBytes, _ = base64.StdEncoding.DecodeString(clientData.Challenge)
	}
	cookieChallengeBytes, _ := base64.StdEncoding.DecodeString(challengeB64)

	if !bytes.Equal(clientChallengeBytes, cookieChallengeBytes) {
		http.Error(rw, "challenge mismatch", http.StatusForbidden)
		return false
	}
	return true
}

func (a *MTlsOrWhitelist) verifyPasskeyResponse(rw http.ResponseWriter, req *http.Request, verifyReq *WebAuthnVerifyRequest, clientDataBytes []byte, canonicalID string) bool {
	userDataList, _, _ := a.getUserData(req)

	authDataBytes, _ := base64.StdEncoding.DecodeString(verifyReq.Response.AuthenticatorData)
	clientDataHash := sha256.Sum256(clientDataBytes)
	signedData := append([]byte{}, authDataBytes...)
	signedData = append(signedData, clientDataHash[:]...)
	signature, _ := base64.StdEncoding.DecodeString(verifyReq.Response.Signature)
	dataHash := sha256.Sum256(signedData)

	for _, userData := range userDataList {
		var passkey map[string]interface{}
		if err := json.Unmarshal([]byte(userData), &passkey); err != nil {
			continue
		}

		if !a.isCorrectAlgorithm(passkey) {
			continue
		}

		publicKeyB64, _ := passkey["publicKey"].(string)
		pubKeyBytes, _ := base64.StdEncoding.DecodeString(publicKeyB64)
		pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			continue
		}

		if ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			if ecdsa.VerifyASN1(ecdsaPubKey, dataHash[:], signature) {
				a.setSessionCookie(rw, canonicalID)
				return true
			}
		}
	}
	return false
}

func (a *MTlsOrWhitelist) isCorrectAlgorithm(passkey map[string]interface{}) bool {
	alg := -7 //nolint:mnd // Default ES256
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
	return alg == -7
}

func (a *MTlsOrWhitelist) setSessionCookie(rw http.ResponseWriter, canonicalID string) {
	sessionPayload := a.getSessionPayload(canonicalID)
	http.SetCookie(rw, &http.Cookie{
		Name:     a.rawConfig.TwoFactor.CookieName,
		Value:    a.signValue(sessionPayload),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(maxTimeDrift),
	})
	rw.WriteHeader(http.StatusOK)
}

type WebAuthnVerifyRequest struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJson"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

type ClientDataJSON struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

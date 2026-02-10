package mtlswhitelist

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMTlsOrWhitelist_getUserData_Multi(t *testing.T) {
	rawConfig := &RawConfig{
		TwoFactor: TwoFactor{
			Users: map[string]interface{}{
				"UserA": []interface{}{
					"TOTPSECRET1",
					map[string]interface{}{"credentialId": "passkey1", "publicKey": "pub1", "alg": -7},
				},
				"UserB": "TOTPSECRET2",
				"UserC": map[string]interface{}{"credentialId": "passkey2", "publicKey": "pub2", "alg": -7},
			},
		},
	}
	a := &MTlsOrWhitelist{rawConfig: rawConfig}

	t.Run("UserA - Multi", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		// Simulate CN match
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "UserA"}},
			},
		}

		data, id, ok := a.getUserData(req)
		if !ok || id != "UserA" {
			t.Errorf("expected UserA, got %v, ok=%v", id, ok)
		}
		if len(data) != 2 {
			t.Errorf("expected 2 credentials, got %d", len(data))
		}
	})

	t.Run("UserB - Single String", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "UserB:1234" // Mocking simple match

		data, id, ok := a.getUserData(req)
		if !ok || id != "UserB" {
			t.Errorf("expected UserB, got %v, ok=%v", id, ok)
		}
		if len(data) != 1 || data[0] != "TOTPSECRET2" {
			t.Errorf("expected TOTPSECRET2, got %v", data)
		}
	})

	t.Run("UserC - Single Object", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "UserC:1234"

		data, id, ok := a.getUserData(req)
		if !ok || id != "UserC" {
			t.Errorf("expected UserC, got %v, ok=%v", id, ok)
		}
		if len(data) != 1 {
			t.Errorf("expected 1 credential, got %d", len(data))
		}
		var pk map[string]interface{}
		json.Unmarshal([]byte(data[0]), &pk)
		if pk["credentialId"] != "passkey2" {
			t.Errorf("expected passkey2, got %v", pk["credentialId"])
		}
	})
}

func TestVerifyTOTP(t *testing.T) {
	plugin := &MTlsOrWhitelist{}

	// Secret: "JBSWY3DPEHPK3PXP" (Base32 for "Hello!")
	// This is a common test vector.
	secret := "JBSWY3DPEHPK3PXP"

	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)

	// Test vectors
	t1 := plugin.getOTP(key, 1)
	t2 := plugin.getOTP(key, 2)
	t.Logf("T=1: %s, T=2: %s", t1, t2)

	if !plugin.checkTOTP(key, 1, t1) {
		t.Errorf("TOTP check failed for T=1")
	}
	if !plugin.checkTOTP(key, 2, t2) {
		t.Errorf("TOTP check failed for T=2")
	}
}

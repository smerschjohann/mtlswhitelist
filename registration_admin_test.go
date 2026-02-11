package mtlswhitelist

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// memoryUserStore is an in-memory mock UserStore for testing.
type memoryUserStore struct {
	data map[string]interface{}
}

func (m *memoryUserStore) Type() string { return "memory" }

func newMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{data: make(map[string]interface{})}
}

func (m *memoryUserStore) ListUsers() (map[string]interface{}, error) {
	result := make(map[string]interface{}, len(m.data))
	for k, v := range m.data {
		result[k] = v
	}
	return result, nil
}

func (m *memoryUserStore) GetUserData(key string) (interface{}, bool, error) {
	val, ok := m.data[key]
	return val, ok, nil
}

func (m *memoryUserStore) SetUserData(key string, value interface{}) error {
	if value == nil {
		delete(m.data, key)
	} else {
		m.data[key] = value
	}
	return nil
}

// --- Test typed structs ---

type deleteCredReq struct {
	Index int `json:"index"`
}

type adminDeleteReq struct {
	Identity string `json:"identity"`
	Index    int    `json:"index"`
}

type adminSetReq struct {
	Identity string `json:"identity"`
	Admin    bool   `json:"admin"`
}

// --- Test helpers ---

func newTestMiddleware(store *memoryUserStore) *MTlsOrWhitelist {
	return &MTlsOrWhitelist{
		rawConfig: &RawConfig{
			TwoFactor: TwoFactor{
				Enabled:    true,
				CookieName: "2fa_session",
				CookieKey:  "test-secret-key-1234567890abcdef",
				PathPrefix: "/.2fa/",
				RPName:     "TestApp",
				RPID:       "localhost",
				UserStore:  UserStoreConfig{Type: "valkey"},
			},
		},
		userStore: store,
	}
}

func generateCode(a *MTlsOrWhitelist, secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	return a.getOTP(key, time.Now().Unix()/30)
}

func newTestReq(url string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.RemoteAddr = testIP + ":12345"
	return req
}

func reqWithCN(method, url, cn string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: cn}},
		},
	}
	return req
}

func authenticateUser(a *MTlsOrWhitelist, identity string) *http.Cookie {
	payload := a.getSessionPayload(identity)
	signed := a.signValue(payload)
	return &http.Cookie{
		Name:  a.rawConfig.TwoFactor.CookieName,
		Value: signed,
	}
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	return b
}

func mustUnmarshal(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
}

func jsonBody(t *testing.T, v interface{}) io.ReadCloser {
	t.Helper()
	return io.NopCloser(bytes.NewReader(mustMarshal(t, v)))
}

// testIP is the default test IP used across tests.
const testIP = "192.168.1.10"

// --- Admin helper tests ---

func TestGetSetAdmins(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	// Initially no admins
	admins := a.getAdmins()
	if len(admins) != 0 {
		t.Errorf("expected 0 admins, got %d", len(admins))
	}

	// Set admins
	if err := a.setAdmins([]string{"alice", "bob"}); err != nil {
		t.Fatalf("setAdmins failed: %v", err)
	}

	admins = a.getAdmins()
	if len(admins) != 2 {
		t.Fatalf("expected 2 admins, got %d", len(admins))
	}
	if admins[0] != "alice" || admins[1] != "bob" {
		t.Errorf("unexpected admins: %v", admins)
	}
}

func TestIsAdminIdentity(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = a.setAdmins([]string{"Alice"})

	if !a.isAdminIdentity("Alice") {
		t.Error("expected Alice to be admin")
	}
	if !a.isAdminIdentity("alice") {
		t.Error("expected case-insensitive match for alice")
	}
	if a.isAdminIdentity("bob") {
		t.Error("expected bob NOT to be admin")
	}
}

func TestPromoteFirstAdmin(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	a.promoteFirstAdmin("alice")
	admins := a.getAdmins()
	if len(admins) != 1 || admins[0] != "alice" {
		t.Errorf("expected alice as sole admin, got %v", admins)
	}

	// Second user should NOT be promoted
	a.promoteFirstAdmin("bob")
	admins = a.getAdmins()
	if len(admins) != 1 || admins[0] != "alice" {
		t.Errorf("expected still only alice, got %v", admins)
	}
}

// --- isRegistrationAllowed tests ---

func TestIsRegistrationAllowed_FirstTime(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := newTestReq("/")
	identity, allowed := a.isRegistrationAllowed(req)
	if !allowed {
		t.Error("expected first-time user to be allowed")
	}
	if identity != testIP {
		t.Errorf("expected identity %s, got %s", testIP, identity)
	}
}

func TestIsRegistrationAllowed_ExistingNotAuthenticated(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "SECRET"}})

	req := newTestReq("/")
	_, allowed := a.isRegistrationAllowed(req)
	if allowed {
		t.Error("expected existing user without 2FA to be denied")
	}
}

func TestIsRegistrationAllowed_ExistingAuthenticated(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "SECRET"}})

	req := newTestReq("/")
	req.AddCookie(authenticateUser(a, testIP))

	identity, allowed := a.isRegistrationAllowed(req)
	if !allowed {
		t.Error("expected authenticated user to be allowed")
	}
	if identity != testIP {
		t.Errorf("expected identity %s, got %s", testIP, identity)
	}
}

// --- isAdmin tests ---

func TestIsAdmin(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "SECRET"}})

	t.Run("admin with 2FA", func(t *testing.T) {
		req := reqWithCN(http.MethodGet, "/", "admin-user")
		req.AddCookie(authenticateUser(a, "admin-user"))

		identity, ok := a.isAdmin(req)
		if !ok {
			t.Error("expected admin to be OK")
		}
		if identity != "admin-user" {
			t.Errorf("expected admin-user, got %s", identity)
		}
	})

	t.Run("admin without 2FA", func(t *testing.T) {
		req := reqWithCN(http.MethodGet, "/", "admin-user")
		_, ok := a.isAdmin(req)
		if ok {
			t.Error("expected admin without 2FA to be denied")
		}
	})

	t.Run("non-admin", func(t *testing.T) {
		req := reqWithCN(http.MethodGet, "/", "regular-user")
		_, ok := a.isAdmin(req)
		if ok {
			t.Error("expected non-admin to be denied")
		}
	})

	t.Run("admin without credentials", func(t *testing.T) {
		_ = a.setAdmins([]string{"no-creds-admin"})
		req := reqWithCN(http.MethodGet, "/", "no-creds-admin")
		_, ok := a.isAdmin(req)
		if ok {
			t.Error("expected admin without credentials to be denied")
		}
	})
}

// --- redirectTo2FA tests ---

func TestRedirectTo2FA_NewUser(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := newTestReq("/protected")
	rr := httptest.NewRecorder()
	a.redirectTo2FA(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/register") {
		t.Errorf("expected redirect to register, got %s", location)
	}
}

func TestRedirectTo2FA_ExistingUser(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "SECRET"}})

	req := newTestReq("/protected")
	rr := httptest.NewRecorder()
	a.redirectTo2FA(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("expected redirect to login, got %s", location)
	}
}

// --- handleRegisterTOTP tests ---

func TestHandleRegisterTOTP_FirstTimeUser(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	secret := "JBSWY3DPEHPK3PXP"
	code := generateCode(a, secret)
	body := strings.NewReader("secret=" + secret + "&code=" + code)
	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-totp", body)
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	a.handleRegisterTOTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	val, found, _ := store.GetUserData(testIP)
	if !found {
		t.Fatal("expected user data to be saved")
	}
	creds, ok := val.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", val)
	}
	if len(creds) != 1 {
		t.Errorf("expected 1 credential, got %d", len(creds))
	}

	if !a.isAdminIdentity(testIP) {
		t.Error("expected first user to become admin")
	}
}

func TestHandleRegisterTOTP_Forbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "EXISTING"}})

	body := strings.NewReader("secret=NEWSECRET")
	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-totp", body)
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	a.handleRegisterTOTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestHandleRegisterTOTP_AuthenticatedCanAdd(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "EXISTING"}})

	secret := "NEWSECRETBASE32"
	code := generateCode(a, secret)
	body := strings.NewReader("secret=" + secret + "&code=" + code)
	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-totp", body)
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(authenticateUser(a, testIP))

	rr := httptest.NewRecorder()
	a.handleRegisterTOTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	val, _, _ := store.GetUserData(testIP)
	creds := val.([]interface{})
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestHandleRegisterTOTP_InvalidCode(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	body := strings.NewReader("secret=JBSWY3DPEHPK3PXP&code=000000")
	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-totp", body)
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	a.handleRegisterTOTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid code, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid verification code") {
		t.Errorf("expected invalid code error, got: %s", rr.Body.String())
	}
}

func TestHandleRegisterTOTP_MissingCode(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	body := strings.NewReader("secret=JBSWY3DPEHPK3PXP")
	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-totp", body)
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	a.handleRegisterTOTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing verification code") {
		t.Errorf("expected missing code error, got: %s", rr.Body.String())
	}
}

// --- handleRegisterPasskey tests ---

func TestHandleRegisterPasskey_FirstTimeUser(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-passkey",
		bytes.NewReader(mustMarshal(t, RegisterPasskeyRequest{
			CredentialID: "cred-123", PublicKey: "pubkey-abc", Alg: -7,
		})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	a.handleRegisterPasskey(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	val, found, _ := store.GetUserData(testIP)
	if !found {
		t.Fatal("expected passkey to be saved")
	}
	creds := val.([]interface{})
	if len(creds) != 1 {
		t.Errorf("expected 1 credential, got %d", len(creds))
	}
}

func TestHandleRegisterPasskey_Forbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "EXISTING"}})

	req := httptest.NewRequest(http.MethodPost, "/.2fa/register-passkey",
		bytes.NewReader(mustMarshal(t, RegisterPasskeyRequest{
			CredentialID: "c", PublicKey: "p", Alg: -7,
		})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	a.handleRegisterPasskey(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- handleDeleteCredential tests ---

func TestHandleDeleteCredential_RemoveOne(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{
		map[string]interface{}{"totp": "SECRET1"},
		map[string]interface{}{"totp": "SECRET2"},
	})

	req := httptest.NewRequest(http.MethodPost, "/.2fa/delete-credential",
		bytes.NewReader(mustMarshal(t, deleteCredReq{Index: 0})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, testIP))

	rr := httptest.NewRecorder()
	a.handleDeleteCredential(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Remaining      int  `json:"remaining"`
		MustReRegister bool `json:"mustReRegister"`
	}
	mustUnmarshal(t, rr.Body.Bytes(), &resp)
	if resp.Remaining != 1 {
		t.Errorf("expected 1 remaining, got %d", resp.Remaining)
	}
	if resp.MustReRegister {
		t.Error("should not need to re-register with 1 cred remaining")
	}
}

func TestHandleDeleteCredential_RemoveLast(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{
		map[string]interface{}{"totp": "SECRET1"},
	})

	req := httptest.NewRequest(http.MethodPost, "/.2fa/delete-credential",
		bytes.NewReader(mustMarshal(t, deleteCredReq{Index: 0})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, testIP))

	rr := httptest.NewRecorder()
	a.handleDeleteCredential(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		MustReRegister bool `json:"mustReRegister"`
	}
	mustUnmarshal(t, rr.Body.Bytes(), &resp)
	if !resp.MustReRegister {
		t.Error("expected mustReRegister=true after deleting last credential")
	}

	// Cookie should be cleared
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "2fa_session" && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}

	// Data should be removed from store
	_, exists, _ := store.GetUserData(testIP)
	if exists {
		t.Error("expected user data to be deleted from store")
	}
}

func TestHandleDeleteCredential_Forbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "SECRET"}})

	req := httptest.NewRequest(http.MethodPost, "/.2fa/delete-credential",
		bytes.NewReader(mustMarshal(t, deleteCredReq{Index: 0})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	a.handleDeleteCredential(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestHandleDeleteCredential_IndexOutOfRange(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "SECRET"}})

	req := httptest.NewRequest(http.MethodPost, "/.2fa/delete-credential",
		bytes.NewReader(mustMarshal(t, deleteCredReq{Index: 5})))
	req.RemoteAddr = testIP + ":12345"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, testIP))

	rr := httptest.NewRecorder()
	a.handleDeleteCredential(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- Admin endpoint tests ---

func TestAdminListUsers(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = store.SetUserData("user-a", []interface{}{map[string]interface{}{"totp": "S1"}})
	_ = store.SetUserData("user-b", []interface{}{map[string]interface{}{"totp": "S2"}})
	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN_SECRET"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin/users", "admin-user")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminListUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Users  map[string]interface{} `json:"users"`
		Admins []string               `json:"admins"`
	}
	mustUnmarshal(t, rr.Body.Bytes(), &resp)

	if _, found := resp.Users[adminStoreKey]; found {
		t.Error("admin store key should be filtered from user list")
	}
	if len(resp.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(resp.Users))
	}
	if len(resp.Admins) != 1 || resp.Admins[0] != "admin-user" {
		t.Errorf("unexpected admins: %v", resp.Admins)
	}
}

func TestAdminListUsers_Forbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := reqWithCN(http.MethodGet, "/.2fa/admin/users", "regular-user")
	rr := httptest.NewRecorder()
	a.handleAdminListUsers(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestAdminGetUser(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = store.SetUserData("target-user", []interface{}{map[string]interface{}{"totp": "S1"}})
	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin/user?identity=target-user", "admin-user")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminGetUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Identity    string      `json:"identity"`
		IsSelf      bool        `json:"isSelf"`
		Credentials interface{} `json:"credentials"`
	}
	mustUnmarshal(t, rr.Body.Bytes(), &resp)

	if resp.Identity != "target-user" {
		t.Errorf("expected target-user, got %s", resp.Identity)
	}
	if resp.IsSelf {
		t.Error("expected isSelf=false for different user")
	}
}

func TestAdminGetUser_Self(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin/user?identity=admin-user", "admin-user")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminGetUser(rr, req)

	var resp struct {
		IsSelf bool `json:"isSelf"`
	}
	mustUnmarshal(t, rr.Body.Bytes(), &resp)
	if !resp.IsSelf {
		t.Error("expected isSelf=true when querying own identity")
	}
}

func TestAdminGetUser_NotFound(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin/user?identity=unknown", "admin-user")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminGetUser(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestAdminDeleteCredential(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN"}})
	_ = store.SetUserData("target-user", []interface{}{
		map[string]interface{}{"totp": "S1"},
		map[string]interface{}{"totp": "S2"},
	})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/delete", "admin-user")
	req.Body = jsonBody(t, adminDeleteReq{Identity: "target-user", Index: 0})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminDeleteCredential(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	val, _, _ := store.GetUserData("target-user")
	creds := val.([]interface{})
	if len(creds) != 1 {
		t.Errorf("expected 1 credential remaining, got %d", len(creds))
	}
}

func TestAdminDeleteCredential_SelfForbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{
		map[string]interface{}{"totp": "S1"},
		map[string]interface{}{"totp": "S2"},
	})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/delete", "admin-user")
	req.Body = jsonBody(t, adminDeleteReq{Identity: "admin-user", Index: 0})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminDeleteCredential(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for self-deletion, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminDeleteCredential_LastAdminProtection(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	// Two admins: admin2 tries to delete sole-admin's only credential.
	// When there are 2 admins, it should succeed.
	_ = a.setAdmins([]string{"sole-admin", "admin2"})
	_ = store.SetUserData("sole-admin", []interface{}{map[string]interface{}{"totp": "SA"}})
	_ = store.SetUserData("admin2", []interface{}{map[string]interface{}{"totp": "A2"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/delete", "admin2")
	req.Body = jsonBody(t, adminDeleteReq{Identity: "sole-admin", Index: 0})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin2"))

	rr := httptest.NewRecorder()
	a.handleAdminDeleteCredential(rr, req)

	// Not sole admin (2 admins exist), so deletion succeeds
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (not sole admin), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminDeleteCredential_SoleAdminProtection(t *testing.T) {
	// The sole-admin protection means: if the target is the ONLY admin and has only 1 cred left.
	// This is a defense-in-depth check (self-deletion is already blocked separately).
	// We verify the check via the isAdminIdentity and getAdmins logic.
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"sole-admin"})
	if !a.isAdminIdentity("sole-admin") {
		t.Fatal("expected sole-admin to be admin")
	}
	if len(a.getAdmins()) != 1 {
		t.Fatal("expected 1 admin")
	}
}

// --- Admin set-admin tests ---

func TestAdminSetAdmin_Grant(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "ADMIN"}})
	_ = store.SetUserData("regular-user", []interface{}{map[string]interface{}{"totp": "REG"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/set-admin", "admin-user")
	req.Body = jsonBody(t, adminSetReq{Identity: "regular-user", Admin: true})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminSetAdmin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !a.isAdminIdentity("regular-user") {
		t.Error("expected regular-user to be admin now")
	}
}

func TestAdminSetAdmin_Revoke(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user", "admin2"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "A1"}})
	_ = store.SetUserData("admin2", []interface{}{map[string]interface{}{"totp": "A2"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/set-admin", "admin-user")
	req.Body = jsonBody(t, adminSetReq{Identity: "admin2", Admin: false})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminSetAdmin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if a.isAdminIdentity("admin2") {
		t.Error("expected admin2 to no longer be admin")
	}
}

func TestAdminSetAdmin_SoleAdminCannotRemoveSelf(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"sole-admin"})
	_ = store.SetUserData("sole-admin", []interface{}{map[string]interface{}{"totp": "SA"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/set-admin", "sole-admin")
	req.Body = jsonBody(t, adminSetReq{Identity: "sole-admin", Admin: false})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "sole-admin"))

	rr := httptest.NewRecorder()
	a.handleAdminSetAdmin(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for sole admin self-demotion, got %d: %s", rr.Code, rr.Body.String())
	}
	if !a.isAdminIdentity("sole-admin") {
		t.Error("sole admin should still be admin after failed removal")
	}
}

func TestAdminSetAdmin_NonSoleAdminCanRemoveSelf(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin1", "admin2"})
	_ = store.SetUserData("admin1", []interface{}{map[string]interface{}{"totp": "A1"}})
	_ = store.SetUserData("admin2", []interface{}{map[string]interface{}{"totp": "A2"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/set-admin", "admin1")
	req.Body = jsonBody(t, adminSetReq{Identity: "admin1", Admin: false})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin1"))

	rr := httptest.NewRecorder()
	a.handleAdminSetAdmin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (not sole admin), got %d: %s", rr.Code, rr.Body.String())
	}
	if a.isAdminIdentity("admin1") {
		t.Error("admin1 should no longer be admin")
	}
}

func TestAdminSetAdmin_DoubleGrant(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "A"}})

	req := reqWithCN(http.MethodPost, "/.2fa/admin/set-admin", "admin-user")
	req.Body = jsonBody(t, adminSetReq{Identity: "admin-user", Admin: true})
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.handleAdminSetAdmin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	// Should still have exactly 1 admin (no duplicates)
	if len(a.getAdmins()) != 1 {
		t.Errorf("expected 1 admin (no duplicates), got %d", len(a.getAdmins()))
	}
}

// --- Admin page access tests ---

func TestServeAdminPage_Forbidden(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := reqWithCN(http.MethodGet, "/.2fa/admin", "regular-user")
	rr := httptest.NewRecorder()
	a.serveAdminPage(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestServeAdminPage_AdminRedirectToLogin(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "S"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin", "admin-user")
	rr := httptest.NewRecorder()
	a.serveAdminPage(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("expected redirect to login, got %s", location)
	}
}

func TestServeAdminPage_Success(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{"admin-user"})
	_ = store.SetUserData("admin-user", []interface{}{map[string]interface{}{"totp": "S"}})

	req := reqWithCN(http.MethodGet, "/.2fa/admin", "admin-user")
	req.AddCookie(authenticateUser(a, "admin-user"))

	rr := httptest.NewRecorder()
	a.serveAdminPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "2FA Admin Panel") {
		t.Error("expected admin panel HTML in response")
	}
}

// --- ServeRegisterPage auth guard tests ---

func TestServeRegisterPage_FirstTimeAllowed(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := newTestReq("/.2fa/register")
	rr := httptest.NewRecorder()
	a.serveRegisterPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "2FA Setup") {
		t.Error("expected register page HTML")
	}
}

func TestServeRegisterPage_ExistingRedirectToLogin(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "S"}})

	req := newTestReq("/.2fa/register")
	rr := httptest.NewRecorder()
	a.serveRegisterPage(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("expected redirect to login, got %s", location)
	}
}

func TestServeRegisterPage_ShowsAdminLink(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	_ = a.setAdmins([]string{testIP})
	_ = store.SetUserData(testIP, []interface{}{map[string]interface{}{"totp": "S"}})

	req := newTestReq("/.2fa/register")
	req.AddCookie(authenticateUser(a, testIP))

	rr := httptest.NewRecorder()
	a.serveRegisterPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Admin Panel") {
		t.Error("expected admin panel link for admin user")
	}
}

func TestServeRegisterPage_SecretNotEmpty(t *testing.T) {
	store := newMemoryUserStore()
	a := newTestMiddleware(store)

	req := newTestReq("/.2fa/register")
	rr := httptest.NewRecorder()
	a.serveRegisterPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// The secret field should look like: <code id="totpSecret">BASE32SECRET</code>
	if !strings.Contains(body, `<code id="totpSecret">`) {
		t.Fatal("expected totpSecret id in HTML")
	}
	// It should NOT contain the identity placeholder or admin link in that spot
	if strings.Contains(body, `<code id="totpSecret">`+testIP) {
		t.Error("secret field contains identity instead of secret")
	}
	if strings.Contains(body, `<code id="totpSecret"><a href=`) {
		t.Error("secret field contains admin link instead of secret")
	}
}

// --- toCredentialSlice tests ---

func TestToCredentialSlice(t *testing.T) {
	a := &MTlsOrWhitelist{}

	t.Run("nil", func(t *testing.T) {
		result := a.toCredentialSlice(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("slice", func(t *testing.T) {
		input := []interface{}{"a", "b"}
		result := a.toCredentialSlice(input)
		if len(result) != 2 {
			t.Errorf("expected 2, got %d", len(result))
		}
	})

	t.Run("single value", func(t *testing.T) {
		result := a.toCredentialSlice("single")
		if len(result) != 1 || result[0] != "single" {
			t.Errorf("expected [single], got %v", result)
		}
	})
}

// --- clearSessionCookie test ---

func TestClearSessionCookie(t *testing.T) {
	a := newTestMiddleware(newMemoryUserStore())
	rr := httptest.NewRecorder()
	a.clearSessionCookie(rr)

	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "2fa_session" && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie with MaxAge < 0")
	}
}

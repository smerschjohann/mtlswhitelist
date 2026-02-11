// Package mtlswhitelist a traefik plugin to check on the certificate or optional a whitelist.
package mtlswhitelist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"
)

const userStoreDefault = "config"

type MTlsOrWhitelist struct {
	next           http.Handler
	name           string
	matchers       *Config
	rawConfig      *RawConfig
	updateMutex    sync.Mutex
	requestHeaders map[string]*template.Template
	userStore      UserStore
}

// RawRule must be defined as  yaegi is a bit dumb and doesn't correctly reflect the type of the config struct.
type RawRule struct {
	Type         string            `json:"type"`
	Headers      map[string]string `json:"headers,omitempty"`
	Ranges       []string          `json:"ranges,omitempty"`
	AddInterface bool              `json:"addInterface,omitempty"`
	Rules        []RawRule         `json:"rules,omitempty"`
}

type ExternalData struct {
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	DataKey       string            `json:"dataKey,omitempty"` // if the data is nested in the response, specify the key here
	SkipTLSVerify bool              `json:"skipTlsVerify,omitempty"`
}

type RejectMessage struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type UserStoreConfig struct {
	Type               string `json:"type,omitempty"`               // "config" (default), "kubernetes", "valkey"
	SecretName         string `json:"secretName,omitempty"`         // Kubernetes: secret name
	SecretNamespace    string `json:"secretNamespace,omitempty"`    // Kubernetes: namespace (auto-detected if empty)
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"` // TLS: skip certificate verification
	Address            string `json:"address,omitempty"`            // Valkey: host:port
	Password           string `json:"password,omitempty"`           // Valkey: AUTH password
	DB                 int    `json:"db,omitempty"`                 // Valkey: database number
	KeyPrefix          string `json:"keyPrefix,omitempty"`          // Valkey: key prefix (default: "2fa:")
}

type TwoFactor struct {
	Enabled    bool                   `json:"enabled,omitempty"`
	RPID       string                 `json:"rpid,omitempty"`
	PathPrefix string                 `json:"pathPrefix,omitempty"`
	RPName     string                 `json:"rpName,omitempty"`
	CookieName string                 `json:"cookieName,omitempty"`
	CookieKey  string                 `json:"cookieKey,omitempty"` // For signing/encryption
	Users      map[string]interface{} `json:"users,omitempty"`     // Identity -> 2FA Data (inline config only)
	UserStore  UserStoreConfig        `json:"userStore,omitempty"` // External user store config
}

type RawConfig struct {
	Rules           []RawRule         `json:"rules"`
	ExternalData    ExternalData      `json:"externalData,omitempty"`
	RefreshInterval string            `json:"refreshInterval,omitempty"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RejectMessage   *RejectMessage    `json:"rejectMessage,omitempty"`
	TwoFactor       TwoFactor         `json:"twoFactor,omitempty"`
}

func CreateConfig() *RawConfig {
	return &RawConfig{
		TwoFactor: TwoFactor{
			PathPrefix: "/_mtls_2fa/",
			CookieName: "mtls_2fa_session",
		},
	}
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, rawConfig *RawConfig, name string) (http.Handler, error) {
	if rawConfig.TwoFactor.PathPrefix == "" {
		rawConfig.TwoFactor.PathPrefix = "/_mtls_2fa/"
	}
	if rawConfig.TwoFactor.CookieName == "" {
		rawConfig.TwoFactor.CookieName = "mtls_2fa_session"
	}
	if rawConfig.TwoFactor.Enabled && rawConfig.TwoFactor.CookieKey == "" {
		return nil, errors.New("TwoFactor is enabled but no cookieKey is configured")
	}

	config, err := NewConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	err = config.Init()
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*template.Template, len(rawConfig.RequestHeaders))
	for headerName, headerTemplate := range rawConfig.RequestHeaders {
		parsedTmpl, parseErr := template.New(headerName).Delims("[[", "]]").Parse(headerTemplate)
		if parseErr != nil {
			return nil, parseErr // Return error to prevent middleware creation
		}
		templates[headerName] = parsedTmpl
	}

	// Initialize user store
	userStore, err := initUserStore(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize user store: %w", err)
	}

	return &MTlsOrWhitelist{
		next:           next,
		name:           name,
		matchers:       config,
		rawConfig:      rawConfig,
		requestHeaders: templates,
		userStore:      userStore,
	}, nil
}

//nolint:ireturn // interface return is by design
func initUserStore(rawConfig *RawConfig) (UserStore, error) {
	storeType := rawConfig.TwoFactor.UserStore.Type
	if storeType == "" {
		storeType = userStoreDefault
	}

	switch storeType {
	case userStoreDefault:
		fmt.Println("[2FA] Using inline config user store")
		return newConfigUserStore(rawConfig.TwoFactor.Users), nil
	case "kubernetes":
		fmt.Println("[2FA] Using Kubernetes Secret user store")
		return newKubernetesUserStore(
			rawConfig.TwoFactor.UserStore.SecretName,
			rawConfig.TwoFactor.UserStore.SecretNamespace,
			rawConfig.TwoFactor.UserStore.InsecureSkipVerify,
		)
	case "valkey":
		fmt.Printf("[2FA] Using Valkey user store at %s\n", rawConfig.TwoFactor.UserStore.Address)
		return newValkeyUserStore(
			rawConfig.TwoFactor.UserStore.Address,
			rawConfig.TwoFactor.UserStore.Password,
			rawConfig.TwoFactor.UserStore.DB,
			rawConfig.TwoFactor.UserStore.KeyPrefix,
		)
	default:
		return nil, fmt.Errorf("unknown user store type: %s", storeType)
	}
}

func (a *MTlsOrWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 1. Handle internal 2FA paths
	if a.handleInternal2FA(rw, req) {
		return
	}

	// 2. Handle mTLS users
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		a.handleRequestsWithValidCert(rw, req)
		return
	}

	// 3. Handle Whitelist/2FA users
	if a.handleWhitelistRequest(rw, req) {
		a.applyRequestHeaders(req, nil)
		a.updateConfigIfRequired()
		a.next.ServeHTTP(rw, req)
	}
}

func (a *MTlsOrWhitelist) handleInternal2FA(rw http.ResponseWriter, req *http.Request) bool {
	if a.rawConfig != nil && a.rawConfig.TwoFactor.Enabled && strings.HasPrefix(req.URL.Path, a.rawConfig.TwoFactor.PathPrefix) {
		a.Serve2FA(rw, req)
		return true
	}
	return false
}

func (a *MTlsOrWhitelist) handleRequestsWithValidCert(rw http.ResponseWriter, req *http.Request) {
	cert := req.TLS.PeerCertificates[0]

	req.Header.Set("X-Whitelist-Cert-Sn", cert.SerialNumber.String())
	req.Header.Set("X-Whitelist-Cert-Cn", cert.Subject.CommonName)

	if !a.check2FA(rw, req) {
		return
	}

	a.applyRequestHeaders(req, cert)
	a.next.ServeHTTP(rw, req)
}

func (a *MTlsOrWhitelist) handleWhitelistRequest(rw http.ResponseWriter, req *http.Request) bool {
	req.Header.Set("X-Whitelist-Cert-Sn", "NoCert")

	allowed := a.matchers.Match(req)
	if !allowed {
		if a.matchers.NextUpdate != nil && a.matchers.NextUpdate.Before(time.Now()) {
			_ = a.updateConfig()
			allowed = a.matchers.Match(req)
		}

		if !allowed {
			http.Error(rw, a.matchers.RejectMessage, a.matchers.RejectCode)
			return false
		}
	}

	return a.check2FA(rw, req)
}

func (a *MTlsOrWhitelist) check2FA(rw http.ResponseWriter, req *http.Request) bool {
	if a.rawConfig != nil && a.rawConfig.TwoFactor.Enabled {
		if !a.is2FAAuthenticated(req) {
			a.redirectTo2FA(rw, req)
			return false
		}
	}
	return true
}

func (a *MTlsOrWhitelist) applyRequestHeaders(req *http.Request, cert interface{}) {
	for headerName, tmpl := range a.requestHeaders {
		var tplOutput bytes.Buffer
		data := map[string]interface{}{"Req": req}
		if cert != nil {
			data["Cert"] = cert
		}
		if err := tmpl.Execute(&tplOutput, data); err != nil {
			fmt.Printf("Error executing template for header %s: %v\n", headerName, err)
			continue
		}
		req.Header.Set(headerName, tplOutput.String())
	}
}

func (a *MTlsOrWhitelist) updateConfigIfRequired() {
	if a.matchers.NextUpdate != nil && a.matchers.NextUpdate.Before(time.Now()) {
		go func() {
			err := a.updateConfig()
			if err != nil {
				fmt.Printf("could not update config %v\n", err)
			}
		}()
	}
}

func (a *MTlsOrWhitelist) updateConfig() error {
	a.updateMutex.Lock()
	defer a.updateMutex.Unlock()

	if a.matchers.NextUpdate == nil || a.matchers.NextUpdate.After(time.Now()) {
		return nil
	}

	newMatchers, err := NewConfig(a.rawConfig)
	if err != nil {
		fmt.Println("Error updating matchers: ", err)
		return err
	}
	err = newMatchers.Init()
	if err != nil {
		fmt.Println("Error updating matchers: ", err)
		return err
	}
	a.matchers = newMatchers
	return nil
}

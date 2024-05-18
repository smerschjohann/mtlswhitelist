// Package plugindemo a demo plugin.
package mtlswhitelist

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type MTlsOrWhitelist struct {
	next        http.Handler
	name        string
	matchers    *Config
	rawConfig   *RawConfig
	updateMutex sync.Mutex
}

// yaegi is a bit dump and doesn't correctly reflect the type of the config struct so we need to define it here
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
	SkipTlsVerify bool              `json:"skipTlsVerify,omitempty"`
}

type RawConfig struct {
	Rules           []RawRule    `json:"rules"`
	ExternalData    ExternalData `json:"externalData,omitempty"`
	RefreshInterval string       `json:"refreshInterval,omitempty"`
}

func CreateConfig() *RawConfig {
	return &RawConfig{}
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, rawConfig *RawConfig, name string) (http.Handler, error) {
	config, err := NewConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	config.Init()

	return &MTlsOrWhitelist{
		next:      next,
		name:      name,
		matchers:  config,
		rawConfig: rawConfig,
	}, nil
}

func (a *MTlsOrWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		fmt.Println("Client Certificate: ", req.TLS.PeerCertificates[0].Subject)
		req.Header.Set("X-Whitelist-Cert-SN", req.TLS.PeerCertificates[0].SerialNumber.String())
		req.Header.Set("X-Whitelist-Cert-CN", req.TLS.PeerCertificates[0].Subject.CommonName)
		a.next.ServeHTTP(rw, req)
		return
	}

	// if no cert provided and request is not from accepted ips, set SN to NoCert
	req.Header.Set("X-Whitelist-Cert-SN", "NoCert")

	allowed := a.matchers.Match(req)
	if !allowed {
		if a.matchers.NextUpdate != nil && a.matchers.NextUpdate.Before(time.Now()) {
			a.updateConfig()
			allowed = a.matchers.Match(req)
		}

		if !allowed {
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}
	}
	if a.matchers.NextUpdate != nil && a.matchers.NextUpdate.Before(time.Now()) {
		go a.updateConfig()
	}
	a.next.ServeHTTP(rw, req)
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

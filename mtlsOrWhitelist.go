// Package plugindemo a demo plugin.
package mtlswhitelist

import (
	"context"
	"fmt"
	"net/http"
)

type MTlsOrWhitelist struct {
	next     http.Handler
	name     string
	matchers *Config
}

// yaegi is a bit dump and doesn't correctly reflect the type of the config struct so we need to define it here
type RawRule struct {
	Type         string            `json:"type"`
	Headers      map[string]string `json:"headers,omitempty"`
	Ranges       []string          `json:"ranges,omitempty"`
	AddInterface bool              `json:"addInterface,omitempty"`
	Rules        []RawRule         `json:"rules,omitempty"`
}

type RawConfig struct {
	Rules []RawRule `json:"rules"`
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
		next:     next,
		name:     name,
		matchers: config,
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
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	a.next.ServeHTTP(rw, req)
}

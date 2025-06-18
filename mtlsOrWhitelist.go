// Package mtlswhitelist a traefik plugin to check on the certificate or optional a whitelist.
package mtlswhitelist

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"
)

type MTlsOrWhitelist struct {
	next           http.Handler
	name           string
	matchers       *Config
	rawConfig      *RawConfig
	updateMutex    sync.Mutex
	requestHeaders map[string]*template.Template
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

type RawConfig struct {
	Rules           []RawRule         `json:"rules"`
	ExternalData    ExternalData      `json:"externalData,omitempty"`
	RefreshInterval string            `json:"refreshInterval,omitempty"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RejectMessage   *RejectMessage    `json:"rejectMessage,omitempty"`
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
	err = config.Init()
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*template.Template, len(rawConfig.RequestHeaders))
	for headerName, headerTemplate := range rawConfig.RequestHeaders {
		tmpl, err := template.New(headerName).Delims("[[", "]]").Parse(headerTemplate)
		if err != nil {
			return nil, err // Return error to prevent middleware creation
		}
		templates[headerName] = tmpl
	}

	return &MTlsOrWhitelist{
		next:           next,
		name:           name,
		matchers:       config,
		rawConfig:      rawConfig,
		requestHeaders: templates,
	}, nil
}

func (a *MTlsOrWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		handleRequestsWithValidCert(req, a, rw)
		return
	}

	// if no cert provided and request is not from accepted ips, set SN to NoCert
	req.Header.Set("X-Whitelist-Cert-Sn", "NoCert")

	allowed := a.matchers.Match(req)
	if !allowed {
		if a.matchers.NextUpdate != nil && a.matchers.NextUpdate.Before(time.Now()) {
			err := a.updateConfig()
			if err != nil {
				fmt.Printf("error updating config: %v", err)
			}
			allowed = a.matchers.Match(req)
		}

		if !allowed {
			http.Error(rw, a.matchers.RejectMessage, a.matchers.RejectCode)
			return
		}
	}

	// add additional headers if defined as requestHeaders
	for headerName, tmpl := range a.requestHeaders {
		var tplOutput bytes.Buffer
		err := tmpl.Execute(&tplOutput, map[string]interface{}{"Req": req})
		if err != nil {
			fmt.Printf("Error executing template for header %s: %v\n", headerName, err)
			continue // Skip this header if there's an error
		}
		req.Header.Set(headerName, tplOutput.String())
	}

	a.updateConfigIfRequired()
	a.next.ServeHTTP(rw, req)
}

func handleRequestsWithValidCert(req *http.Request, a *MTlsOrWhitelist, rw http.ResponseWriter) {
	cert := req.TLS.PeerCertificates[0]

	fmt.Println("Client Certificate: ", req.TLS.PeerCertificates[0].Subject)
	req.Header.Set("X-Whitelist-Cert-Sn", cert.SerialNumber.String())
	req.Header.Set("X-Whitelist-Cert-Cn", cert.Subject.CommonName)

	// add additional headers if defined as requestHeaders
	for headerName, tmpl := range a.requestHeaders {
		var tplOutput bytes.Buffer
		err := tmpl.Execute(&tplOutput, map[string]interface{}{"Cert": cert, "Req": req})
		if err != nil {
			fmt.Printf("Error executing template for header %s: %v\n", headerName, err)
			continue // Skip this header if there's an error
		}
		req.Header.Set(headerName, tplOutput.String())
	}

	a.next.ServeHTTP(rw, req)
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

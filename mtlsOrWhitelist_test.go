package mtlswhitelist

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
	"time"
)

type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.called = true
	rw.WriteHeader(http.StatusOK)
}

func generateTestCertificate() *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "TestCN",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	return cert
}

func TestMTlsOrWhitelist_ServeHTTP(t *testing.T) {
	cert := generateTestCertificate()

	type fields struct {
		next           http.Handler
		matchers       *Config
		rawConfig      *RawConfig
		requestHeaders map[string]*template.Template
	}
	type args struct {
		rw  http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		wantNextCalled     bool
		wantStatusCode     int
		wantHeaderSN       string
		wantHeaderCN       string
		requestHeaderCheck func(t *testing.T, req *http.Request)
	}{
		{
			name: "with TLS",
			fields: fields{
				next: &mockHandler{},
				matchers: &Config{
					Rules: []Rule{&RuleHeader{
						Headers: map[string]string{},
					}},
				},
				rawConfig: &RawConfig{
					RequestHeaders: map[string]string{
						"X-Custom-Header": "[[.Cert.Subject.CommonName]]",
						"X-Custom-Mail":   "[[.Cert.Subject.CommonName]]@domain.tld",
					},
				},
				requestHeaders: map[string]*template.Template{
					"X-Custom-Header": template.Must(template.New("X-Custom-Header").Delims("[[", "]]").Parse("[[.Cert.Subject.CommonName]]")),
					"X-Custom-Mail":   template.Must(template.New("X-Custom-Mail").Delims("[[", "]]").Parse("[[.Cert.Subject.CommonName]]@domain.tld")),
				},
			},
			args: args{
				rw: httptest.NewRecorder(),
				req: &http.Request{
					TLS: &tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{
							cert,
						},
					},
					Header: http.Header{},
				},
			},
			wantNextCalled: true,
			wantStatusCode: http.StatusOK,
			wantHeaderSN:   "12345",
			wantHeaderCN:   "TestCN",
			requestHeaderCheck: func(t *testing.T, req *http.Request) {
				t.Helper()
				if req.Header.Get("X-Custom-Header") != "TestCN" {
					t.Errorf("X-Custom-Header = %v, want %v", req.Header.Get("X-Custom-Header"), "TestCN")
				}
				if req.Header.Get("X-Custom-Mail") != "TestCN@domain.tld" {
					t.Errorf("X-Custom-Header = %v, want %v", req.Header.Get("X-Custom-Mail"), "TestCN@domain.tld")
				}
			},
		},
		{
			name: "without TLS, whitelisted",
			fields: fields{
				next: &mockHandler{},
				matchers: &Config{
					Rules: []Rule{&RuleHeader{
						Headers: map[string]string{},
					}},
				},
				rawConfig: &RawConfig{
					RequestHeaders: map[string]string{"X-Custom-Header": "staticvalue"},
				},
				requestHeaders: map[string]*template.Template{
					"X-Custom-Header": template.Must(template.New("X-Custom-Header").Delims("[[", "]]").Parse("staticvalue")),
				},
			},
			args: args{
				rw:  httptest.NewRecorder(),
				req: &http.Request{Header: http.Header{}},
			},
			wantNextCalled: true,
			wantStatusCode: http.StatusOK,
			wantHeaderSN:   "NoCert",
			requestHeaderCheck: func(t *testing.T, req *http.Request) {
				t.Helper()
				if req.Header.Get("X-Custom-Header") != "staticvalue" {
					t.Errorf("X-Custom-Header = %v, want %v", req.Header.Get("X-Custom-Header"), "staticvalue")
				}
			},
		},
		{
			name: "without TLS, not whitelisted",
			fields: fields{
				next: &mockHandler{},
				matchers: &Config{
					Rules: []Rule{&RuleHeader{
						Headers: map[string]string{"X-Non-Existent": ".+"},
					}},
				},
				rawConfig: &RawConfig{},
			},
			args: args{
				rw:  httptest.NewRecorder(),
				req: &http.Request{Header: http.Header{}},
			},
			wantNextCalled: false,
			wantStatusCode: http.StatusForbidden,
			wantHeaderSN:   "NoCert",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &MTlsOrWhitelist{
				next:           mockNextHandler(tt.wantNextCalled),
				matchers:       tt.fields.matchers,
				requestHeaders: tt.fields.requestHeaders,
			}
			err := a.matchers.Init()
			if err != nil {
				t.Errorf("error init matchers, test %v, error: %v", tt.name, err)
			}
			a.ServeHTTP(tt.args.rw, tt.args.req)
			resp := tt.args.rw.(*httptest.ResponseRecorder)

			if resp.Code != tt.wantStatusCode {
				t.Errorf("ServeHTTP() statusCode = %v, want %v", resp.Code, tt.wantStatusCode)
			}

			if tt.wantHeaderSN != "" {
				if got := tt.args.req.Header.Get("X-Whitelist-Cert-Sn"); got != tt.wantHeaderSN {
					t.Errorf("ServeHTTP() X-Whitelist-Cert-SN = %v, want %v", got, tt.wantHeaderSN)
				}
			}

			if tt.requestHeaderCheck != nil {
				tt.requestHeaderCheck(t, tt.args.req)
			}
		})
	}
}

type mockNextHandler bool

func (m mockNextHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m {
		rw.WriteHeader(http.StatusOK)
	} else {
		panic("next should not have been called")
	}
}

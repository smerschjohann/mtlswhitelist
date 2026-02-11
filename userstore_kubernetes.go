package mtlswhitelist

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	k8sTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // not a credential, but a path to the token file
	k8sCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	k8sCacheTTL      = 30 * time.Second
)

// kubernetesUserStore reads/writes 2FA data from/to a Kubernetes Secret.
// Secret data keys are identity strings (base64-encoded per K8s spec),
// values are JSON-encoded credential arrays.
type kubernetesUserStore struct {
	apiHost   string
	namespace string
	name      string
	client    *http.Client
	debug     bool

	mu        sync.RWMutex
	cache     map[string]interface{}
	cacheTime time.Time
}

func (s *kubernetesUserStore) Type() string { return "kubernetes" }

func newKubernetesUserStore(secretName, secretNamespace string, insecureSkipVerify bool, debug bool) (*kubernetesUserStore, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running in Kubernetes: KUBERNETES_SERVICE_HOST/PORT not set")
	}

	_, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

	ns := secretNamespace
	if ns == "" {
		nsBytes, nsErr := os.ReadFile(k8sNamespacePath)
		if nsErr != nil {
			return nil, fmt.Errorf("no namespace configured and cannot read from service account: %w", nsErr)
		}
		ns = strings.TrimSpace(string(nsBytes))
	}

	if secretName == "" {
		return nil, errors.New("kubernetes secretName is required")
	}

	// Load CA cert for in-cluster TLS
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // MinVersion is TLS 1.2
	if insecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else {
		caCert, err := os.ReadFile(k8sCACertPath)
		if err == nil && len(caCert) > 0 {
			roots := x509.NewCertPool()
			if ok := roots.AppendCertsFromPEM(caCert); ok {
				tlsConfig.RootCAs = roots
			}
		}
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second, //nolint:mnd
	}

	return &kubernetesUserStore{
		apiHost:   "https://" + net.JoinHostPort(host, port),
		namespace: ns,
		name:      secretName,
		client:    client,
		debug:     debug,
	}, nil
}

func (s *kubernetesUserStore) getToken() (string, error) {
	token, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %w", err)
	}
	return string(token), nil
}

func (s *kubernetesUserStore) secretURL() string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", s.apiHost, s.namespace, s.name)
}

func (s *kubernetesUserStore) doRequest(method, url string, body io.Reader, contentType string) ([]byte, int, error) {
	if s.debug {
		fmt.Fprintf(os.Stderr, "[2FA-K8S] Request: %s %s\n", method, url)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, err
	}

	token, err := s.getToken()
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		if s.debug {
			fmt.Fprintf(os.Stderr, "[2FA-K8S] Request failed: %v\n", err)
		}
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if s.debug {
		fmt.Fprintf(os.Stderr, "[2FA-K8S] Response: %d, Body: %s\n", resp.StatusCode, string(respBody))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBody, resp.StatusCode, fmt.Errorf("kubernetes API returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, resp.StatusCode, nil
}

func (s *kubernetesUserStore) fetchSecret() (map[string]interface{}, error) {
	s.mu.RLock()
	if s.cache != nil && time.Since(s.cacheTime) < k8sCacheTTL {
		cached := s.cache
		s.mu.RUnlock()
		if s.debug {
			fmt.Fprintln(os.Stderr, "[2FA-K8S] Using cached secret data")
		}
		return cached, nil
	}
	s.mu.RUnlock()

	body, statusCode, err := s.doRequest(http.MethodGet, s.secretURL(), nil, "")
	if err != nil {
		if statusCode == http.StatusNotFound {
			// Secret does not exist yet — treat as empty user store
			return make(map[string]interface{}), nil
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var secret struct {
		Data map[string]string `json:"data"` // base64-encoded values
	}
	if err := json.Unmarshal(body, &secret); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	users := make(map[string]interface{}, len(secret.Data))
	for key, b64Value := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(b64Value)
		if err != nil {
			if s.debug {
				fmt.Fprintf(os.Stderr, "[2FA-K8S] Failed to decode base64 for key %s: %v\n", key, err)
			}
			continue
		}
		var userData interface{}
		if err := json.Unmarshal(decoded, &userData); err != nil {
			// Treat as plain string
			if s.debug {
				fmt.Fprintf(os.Stderr, "[2FA-K8S] Data for key %s is not JSON, treating as plain string\n", key)
			}
			users[key] = string(decoded)
			continue
		}
		if s.debug {
			fmt.Fprintf(os.Stderr, "[2FA-K8S] Loaded user data for %s: %v\n", key, userData)
		}
		users[key] = userData
	}

	s.mu.Lock()
	s.cache = users
	s.cacheTime = time.Now()
	s.mu.Unlock()

	return users, nil
}

func (s *kubernetesUserStore) ListUsers() (map[string]interface{}, error) {
	if s == nil {
		return nil, errors.New("kubernetes store not initialized")
	}
	return s.fetchSecret()
}

func (s *kubernetesUserStore) GetUserData(key string) (interface{}, bool, error) {
	if s == nil {
		return nil, false, errors.New("kubernetes store not initialized")
	}
	users, err := s.fetchSecret()
	if err != nil {
		return nil, false, err
	}
	val, ok := users[key]
	return val, ok, nil
}

func (s *kubernetesUserStore) SetUserData(key string, value interface{}) error {
	if s == nil {
		return errors.New("kubernetes store not initialized")
	}
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	b64Value := base64.StdEncoding.EncodeToString(jsonBytes)

	patch := map[string]interface{}{
		"data": map[string]string{
			key: b64Value,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal patch: %w", err)
	}

	_, _, err = s.doRequest(
		http.MethodPatch,
		s.secretURL(),
		strings.NewReader(string(patchBytes)),
		"application/strategic-merge-patch+json",
	)
	if err != nil {
		return fmt.Errorf("failed to patch secret: %w", err)
	}

	// Invalidate cache
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()

	return nil
}

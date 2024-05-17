package mtlswhitelist

import (
	"net/http"
	"regexp"
)

type RuleHeader struct {
	Headers map[string]string `json:"headers"`

	// Internal
	allowedHeaders map[string]*regexp.Regexp
}

func (r *RuleHeader) Init() error {
	r.allowedHeaders = make(map[string]*regexp.Regexp)
	for key, pattern := range r.Headers {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		r.allowedHeaders[key] = compiled
	}
	return nil
}

func (r *RuleHeader) Match(req *http.Request) bool {
	for key, regex := range r.allowedHeaders {
		value := req.Header.Get(key)
		if len(value) == 0 {
			return false
		}
		if !regex.MatchString(value) {
			return false
		}
	}
	req.Header.Set("X-Whitelist-Header", "true")
	return true
}

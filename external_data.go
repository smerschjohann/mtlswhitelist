package mtlswhitelist

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
)

func GetExternalData(config ExternalData) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, config.URL, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range config.Headers {
		tval, templateErr := templateValue(value, "")
		if templateErr != nil {
			return nil, fmt.Errorf("error in templateValue %s: %w", value, err)
		}
		req.Header.Set(key, tval)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonData map[string]interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func templateValue(templateStr string, data any) (string, error) {
	funcMap := template.FuncMap{
		"file": getDataFromFile,
		"env":  getDataFromEnv,
	}

	tmpl, err := template.New("template").Delims("[[", "]]").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("error parsing template: %v %w", templateStr, err)
	}

	var result strings.Builder
	err = tmpl.Execute(&result, data)
	if err != nil {
		return "", fmt.Errorf("error executing template: %v %w", templateStr, err)
	}

	return result.String(), nil
}

func getDataFromEnv(key string) string {
	return os.Getenv(key)
}

func getDataFromFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

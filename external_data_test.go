package mtlswhitelist

import (
	"os"
	"testing"
)

func Test_templateValue_file(t *testing.T) {
	// Prepare test: create a temporary file and write some data to it
	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	text := []byte("Hello, World!")
	if _, err = tmpfile.Write(text); err != nil {
		t.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Run test
	got, err := templateValue("[[ file \""+tmpfile.Name()+"\" ]]", nil) // {{ file "path/to/file" }}
	if err != nil {
		t.Errorf("templateValue() error = %v", err)
		return
	}
	if got != string(text) {
		t.Errorf("templateValue() = %v, want %v", got, text)
	}
}

func Test_templateValue_env(t *testing.T) {
	// Prepare test: set an environment variable
	key := "TEST"
	value := "Hello, World!"
	os.Setenv(key, value)
	defer os.Unsetenv(key) // clean up

	// Run test
	got, err := templateValue("[[ env \"TEST\" ]]", nil)
	if err != nil {
		t.Errorf("templateValue() error = %v", err)
		return
	}
	if got != value {
		t.Errorf("templateValue() = %v, want %v", got, value)
	}
}

func Test_ExternalData(t *testing.T) {
	data, err := GetExternalData(ExternalData{
		URL: "https://jsonplaceholder.typicode.com/todos/1",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		DataKey: "title",
	})

	if err != nil {
		t.Errorf("GetExternalData() error = %v", err)
		return
	}

	if data["title"] != "delectus aut autem" {
		t.Errorf("GetExternalData() = %v, want %v", data["title"], "delectus aut autem")
	}
}

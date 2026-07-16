package configuration

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestReadDataFromFile(t *testing.T) {
	expectedData := []byte("test data 0815")

	tempFile, err := os.CreateTemp("", "TestReadDataFromFile")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	defer os.Remove(tempFile.Name())

	content := expectedData
	if err := os.WriteFile(tempFile.Name(), content, 0644); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	cl := FileConfigLoader{Path: tempFile.Name()}

	data, err := cl.readDataFromFile()

	if !bytes.Equal(data, expectedData) {
		t.Errorf("got \"%v\", want \"%v\"", string(data[:]), string(expectedData[:]))
	}
}

func TestUnmarshalDataToConfig(t *testing.T) {
	configBaseUrl := "https://thisisatest.invalid"
	configDisableCV := true
	configName := "testvalueName"
	configCertificateSecret := "testvalueCS"
	configCertificatePath := "testvalueCP"
	configKeySecret := "testvalueKS"
	configKeyPath := "testvalueKP"
	configCaPath := "testvalueCAP"
	configAction := "testvalueCA"

	yamlData := fmt.Sprintf(`
base_url: "%v"
disable_certificate_validation: %v
certificates:
  - name: "%v"
    cert_secret: "%v"
    cert_path: "%v"
    key_secret: "%v"
    key_path: "%v"
    ca_path: "%v"
    action: "%v"
`,
		configBaseUrl,
		strconv.FormatBool(configDisableCV),
		configName,
		configCertificateSecret,
		configCertificatePath,
		configKeySecret,
		configKeyPath,
		configCaPath,
		configAction,
	)

	cl := FileConfigLoader{}

	data, err := cl.unmarshalDataToConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err.Error())
		t.Fail()
	}

	if configBaseUrl != data.BaseURL {
		t.Logf("BaseURL: expected %v, got %v", configBaseUrl, data.BaseURL)
		t.Fail()
	}

	if configDisableCV != data.DisableCertificateValidation {
		t.Logf("DisableCertificateValidation: expected %v, got %v", strconv.FormatBool(configDisableCV), strconv.FormatBool(data.DisableCertificateValidation))
		t.Fail()
	}

	if configName != data.Certificates[0].Name {
		t.Logf("Certificates.Name: expected %v, got %v", configName, data.Certificates[0].Name)
		t.Fail()
	}

	if configCertificateSecret != data.Certificates[0].CertificateSecret {
		t.Logf("Certificates.CertificateSecret: expected %v, got %v", configCertificateSecret, data.Certificates[0].CertificateSecret)
		t.Fail()
	}

	if configCertificatePath != data.Certificates[0].CertificatePath {
		t.Logf("Certificates.CertificatePath: expected %v, got %v", configCertificatePath, data.Certificates[0].CertificatePath)
		t.Fail()
	}

	if configKeySecret != data.Certificates[0].KeySecret {
		t.Logf("Certificates.KeySecret: expected %v, got %v", configKeySecret, data.Certificates[0].KeySecret)
		t.Fail()
	}

	if configKeyPath != data.Certificates[0].KeyPath {
		t.Logf("Certificates.KeyPath: expected %v, got %v", configKeyPath, data.Certificates[0].KeyPath)
		t.Fail()
	}

	if configCaPath != data.Certificates[0].CaPath {
		t.Logf("Certificates.CaPath: expected %v, got %v", configCaPath, data.Certificates[0].CaPath)
		t.Fail()
	}

	if configAction != data.Certificates[0].Action.Command {
		t.Logf("Certificates.Action: expected %v, got %v", configAction, data.Certificates[0].Action.Command)
		t.Fail()
	}

}

// TestUnmarshalHTTPBlockAndDefaultSecrets covers the config surface added by
// #36, #37 and #48 in the shape a user actually writes it.
func TestUnmarshalHTTPBlockAndDefaultSecrets(t *testing.T) {
	yamlData := `
base_url: "https://certwarden.example.com"
default_cert_secret: "${CERTWARDEN_CERT_SECRET}"
default_key_secret: "file:/run/credentials/certwarden.service/key"
http:
  timeout: 30s
  retries: 4
  retry_backoff: 2s
  headers:
    CF-Access-Client-Id: "${CF_ACCESS_CLIENT_ID}"
    CF-Access-Client-Secret: "${CF_ACCESS_CLIENT_SECRET}"
certificates:
  - name: "example.com"
    cert_path: "/etc/certs/example.com.pem"
`

	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	if cfg.DefaultCertificateSecret != "${CERTWARDEN_CERT_SECRET}" {
		t.Errorf("DefaultCertificateSecret: got %v", cfg.DefaultCertificateSecret)
	}

	if cfg.DefaultKeySecret != "file:/run/credentials/certwarden.service/key" {
		t.Errorf("DefaultKeySecret: got %v", cfg.DefaultKeySecret)
	}

	if cfg.HTTP.Timeout != "30s" {
		t.Errorf("HTTP.Timeout: got %v", cfg.HTTP.Timeout)
	}

	if cfg.HTTP.Retries == nil || *cfg.HTTP.Retries != 4 {
		t.Errorf("HTTP.Retries: got %v", cfg.HTTP.Retries)
	}

	if cfg.HTTP.RetryBackoff != "2s" {
		t.Errorf("HTTP.RetryBackoff: got %v", cfg.HTTP.RetryBackoff)
	}

	if got := cfg.HTTP.Headers["CF-Access-Client-Id"]; got != "${CF_ACCESS_CLIENT_ID}" {
		t.Errorf("HTTP.Headers: got %v", got)
	}

	if len(cfg.HTTP.Headers) != 2 {
		t.Errorf("HTTP.Headers: expected 2 entries, got %v", cfg.HTTP.Headers)
	}
}

// TestUnmarshalOmittedHTTPBlockLeavesRetriesUnset is what lets HTTPSettings tell
// "retries: 0" from a missing key.
func TestUnmarshalOmittedHTTPBlockLeavesRetriesUnset(t *testing.T) {
	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte("base_url: \"https://certwarden.example.com\"\n"))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	if cfg.HTTP.Retries != nil {
		t.Errorf("expected an absent http block to leave retries unset, got %v", *cfg.HTTP.Retries)
	}
}

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

	if configAction != data.Certificates[0].Action {
		t.Logf("Certificates.Action: expected %v, got %v", configAction, data.Certificates[0].Action)
		t.Fail()
	}

}

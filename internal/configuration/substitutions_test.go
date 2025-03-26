package configuration

import (
	"testing"
)

// TestStringSubstitutionWithPlaceholders tests the string substitution feature.
// It ensures that {name}, {cert_path} and {key_path} get substituted correctly.
func TestStringSubstitutionWithPlaceholders(t *testing.T) {
	cert := CertificateData{
		Name:            "qwer",
		CertificatePath: "/fake/path/{name}",
		KeyPath:         "/fake/path/{name}-key",
		CaPath:          "/fake/path/{name}-ca",
		Action:          "./fake action {cert_path} {key_path} {ca_path}",
	}

	cfg := ConfigFileData{
		Certificates: []CertificateData{cert},
	}

	cfg.SubstituteKeys(nil)

	if cfg.Certificates[0].CertificatePath != "/fake/path/qwer" {
		t.Fail()
		t.Logf(`CertificatePath = %q, want "/fake/path/qwer"`, cfg.Certificates[0].CertificatePath)
	}
	if cfg.Certificates[0].KeyPath != "/fake/path/qwer-key" {
		t.Fail()
		t.Logf(`KeyPath = %q, want "/fake/path/qwer-key"`, cfg.Certificates[0].KeyPath)
	}
	if cfg.Certificates[0].CaPath != "/fake/path/qwer-ca" {
		t.Fail()
		t.Logf(`CaPath = %q, want "/fake/path/qwer-ca"`, cfg.Certificates[0].CaPath)
	}
	if cfg.Certificates[0].Action != "./fake action /fake/path/qwer /fake/path/qwer-key /fake/path/qwer-ca" {
		t.Fail()
		t.Logf(`Action = %q, want "./fake action /fake/path/qwer /fake/path/qwer-key /fake/path/qwer-ca"`, cfg.Certificates[0].Action)
	}
}

// TestStringSubstitutionWithPlaceholders tests the string substitution feature.
// It ensures that if no substitutes are present, the config values are not changed.
func TestStringSubstitutionWithoutPlaceholders(t *testing.T) {
	cert := CertificateData{
		Name:            "qwer",
		CertificatePath: "/fake/path/asd",
		KeyPath:         "/fake/path/asdf-key",
		CaPath:          "/fake/path/asdf-ca",
		Action:          "./fake action abcd efgh",
	}

	cfg := ConfigFileData{
		Certificates: []CertificateData{cert},
	}

	cfg.SubstituteKeys(nil)

	if cfg.Certificates[0].CertificatePath != "/fake/path/asd" {
		t.Fail()
		t.Logf(`CertificatePath = %q, want "/fake/path/asd"`, cfg.Certificates[0].CertificatePath)
	}
	if cfg.Certificates[0].KeyPath != "/fake/path/asdf-key" {
		t.Fail()
		t.Logf(`KeyPath = %q, want "/fake/path/asdf-key"`, cfg.Certificates[0].KeyPath)
	}
	if cfg.Certificates[0].CaPath != "/fake/path/asdf-ca" {
		t.Fail()
		t.Logf(`CaPath = %q, want "/fake/path/asdf-ca"`, cfg.Certificates[0].CaPath)
	}
	if cfg.Certificates[0].Action != "./fake action abcd efgh" {
		t.Fail()
		t.Logf(`Action = %q, want "./fake action abcd efgh"`, cfg.Certificates[0].Action)
	}
}

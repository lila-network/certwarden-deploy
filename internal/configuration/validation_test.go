package configuration

import "testing"

func TestGetConfigWithNilLoaderReturnsError(t *testing.T) {
	if _, err := GetConfig(nil); err == nil {
		t.Fatal("expected error for nil config loader")
	}
}

func TestConfigValidationReportsMissingAndInvalidFields(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:              "invalid name",
				CertificateSecret: "",
				CertificatePath:   "",
			},
			{
				Name: "",
			},
		},
	}

	err := cfg.IsValid()

	if !err.HasMessages() {
		t.Fatal("expected validation errors")
	}

	expectedMessages := map[string]bool{
		`Field 'base_url' in config file is required!`:                                   false,
		`Field 'cert_secret' for certificate invalid name cannot be blank!`:              false,
		`Field 'cert_path' for certificate invalid name cannot be blank!`:                false,
		`Field 'name' for certificate may only contain -_. and alphanumeric characters!`: false,
		`Field 'name' for certificates cannot be blank!`:                                 false,
		`Field 'cert_secret' for certificate unnamed_certificate cannot be blank!`:       false,
		`Field 'cert_path' for certificate unnamed_certificate cannot be blank!`:         false,
	}

	for _, message := range err.ErrorMessages {
		if _, ok := expectedMessages[message]; ok {
			expectedMessages[message] = true
		}
	}

	for message, seen := range expectedMessages {
		if !seen {
			t.Fatalf("expected validation message %q to be reported, got %v", message, err.ErrorMessages)
		}
	}
}

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

// TestConfigValidationRejectsBlankAction covers the difference between "no
// action wanted" and "an action was configured but it is blank": only the
// latter is a mistake.
func TestConfigValidationRejectsBlankAction(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://example.invalid",
		Certificates: []CertificateData{
			{
				Name:              "blank-string.example.com",
				CertificateSecret: "secret",
				CertificatePath:   "/tmp/blank-string-cert.pem",
				Action:            ShellAction("   "),
			},
			{
				Name:              "empty-list.example.com",
				CertificateSecret: "secret",
				CertificatePath:   "/tmp/empty-list-cert.pem",
				Action:            ExecAction(),
			},
		},
	}

	err := cfg.IsValid()

	for _, want := range []string{
		`Field 'action' for certificate blank-string.example.com cannot be blank!`,
		`Field 'action' for certificate empty-list.example.com cannot be blank!`,
	} {
		found := false
		for _, message := range err.ErrorMessages {
			if message == want {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("expected validation message %q, got %v", want, err.ErrorMessages)
		}
	}
}

func TestConfigValidationAcceptsOmittedAction(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://example.invalid",
		Certificates: []CertificateData{
			{
				Name:              "example.com",
				CertificateSecret: "secret",
				CertificatePath:   "/tmp/cert.pem",
			},
		},
	}

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected an omitted action to be valid, got %v", err.ErrorMessages)
	}
}

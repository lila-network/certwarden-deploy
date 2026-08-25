package configuration

import (
	"strings"
	"testing"
)

// blankSecretMessage builds the message IsValid reports for a certificate that
// ended up with no usable cert_secret.
func blankSecretMessage(name string) string {
	return `Field 'cert_secret' for certificate ` + name +
		` is set neither on the certificate nor as 'default_cert_secret', and ` +
		APIKeyEnvVar + ` is not set either!`
}

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
		blankSecretMessage("invalid name"):                                               false,
		`Field 'cert_path' for certificate invalid name cannot be blank!`:                false,
		`Field 'name' for certificate may only contain -_. and alphanumeric characters!`: false,
		`Field 'name' for certificates cannot be blank!`:                                 false,
		blankSecretMessage(unnamedCertificate):                                           false,
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
func TestConfigValidationAcceptsBlankAction(t *testing.T) {
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

	for _, unwanted := range []string{
		`Field 'action' for certificate blank-string.example.com cannot be blank!`,
		`Field 'action' for certificate empty-list.example.com cannot be blank!`,
	} {
		found := false
		for _, message := range err.ErrorMessages {
			if message == unwanted {
				found = true
				break
			}
		}

		if found {
			t.Fatalf("blank action must warn at rollout, not fail validation; got %q", unwanted)
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

// TestConfigValidationRejectsUnknownRunOn pins that a typo in run_on stops the
// run instead of being silently skipped: a policy nobody validates is an
// action that quietly never fires.
func TestConfigValidationRejectsUnknownRunOn(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://example.invalid",
		Certificates: []CertificateData{
			{
				Name:              "example.com",
				CertificateSecret: "secret",
				CertificatePath:   "/tmp/cert.pem",
				RunOn:             "on_change",
			},
		},
	}

	err := cfg.IsValid()

	if !err.HasMessages() {
		t.Fatal("expected an unknown run_on to be rejected")
	}

	want := `Field 'run_on' for certificate example.com must be one of 'new', 'changed', 'new_or_changed' or 'all', got 'on_change'!`
	for _, message := range err.ErrorMessages {
		if message == want {
			return
		}
	}

	t.Fatalf("expected validation message %q, got %v", want, err.ErrorMessages)
}

func TestConfigValidationAcceptsEveryKnownRunOn(t *testing.T) {
	for _, runOn := range []string{"", "new", "changed", "new_or_changed", "all"} {
		t.Run("run_on="+runOn, func(t *testing.T) {
			cfg := ConfigFileData{
				BaseURL: "https://example.invalid",
				Certificates: []CertificateData{
					{
						Name:              "example.com",
						CertificateSecret: "secret",
						CertificatePath:   "/tmp/cert.pem",
						RunOn:             runOn,
					},
				},
			}

			if err := cfg.IsValid(); err.HasMessages() {
				t.Fatalf("expected run_on %q to be valid, got %v", runOn, err.ErrorMessages)
			}
		})
	}
}

// TestEffectiveRunOnDefaultsToNewOrChanged pins the default that keeps every
// pre-run_on config behaving as before.
func TestEffectiveRunOnDefaultsToNewOrChanged(t *testing.T) {
	if got := (CertificateData{}).EffectiveRunOn(); got != RunOnNewOrChanged {
		t.Fatalf("omitted run_on = %q, want %q", got, RunOnNewOrChanged)
	}

	if got := (CertificateData{RunOn: "all"}).EffectiveRunOn(); got != RunOnAll {
		t.Fatalf("run_on 'all' = %q, want %q", got, RunOnAll)
	}
}

// Without a key_secret the combined secret the two endpoints authenticate with
// cannot be built, so the config must be rejected up front instead of failing
// with a 401 at runtime.
func TestConfigValidationRequiresKeySecretForPrivateCertPaths(t *testing.T) {
	tests := []struct {
		name        string
		cert        CertificateData
		wantMessage string
	}{
		{
			name: "privatecert_path without key_secret",
			cert: CertificateData{
				Name:              "example.com",
				CertificateSecret: "cert-secret",
				CertificatePath:   "/tmp/cert.pem",
				PrivateCertPath:   "/tmp/app.pem",
			},
			wantMessage: `Field 'key_secret' for certificate example.com is required when 'privatecert_path' is set!`,
		},
		{
			name: "privatecertchain_path without key_secret",
			cert: CertificateData{
				Name:                 "example.com",
				CertificateSecret:    "cert-secret",
				CertificatePath:      "/tmp/cert.pem",
				PrivateCertChainPath: "/tmp/app-fullchain.pem",
			},
			wantMessage: `Field 'key_secret' for certificate example.com is required when 'privatecertchain_path' is set!`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ConfigFileData{
				BaseURL:      "https://certwarden.example.com",
				Certificates: []CertificateData{test.cert},
			}

			err := cfg.IsValid()

			if !contains(err.ErrorMessages, test.wantMessage) {
				t.Fatalf("expected validation message %q, got %v", test.wantMessage, err.ErrorMessages)
			}
		})
	}
}

// Leaving both new paths unset must stay valid: they are optional and the
// behaviour without them is unchanged.
func TestConfigValidationAcceptsMissingPrivateCertPaths(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Certificates: []CertificateData{
			{
				Name:              "example.com",
				CertificateSecret: "cert-secret",
				CertificatePath:   "/tmp/cert.pem",
			},
		},
	}

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected config without private cert paths to be valid, got %v", err.ErrorMessages)
	}
}

func contains(messages []string, want string) bool {
	for _, message := range messages {
		if message == want {
			return true
		}
	}

	return false
}

func TestConfigValidationRejectsUnknownDownloadFormat(t *testing.T) {
	tests := []struct {
		name        string
		cert        CertificateData
		wantMessage string
	}{
		{
			name: "invalid privatecert_format",
			cert: CertificateData{
				Name:              "example.com",
				CertificateSecret: "cert-secret",
				CertificatePath:   "/tmp/cert.pem",
				KeySecret:         "key-secret",
				PrivateCertPath:   "/tmp/app.pem",
				PrivateCertFormat: "p12",
			},
			wantMessage: `Field 'privatecert_format' for certificate example.com must be one of pem, pkcs12, jks!`,
		},
		{
			name: "invalid privatecertchain_format",
			cert: CertificateData{
				Name:                   "example.com",
				CertificateSecret:      "cert-secret",
				CertificatePath:        "/tmp/cert.pem",
				KeySecret:              "key-secret",
				PrivateCertChainPath:   "/tmp/app-fullchain.pem",
				PrivateCertChainFormat: "der",
			},
			wantMessage: `Field 'privatecertchain_format' for certificate example.com must be one of pem, pkcs12, jks!`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ConfigFileData{
				BaseURL:      "https://certwarden.example.com",
				Certificates: []CertificateData{test.cert},
			}

			err := cfg.IsValid()

			if !contains(err.ErrorMessages, test.wantMessage) {
				t.Fatalf("expected validation message %q, got %v", test.wantMessage, err.ErrorMessages)
			}
		})
	}
}

func TestConfigValidationAcceptsEverySupportedDownloadFormat(t *testing.T) {
	for _, format := range []string{"", "pem", "pkcs12", "jks"} {
		t.Run("format "+format, func(t *testing.T) {
			cfg := ConfigFileData{
				BaseURL: "https://certwarden.example.com",
				Certificates: []CertificateData{
					{
						Name:                   "example.com",
						CertificateSecret:      "cert-secret",
						CertificatePath:        "/tmp/cert.pem",
						KeySecret:              "key-secret",
						PrivateCertPath:        "/tmp/app.pem",
						PrivateCertFormat:      format,
						PrivateCertChainPath:   "/tmp/app-fullchain.pem",
						PrivateCertChainFormat: format,
					},
				},
			}

			if err := cfg.IsValid(); err.HasMessages() {
				t.Fatalf("expected format %q to be valid, got %v", format, err.ErrorMessages)
			}
		})
	}
}

// TestConfigValidationBlankSecretCheckRunsAfterDefaults is the regression guard
// for the ordering #48 depends on: a certificate that deliberately leaves
// cert_secret out is valid as long as a default fills it in, and IsValid must
// not tell the user to set a field they left out on purpose.
func TestConfigValidationBlankSecretCheckRunsAfterDefaults(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "")

	cfg := ConfigFileData{
		BaseURL:                  "https://certwarden.example.com",
		DefaultCertificateSecret: "default-cert-secret",
		DefaultKeySecret:         "default-key-secret",
		Certificates: []CertificateData{
			{Name: "example.com", CertificatePath: "/etc/certs/example.com.pem"},
		},
	}

	// before resolution the raw field really is blank, which is exactly the
	// state the old check used to reject
	if cfg.Certificates[0].CertificateSecret != "" {
		t.Fatal("precondition failed: cert_secret should start out blank")
	}

	resolution := cfg.ResolveSecrets(testLogger())
	assertNoMessages(t, resolution)

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected a defaulted certificate to validate, got %v", err.ErrorMessages)
	}
}

// TestConfigValidationBlankSecretMessageNamesBothPlaces makes sure the error
// points at every place the secret could have come from, not just the field on
// the certificate.
func TestConfigValidationBlankSecretMessageNamesBothPlaces(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "")

	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Certificates: []CertificateData{
			{Name: "example.com", CertificatePath: "/etc/certs/example.com.pem"},
		},
	}

	assertNoMessages(t, cfg.ResolveSecrets(testLogger()))

	err := cfg.IsValid()
	message := onlyMessage(t, err)

	for _, want := range []string{"cert_secret", "example.com", "default_cert_secret", APIKeyEnvVar} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected message to mention %q, got %q", want, message)
		}
	}
}

package configuration

import (
	"bytes"
	"strings"
	"testing"
)

// withOverrides sets the CLI override vars for one test and restores them after,
// so a test can never bleed into the next one through package state.
func withOverrides(t *testing.T, baseURL string, apiKey string) {
	t.Helper()

	previousBaseURL, previousAPIKey := BaseURLOverride, APIKeyOverride
	t.Cleanup(func() {
		BaseURLOverride, APIKeyOverride = previousBaseURL, previousAPIKey
	})

	BaseURLOverride, APIKeyOverride = baseURL, apiKey
}

func TestApplyOverridesReplacesBaseURL(t *testing.T) {
	withOverrides(t, "https://staging.example.com", "")

	cfg := ConfigFileData{BaseURL: "https://certwarden.example.com"}
	cfg.ApplyOverrides(testLogger())

	if cfg.BaseURL != "https://staging.example.com" {
		t.Fatalf("unexpected base_url: got %q", cfg.BaseURL)
	}
}

func TestApplyOverridesKeepsConfigValueWhenFlagIsUnset(t *testing.T) {
	withOverrides(t, "", "")

	cfg := ConfigFileData{BaseURL: "https://certwarden.example.com"}
	cfg.ApplyOverrides(testLogger())

	if cfg.BaseURL != "https://certwarden.example.com" {
		t.Fatalf("unset --base-url must not touch the config value, got %q", cfg.BaseURL)
	}
}

// TestValidationRejectsInvalidBaseURLOverride makes sure a typo on the command
// line is caught during validation, before any request goes out.
func TestValidationRejectsInvalidBaseURLOverride(t *testing.T) {
	for _, invalid := range []string{"not a url", "certwarden.example.com", "://missing-scheme"} {
		t.Run(invalid, func(t *testing.T) {
			withOverrides(t, invalid, "")

			cfg := ConfigFileData{BaseURL: "https://certwarden.example.com"}
			cfg.ApplyOverrides(testLogger())

			err := cfg.IsValid()
			if !err.HasMessages() {
				t.Fatalf("expected %q to be rejected as base_url", invalid)
			}

			if !strings.Contains(strings.Join(err.ErrorMessages, "\n"), "base_url") {
				t.Fatalf("expected the message to name base_url, got %v", err.ErrorMessages)
			}
		})
	}
}

func TestValidationAcceptsValidBaseURLOverride(t *testing.T) {
	withOverrides(t, "http://127.0.0.1:8080", "")

	cfg := ConfigFileData{BaseURL: "https://certwarden.example.com"}
	cfg.ApplyOverrides(testLogger())

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected a valid override to pass validation, got %v", err.ErrorMessages)
	}
}

// TestAPIKeyOverrideAppliesToEveryCertificate documents the blunt part of the
// flag: it replaces both secrets on every certificate, whatever the config said.
func TestAPIKeyOverrideAppliesToEveryCertificate(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "env-api-key")
	withOverrides(t, "", "flag-api-key")

	cfg := ConfigFileData{
		DefaultCertificateSecret: "config-default",
		Certificates: []CertificateData{
			{Name: "one.example.com", CertificateSecret: "per-certificate", KeySecret: "per-certificate-key"},
			{Name: "two.example.com"},
		},
	}

	assertNoMessages(t, cfg.ResolveSecrets(testLogger()))

	for _, cert := range cfg.Certificates {
		if cert.CertificateSecret != "flag-api-key" || cert.KeySecret != "flag-api-key" {
			t.Fatalf("expected --api-key to win for %s: got cert=%q key=%q",
				cert.Name, cert.CertificateSecret, cert.KeySecret)
		}
	}
}

// TestAPIKeyOverridePrecedence pins flag > env > config for the secret chain.
func TestAPIKeyOverridePrecedence(t *testing.T) {
	tests := []struct {
		name       string
		flag       string
		env        string
		certSecret string
		want       string
	}{
		{name: "flag beats env and config", flag: "flag-api-key", env: "env-api-key", certSecret: "config-secret", want: "flag-api-key"},
		{name: "env beats config when it is the only fallback", env: "env-api-key", want: "env-api-key"},
		{name: "config wins when no flag is given", env: "env-api-key", certSecret: "config-secret", want: "config-secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(APIKeyEnvVar, tc.env)
			withOverrides(t, "", tc.flag)

			cfg := ConfigFileData{
				Certificates: []CertificateData{{Name: "example.com", CertificateSecret: tc.certSecret}},
			}

			assertNoMessages(t, cfg.ResolveSecrets(testLogger()))

			if got := cfg.Certificates[0].CertificateSecret; got != tc.want {
				t.Fatalf("unexpected cert_secret: got %q want %q", got, tc.want)
			}
		})
	}
}

// TestAPIKeyOverrideSkipsUnresolvableReferences covers why --api-key
// short-circuits resolution: it is reached for precisely when the config's
// references do not resolve on the box you are debugging on.
func TestAPIKeyOverrideSkipsUnresolvableReferences(t *testing.T) {
	withOverrides(t, "", "flag-api-key")

	cfg := ConfigFileData{
		DefaultCertificateSecret: "${CERTWARDEN_DEFINITELY_UNSET}",
		Certificates: []CertificateData{
			{Name: "example.com", CertificateSecret: "${ALSO_DEFINITELY_UNSET}"},
		},
	}

	err := cfg.ResolveSecrets(testLogger())
	if err.HasMessages() {
		t.Fatalf("expected --api-key to make unresolvable references moot, got %v", err.ErrorMessages)
	}

	if cfg.Certificates[0].CertificateSecret != "flag-api-key" {
		t.Fatalf("unexpected cert_secret: got %q", cfg.Certificates[0].CertificateSecret)
	}
}

// TestOverridesNeverLogTheAPIKeyValue is the security guard for #35: the flag
// name may be logged, the key behind it may not.
func TestOverridesNeverLogTheAPIKeyValue(t *testing.T) {
	const apiKey = "FLAGAPIKEYMUSTNEVERAPPEARINTHEJOURNAL"

	withOverrides(t, "https://staging.example.com", apiKey)

	var logs bytes.Buffer
	logger := capturingLogger(&logs)

	cfg := ConfigFileData{
		BaseURL:      "https://certwarden.example.com",
		Certificates: []CertificateData{{Name: "example.com"}},
	}
	cfg.ApplyOverrides(logger)
	assertNoMessages(t, cfg.ResolveSecrets(logger))

	if cfg.Certificates[0].CertificateSecret != apiKey {
		t.Fatalf("precondition failed: --api-key was not applied, got %q", cfg.Certificates[0].CertificateSecret)
	}

	if strings.Contains(logs.String(), apiKey) {
		t.Fatalf("--api-key value leaked into log output: %q", logs.String())
	}

	// the flag itself is reported, so an override is still traceable
	if !strings.Contains(logs.String(), "--api-key") {
		t.Fatalf("expected the flag name to be logged at debug, got %q", logs.String())
	}

	if !strings.Contains(logs.String(), "--base-url") {
		t.Fatalf("expected the --base-url override to be logged at debug, got %q", logs.String())
	}
}

package configuration

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeSecretFile drops a secret into a file and returns a "file:" reference to it.
func writeSecretFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	return fileRefPrefix + path
}

// resolveOne runs a single certificate through ResolveSecrets and returns the
// resolved certificate plus the validation result.
func resolveOne(t *testing.T, cert CertificateData) (CertificateData, ConfigValidationError) {
	t.Helper()

	cfg := ConfigFileData{Certificates: []CertificateData{cert}}
	err := cfg.ResolveSecrets(testLogger())

	return cfg.Certificates[0], err
}

// assertNoMessages fails the test if the validation reported anything.
func assertNoMessages(t *testing.T, err ConfigValidationError) {
	t.Helper()

	if err.HasMessages() {
		t.Fatalf("unexpected validation errors: %v", err.ErrorMessages)
	}
}

// onlyMessage returns the single reported validation message.
func onlyMessage(t *testing.T, err ConfigValidationError) string {
	t.Helper()

	if len(err.ErrorMessages) != 1 {
		t.Fatalf("expected exactly one validation message, got %v", err.ErrorMessages)
	}

	return err.ErrorMessages[0]
}

func TestResolveSecretsExpandsEnvironmentReference(t *testing.T) {
	t.Setenv("CERTWARDEN_APP_CERT_SECRET", "env-cert-secret")
	t.Setenv("CERTWARDEN_APP_KEY_SECRET", "env-key-secret")

	cert, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: "${CERTWARDEN_APP_CERT_SECRET}",
		KeySecret:         "${CERTWARDEN_APP_KEY_SECRET}",
	})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "env-cert-secret" {
		t.Fatalf("unexpected cert_secret: got %q", cert.CertificateSecret)
	}

	if cert.KeySecret != "env-key-secret" {
		t.Fatalf("unexpected key_secret: got %q", cert.KeySecret)
	}
}

// TestResolveSecretsReadsAndTrimsFileReference covers the systemd
// LoadCredential= shape, where the credential file usually ends in a newline.
func TestResolveSecretsReadsAndTrimsFileReference(t *testing.T) {
	cert, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: writeSecretFile(t, "  file-secret\n"),
	})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "file-secret" {
		t.Fatalf("expected file contents to be trimmed: got %q", cert.CertificateSecret)
	}
}

func TestResolveSecretsLeavesLiteralValueUnchanged(t *testing.T) {
	cert, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: "examplekey_notvalid_hrzjGDDw8z",
	})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "examplekey_notvalid_hrzjGDDw8z" {
		t.Fatalf("literal value was modified: got %q", cert.CertificateSecret)
	}
}

// TestResolveSecretsEscapesLiteralDollarBrace documents the escape hatch for a
// secret that genuinely starts with "${".
func TestResolveSecretsEscapesLiteralDollarBrace(t *testing.T) {
	t.Setenv("CERTWARDEN_APP_CERT_SECRET", "must-not-be-used")

	cert, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: "$${CERTWARDEN_APP_CERT_SECRET}",
	})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "${CERTWARDEN_APP_CERT_SECRET}" {
		t.Fatalf("unexpected escaped value: got %q", cert.CertificateSecret)
	}
}

// TestResolveSecretsErrorsOnUnsetEnvironmentVariable pins the "loud, not empty"
// contract: an unset variable is a config error, never a silently blank secret.
func TestResolveSecretsErrorsOnUnsetEnvironmentVariable(t *testing.T) {
	os.Unsetenv("CERTWARDEN_DEFINITELY_UNSET")

	_, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: "${CERTWARDEN_DEFINITELY_UNSET}",
	})

	message := onlyMessage(t, err)

	if !strings.Contains(message, "CERTWARDEN_DEFINITELY_UNSET") {
		t.Fatalf("expected the message to name the variable, got %q", message)
	}

	if !strings.Contains(message, "cert_secret") || !strings.Contains(message, "example.com") {
		t.Fatalf("expected the message to name the field and certificate, got %q", message)
	}
}

func TestResolveSecretsErrorsOnUnreadableFileReference(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")

	_, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: fileRefPrefix + missing,
	})

	message := onlyMessage(t, err)

	if !strings.Contains(message, missing) {
		t.Fatalf("expected the message to name the path, got %q", message)
	}
}

// TestResolveSecretsRejectsMalformedEnvironmentReference makes sure a partial
// reference is reported instead of being sent to the server as a literal, which
// would only ever surface as a confusing 401.
func TestResolveSecretsRejectsMalformedEnvironmentReference(t *testing.T) {
	t.Setenv("CERTWARDEN_APP_CERT_SECRET", "env-cert-secret")

	for _, raw := range []string{"${CERTWARDEN_APP_CERT_SECRET}-suffix", "${}", "${ SPACED }"} {
		t.Run(raw, func(t *testing.T) {
			_, err := resolveOne(t, CertificateData{Name: "example.com", CertificateSecret: raw})

			message := onlyMessage(t, err)
			if !strings.Contains(message, "malformed environment variable reference") {
				t.Fatalf("expected a malformed-reference message, got %q", message)
			}
		})
	}
}

// TestResolveSecretsFallsBackToAPIKeyEnvVar covers the parity layer: one key in
// the environment, no secrets in the file at all.
func TestResolveSecretsFallsBackToAPIKeyEnvVar(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "env-api-key")

	cert, err := resolveOne(t, CertificateData{Name: "example.com"})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "env-api-key" || cert.KeySecret != "env-api-key" {
		t.Fatalf("expected both secrets to fall back to %s: got cert=%q key=%q",
			APIKeyEnvVar, cert.CertificateSecret, cert.KeySecret)
	}
}

// TestResolveSecretsPrefersCertificateSecretOverEnvVar pins the precedence
// between the per-certificate value and the environment fallback.
func TestResolveSecretsPrefersCertificateSecretOverEnvVar(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "env-api-key")

	cert, err := resolveOne(t, CertificateData{
		Name:              "example.com",
		CertificateSecret: "per-certificate-secret",
	})

	assertNoMessages(t, err)

	if cert.CertificateSecret != "per-certificate-secret" {
		t.Fatalf("expected the certificate secret to win: got %q", cert.CertificateSecret)
	}

	// key_secret was not set on the certificate, so it still uses the fallback
	if cert.KeySecret != "env-api-key" {
		t.Fatalf("expected key_secret to fall back: got %q", cert.KeySecret)
	}
}

// TestResolveSecretsNeverLogsResolvedSecrets is the security guard for #34.
//
// Debug is the loudest level the tool can be run at, so if a resolved secret is
// absent here it is absent everywhere. Every indirection form is exercised at
// once: whichever way a secret enters the config, it must not come back out
// through the journal.
func TestResolveSecretsNeverLogsResolvedSecrets(t *testing.T) {
	const (
		envSecret     = "ENVSECRETMUSTNEVERAPPEARINTHEJOURNAL"
		fileSecret    = "FILESECRETMUSTNEVERAPPEARINTHEJOURNAL"
		literalSecret = "LITERALSECRETMUSTNEVERAPPEARINTHEJOURNAL"
		fallbackKey   = "FALLBACKKEYMUSTNEVERAPPEARINTHEJOURNAL"
	)

	t.Setenv("CERTWARDEN_APP_CERT_SECRET", envSecret)
	t.Setenv(APIKeyEnvVar, fallbackKey)

	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:              "env.example.com",
				CertificateSecret: "${CERTWARDEN_APP_CERT_SECRET}",
				KeySecret:         writeSecretFile(t, fileSecret+"\n"),
			},
			{
				Name:              "literal.example.com",
				CertificateSecret: literalSecret,
			},
		},
	}

	var logs bytes.Buffer
	err := cfg.ResolveSecrets(capturingLogger(&logs))
	assertNoMessages(t, err)

	// the secrets really did make it into the config, so the check below is not
	// passing for the trivial reason that nothing was resolved at all
	if cfg.Certificates[0].CertificateSecret != envSecret {
		t.Fatalf("env secret was not resolved: got %q", cfg.Certificates[0].CertificateSecret)
	}
	if cfg.Certificates[0].KeySecret != fileSecret {
		t.Fatalf("file secret was not resolved: got %q", cfg.Certificates[0].KeySecret)
	}
	if cfg.Certificates[1].KeySecret != fallbackKey {
		t.Fatalf("fallback key was not applied: got %q", cfg.Certificates[1].KeySecret)
	}

	for _, secret := range []string{envSecret, fileSecret, literalSecret, fallbackKey} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("resolved secret %q leaked into log output: %q", secret, logs.String())
		}
	}
}

// TestResolveSecretsErrorsNeverContainTheValue makes sure the "name the
// variable, not the value" rule also holds when a file was read successfully but
// something else about the config is wrong.
func TestResolveSecretsErrorsNeverContainTheValue(t *testing.T) {
	const secret = "SECRETVALUEMUSTNEVERAPPEARINANERROR"

	ref := writeSecretFile(t, secret)

	var logs bytes.Buffer
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{Name: "example.com", CertificateSecret: ref, KeySecret: "${CERTWARDEN_DEFINITELY_UNSET}"},
		},
	}
	os.Unsetenv("CERTWARDEN_DEFINITELY_UNSET")

	err := cfg.ResolveSecrets(capturingLogger(&logs))
	err.Print(capturingLogger(&logs))

	if strings.Contains(logs.String(), secret) {
		t.Fatalf("secret leaked through the validation error output: %q", logs.String())
	}
}

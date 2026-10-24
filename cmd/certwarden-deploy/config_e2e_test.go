package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
)

// deadAddress is a port nothing listens on.
//
// It is what a config file looks like from a CI runner that has never heard of
// the CertWarden instance it names, which is precisely the case `config
// validate` has to work in.
const deadAddress = "http://127.0.0.1:1"

// TestCLI_ConfigValidateMakesNoNetworkRequests is the contract of the whole
// command: it has to work in a pre-commit hook, on a laptop, against a server
// that is not reachable and may not even exist.
//
// The server counts every request it gets, and getting any at all is the
// failure.
func TestCLI_ConfigValidateMakesNoNetworkRequests(t *testing.T) {
	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("config validate made a request to %s", r.URL.Path)
	}))
	defer server.Close()

	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()

	cert := newE2ECert(tmpDir, "example.com")
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runSplit(t, 0, binaryPath, "-c", configPath, "config", "validate")

	if got := requests.Load(); got != 0 {
		t.Fatalf("config validate made %d requests, want 0", got)
	}
}

// TestCLI_ConfigValidateWorksAgainstADeadAddress is the same contract from the
// other side, and contrasts it with --dry-run, which is what users reach for
// today and which is not a substitute: it really does hit the API.
func TestCLI_ConfigValidateWorksAgainstADeadAddress(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()

	cert := newE2ECert(tmpDir, "example.com")
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, deadAddress, cert)

	runSplit(t, 0, binaryPath, "-c", configPath, "config", "validate")

	// a dry run against the same config fails, because it fetches
	runSplit(t, 2, binaryPath, "-c", configPath, "--dry-run")
}

func TestCLI_ConfigValidateExitsOneAndReportsEveryError(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// three independent problems: no base_url, no cert_secret, unknown run_on
	writeFile(t, configPath, `certificates:
  - name: "example.com"
    cert_path: "/tmp/cert.pem"
    run_on: "whenever"
`)

	_, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "config", "validate")

	// every problem at once, not just the first one
	for _, want := range []string{"'base_url'", "'cert_secret'", "'run_on'"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("expected %s to be reported, got:\n%s", want, stderr)
		}
	}
}

func TestCLI_ConfigValidateExitsZeroOnAGoodConfig(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()

	cert := newE2ECert(tmpDir, "example.com")
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, "https://certwarden.example.com", cert)

	runSplit(t, 0, binaryPath, "-c", configPath, "config", "validate")
}

// TestCLI_ConfigShowRedactsSecretsAndHeaders is the security guard for #40.
//
// The reference Python tool's `config view` dumps the parsed YAML, plaintext
// API keys and all, straight to stdout. This asserts the resolved values are
// nowhere in the output, wherever they came from: a literal, an environment
// reference, a config-level default and a header.
func TestCLI_ConfigShowRedactsSecretsAndHeaders(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	credential := filepath.Join(tmpDir, "key-credential")
	writeFile(t, credential, "FILE-KEY-SECRET\n")

	writeFile(t, configPath, fmt.Sprintf(`base_url: "https://certwarden.example.com"
default_cert_secret: "DEFAULT-CERT-SECRET"
default_key_secret: "DEFAULT-KEY-SECRET"
http:
  headers:
    CF-Access-Client-Id: "HEADER-CLIENT-ID"
    CF-Access-Client-Secret: "${CF_ACCESS_SECRET}"
certificates:
  - name: "literal.example.com"
    cert_secret: "LITERAL-CERT-SECRET"
    cert_path: "/tmp/literal-cert.pem"
    key_secret: "file:%s"
    key_path: "/tmp/literal-key.pem"
  - name: "env.example.com"
    cert_secret: "${ENV_CERT_SECRET}"
    cert_path: "/tmp/env-cert.pem"
  - name: "default.example.com"
    cert_path: "/tmp/default-cert.pem"
`, credential))

	t.Setenv("CF_ACCESS_SECRET", "HEADER-ACCESS-SECRET")
	t.Setenv("ENV_CERT_SECRET", "ENV-CERT-SECRET")

	stdout, stderr := runSplit(t, 0, binaryPath, "-v", "-c", configPath, "config", "show")

	// every value that is a secret, whatever it was resolved from
	secrets := []string{
		"LITERAL-CERT-SECRET",
		"FILE-KEY-SECRET",
		"ENV-CERT-SECRET",
		"DEFAULT-CERT-SECRET",
		"DEFAULT-KEY-SECRET",
		"HEADER-CLIENT-ID",
		"HEADER-ACCESS-SECRET",
	}

	for _, secret := range secrets {
		if strings.Contains(stdout, secret) {
			t.Errorf("secret %q leaked into the config show output:\n%s", secret, stdout)
		}

		// --verbose is on, so this also covers the log
		if strings.Contains(stderr, secret) {
			t.Errorf("secret %q leaked into the log:\n%s", secret, stderr)
		}
	}

	// and the output is still useful: it says a secret is there
	if !strings.Contains(stdout, configuration.RedactedSecret) {
		t.Fatalf("expected redacted secrets in the output:\n%s", stdout)
	}

	// the header names stay: whether CF-Access-Client-Id is sent at all is the
	// question this output exists to answer
	for _, name := range []string{"CF-Access-Client-Id", "CF-Access-Client-Secret"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("expected header name %q to be shown:\n%s", name, stdout)
		}
	}

	// One <redacted> per field that ended up holding a secret: the 2
	// config-level defaults, the 2 headers, and both secrets of all 3
	// certificates, every one of which resolved to something because the
	// defaults fill in whatever the entry left out.
	if got := strings.Count(stdout, configuration.RedactedSecret); got != 10 {
		t.Errorf("expected 10 redacted values, got %d:\n%s", got, stdout)
	}
}

// TestCLI_ConfigShowHasNoEscapeHatch pins that there is no way to ask for the
// plaintext. The flag not existing is the feature.
func TestCLI_ConfigShowHasNoEscapeHatch(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	writeE2EConfig(t, configPath, "https://certwarden.example.com", newE2ECert(tmpDir, "example.com"))

	for _, flag := range []string{"--show-secrets", "--reveal-secrets", "--unsafe"} {
		if _, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "config", "show", flag); !strings.Contains(stderr, "unknown flag") {
			t.Errorf("expected %s not to exist, got: %s", flag, stderr)
		}
	}
}

// TestCLI_ConfigShowReflectsSubstitutionAndResolution makes sure the output is
// the effective config rather than a re-dump of the file: a config file that is
// read back verbatim answers nothing that `cat` does not.
func TestCLI_ConfigShowReflectsSubstitutionAndResolution(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// no cert_secret anywhere in the file: it can only come from the fallback
	writeFile(t, configPath, `base_url: "https://certwarden.example.com"
certificates:
  - name: "example.com"
    cert_path: "/etc/ssl/{name}/fullchain.pem"
    action: "/usr/bin/systemctl reload nginx"
`)

	t.Setenv(configuration.APIKeyEnvVar, "ENV-FALLBACK-SECRET")

	stdout, _ := runSplit(t, 0, binaryPath, "--base-url", "https://override.example.com", "-c", configPath, "config", "show")

	// placeholders are expanded
	if !strings.Contains(stdout, "/etc/ssl/example.com/fullchain.pem") {
		t.Errorf("expected {name} to be substituted:\n%s", stdout)
	}
	if strings.Contains(stdout, "{name}") {
		t.Errorf("expected no unexpanded placeholder:\n%s", stdout)
	}

	// the CLI override is folded in
	if !strings.Contains(stdout, "https://override.example.com") {
		t.Errorf("expected --base-url to be reflected:\n%s", stdout)
	}

	// the CERTWARDEN_API_KEY fallback was applied: the field is redacted rather
	// than empty, which is the whole point of redacting an unset secret to ""
	if !strings.Contains(stdout, "cert_secret: "+configuration.RedactedSecret) {
		t.Errorf("expected the resolved fallback secret to show as redacted:\n%s", stdout)
	}
	if strings.Contains(stdout, "ENV-FALLBACK-SECRET") {
		t.Fatalf("the resolved secret leaked:\n%s", stdout)
	}

	// defaults a run would apply are filled in
	for _, want := range []string{"run_on: new_or_changed", "enabled: true", "timeout: 10s", "retries: 2"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected the effective config to show %q:\n%s", want, stdout)
		}
	}
}

func TestCLI_ConfigShowExitsOneOnABrokenConfig(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	writeFile(t, configPath, "certificates:\n  - name: \"example.com\"\n")

	stdout, _ := runSplit(t, 1, binaryPath, "-c", configPath, "config", "show")
	if stdout != "" {
		t.Errorf("expected no config to be printed for a broken config, got:\n%s", stdout)
	}
}

func TestCLI_ConfigInitRefusesToClobberWithoutForce(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	initTarget := filepath.Join(tmpDir, "config.yaml")

	writeFile(t, initTarget, "base_url: \"https://precious.example.com\"\n")

	_, stderr := runSplit(t, 1, binaryPath, "config", "init", "--path", initTarget)
	if !strings.Contains(stderr, "--force") {
		t.Errorf("expected the error to point at --force, got: %s", stderr)
	}

	assertFileContents(t, initTarget, "base_url: \"https://precious.example.com\"\n")

	// --force replaces it
	runSplit(t, 0, binaryPath, "config", "init", "--path", initTarget, "--force")

	data, err := os.ReadFile(initTarget)
	if err != nil {
		t.Fatalf("failed to read %s: %v", initTarget, err)
	}

	if strings.Contains(string(data), "precious.example.com") {
		t.Errorf("expected --force to replace the file, got:\n%s", string(data))
	}
}

// TestCLI_ConfigInitWritesAValidConfig closes the loop between the two
// commands: a scaffold that its own linter rejects is not a scaffold.
func TestCLI_ConfigInitWritesAValidConfig(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	initTarget := filepath.Join(tmpDir, "config.yaml")

	runSplit(t, 0, binaryPath, "config", "init", "--path", initTarget)

	info, err := os.Stat(initTarget)
	if err != nil {
		t.Fatalf("failed to stat %s: %v", initTarget, err)
	}

	// the file that is about to hold API keys is not world readable
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("unexpected mode for the starter config: got %o want 600", mode)
	}

	runSplit(t, 0, binaryPath, "-c", initTarget, "config", "validate")

	// and it is commented, not a bare skeleton
	data, err := os.ReadFile(initTarget)
	if err != nil {
		t.Fatalf("failed to read %s: %v", initTarget, err)
	}

	if !strings.Contains(string(data), "# required") {
		t.Errorf("expected the starter config to be commented:\n%s", string(data))
	}
}

// TestCLI_ConfigInitDefaultPathIsDiscoverable pins the coupling between the
// default --path and the config file search: `config init` followed by a bare
// run in the same directory has to find the file that was just written.
func TestCLI_ConfigInitDefaultPathIsDiscoverable(t *testing.T) {
	binaryPath := buildBinary(t)
	workDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	runSplitInDir(t, 0, workDir, binaryPath, "config", "init")

	if _, err := os.Stat(filepath.Join(workDir, "certwarden-deploy.yaml")); err != nil {
		t.Fatalf("expected the starter config in the working directory: %v", err)
	}

	// no -c: this only passes if discovery finds what init wrote
	runSplitInDir(t, 0, workDir, binaryPath, "config", "validate")
}

// TestCLI_ConfigShowDesugarsGroups is the seam between the groups feature and
// this command.
//
// `config show` answers "what will the tool act on", and what it acts on is
// never a group: ExpandGroups desugars them before the first request. So the
// output has to be the flat list, with the group's values on each member and
// {name} resolved per certificate, and it must not echo the groups back.
func TestCLI_ConfigShowDesugarsGroups(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	writeFile(t, configPath, `base_url: "https://certwarden.example.com"
groups:
  nginx:
    cert_secret: "GROUP-CERT-SECRET"
    key_secret: "GROUP-KEY-SECRET"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    key_path: "/etc/nginx/ssl/{name}.key"
    action: "systemctl reload nginx"
    certificates:
      - name: "a.example.com"
      - name: "b.example.com"
        key_secret: "OWN-KEY-SECRET"
certificates:
  - name: "flat.example.com"
    cert_secret: "FLAT-CERT-SECRET"
    cert_path: "/etc/ssl/flat.crt"
`)

	stdout, _ := runSplit(t, 0, binaryPath, "-c", configPath, "config", "show")

	// the sugar is gone: the groups key describes nothing the run does
	if strings.Contains(stdout, "groups:") {
		t.Errorf("expected the groups to be desugared away:\n%s", stdout)
	}

	// every member of the group is there, with the group's path resolved for it
	for _, want := range []string{
		"name: a.example.com",
		"name: b.example.com",
		"name: flat.example.com",
		"/etc/nginx/ssl/a.example.com.crt",
		"/etc/nginx/ssl/b.example.com.key",
		"action: systemctl reload nginx",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected the desugared config to show %q:\n%s", want, stdout)
		}
	}

	if strings.Contains(stdout, "{name}") {
		t.Errorf("expected no unexpanded placeholder:\n%s", stdout)
	}

	// and not one of the secrets a group carries reaches the output, on the
	// group or on the certificates it expanded to
	for _, secret := range []string{"GROUP-CERT-SECRET", "GROUP-KEY-SECRET", "OWN-KEY-SECRET", "FLAT-CERT-SECRET"} {
		if strings.Contains(stdout, secret) {
			t.Fatalf("secret %q leaked into `config show` output:\n%s", secret, stdout)
		}
	}

	// redacted rather than dropped: the output still says a secret is there
	if count := strings.Count(stdout, "cert_secret: "+configuration.RedactedSecret); count != 3 {
		t.Errorf("expected all 3 certificates to show a redacted cert_secret, got %d:\n%s", count, stdout)
	}
}

// TestCLI_ConfigValidateChecksGroupedConfigs makes sure the linter sees a
// grouped config the way a run does.
//
// A group is desugared before validation, so a problem introduced by a group
// has to be reported by `config validate` rather than waiting for a real run to
// hit it, and the message has to name the group so the user knows where to look.
func TestCLI_ConfigValidateChecksGroupedConfigs(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// a duplicate name reachable only by expanding the group: without
	// ExpandGroups in the validate path there is no certificate here to check
	// at all, and the command would call this file clean
	writeFile(t, configPath, `base_url: "https://certwarden.example.com"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: "dup.example.com"
      - name: "dup.example.com"
`)

	_, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "config", "validate")

	if !strings.Contains(stderr, "is not unique") {
		t.Errorf("expected the duplicate name to be reported:\n%s", stderr)
	}

	// the message names the group, which is the only pointer at the offending
	// line there is when the value at fault is the group's
	if !strings.Contains(stderr, "group 'nginx'") {
		t.Errorf("expected the message to name the group:\n%s", stderr)
	}

}

// TestCLI_ConfigValidateChecksGroupSuppliedValues makes sure IsValid runs over
// the values a group supplied, not just over the ones typed on a certificate.
//
// Nothing downstream of ExpandGroups knows a group was involved, so this is
// really a check that validate desugars before it validates rather than after.
func TestCLI_ConfigValidateChecksGroupSuppliedValues(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// every faulty value here is set on the group and on no certificate
	writeFile(t, configPath, `base_url: "https://certwarden.example.com"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    privatecert_path: "/etc/nginx/ssl/{name}.p12"
    privatecert_format: "bogus"
    run_on: "whenever"
    certificates:
      - name: "a.example.com"
`)

	_, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "config", "validate")

	for _, want := range []string{
		// the format the group set is not a container that exists
		"privatecert_format",
		// the group set privatecert_path but no key_secret, which that
		// endpoint cannot be called without
		"key_secret",
		// the group's run_on is not a policy that exists
		"run_on",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("expected the group's %s to be reported:\n%s", want, stderr)
		}
	}

	// and the messages name the group, because the offending line is in it
	if !strings.Contains(stderr, "group 'nginx'") {
		t.Errorf("expected the messages to name the group:\n%s", stderr)
	}
}

// TestCLI_ConfigValidateReportsAGroupFlatCollision pins the collision that
// spans both keys, which is the one a user cannot see by reading either key on
// its own.
func TestCLI_ConfigValidateReportsAGroupFlatCollision(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	writeFile(t, configPath, `base_url: "https://certwarden.example.com"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: "dup.example.com"
certificates:
  - name: "dup.example.com"
    cert_secret: "secret"
    cert_path: "/etc/ssl/dup.crt"
`)

	_, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "config", "validate")

	// the flat entry is the one reported: it is the second of the two, the
	// expanded members being placed first. See ExpandGroups.
	if !strings.Contains(stderr, "certificate dup.example.com is not unique") {
		t.Errorf("expected the collision across groups and the flat list to be reported:\n%s", stderr)
	}
}

// TestCLI_ConfigValidateAcceptsAGoodGroupedConfig is the other half: a group
// that fills in the fields its members leave out must not be reported as if the
// members had left them out.
func TestCLI_ConfigValidateAcceptsAGoodGroupedConfig(t *testing.T) {
	binaryPath := buildBinary(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// neither certificate sets cert_secret or cert_path: both are required, and
	// both come from the group
	writeFile(t, configPath, `base_url: "`+deadAddress+`"
groups:
  nginx:
    cert_secret: "${GROUP_SECRET_VAR}"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: "a.example.com"
      - name: "b.example.com"
`)

	t.Setenv("GROUP_SECRET_VAR", "resolved-from-the-env")

	// exit 0: the group satisfies every requirement its members do not
	runSplit(t, 0, binaryPath, "-c", configPath, "config", "validate")
}

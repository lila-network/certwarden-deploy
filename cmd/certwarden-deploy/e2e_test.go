package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/constants"
)

func TestCLI_DeploysFilesAndOnlyRunsActionOnChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case constants.CertificateApiPath + "example.com":
			_, _ = w.Write([]byte("cert-body"))
		case constants.KeyApiPath + "example.com":
			_, _ = w.Write([]byte("key-body"))
		case constants.CaCertificateApiPath + "example.com":
			_, _ = w.Write([]byte("ca-body"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	actionMarker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", actionMarker))

	certPath := filepath.Join(tmpDir, "certs", "example.com-cert.pem")
	keyPath := filepath.Join(tmpDir, "certs", "example.com-key.pem")
	caPath := filepath.Join(tmpDir, "certs", "example.com-ca.pem")
	configPath := filepath.Join(tmpDir, "config.yaml")

	config := fmt.Sprintf(`base_url: %q
disable_certificate_validation: false
certificates:
  - name: "example.com"
    cert_secret: "cert-secret"
    cert_path: %q
    key_secret: "key-secret"
    key_path: %q
    ca_path: %q
    action: %q
`, server.URL, certPath, keyPath, caPath, actionScript)
	writeFile(t, configPath, config)

	runBinary(t, binaryPath, "-c", configPath)

	assertFileContents(t, certPath, "cert-body")
	assertFileContents(t, keyPath, "key-body")
	assertFileContents(t, caPath, "ca-body")
	assertActionCount(t, actionMarker, 1)

	runBinary(t, binaryPath, "-c", configPath)
	assertActionCount(t, actionMarker, 1)
}

func TestCLI_RejectsInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "invalid-config.yaml")

	writeFile(t, configPath, `certificates:
  - name: "example.com"
`)

	cmd := exec.Command(binaryPath, "-c", configPath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected invalid config to fail, got success with output: %s", string(output))
	}
}

func TestCLI_DryRunDoesNotWriteFilesOrRunAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case constants.CertificateApiPath + "example.com":
			_, _ = w.Write([]byte("cert-body"))
		case constants.KeyApiPath + "example.com":
			_, _ = w.Write([]byte("key-body"))
		case constants.CaCertificateApiPath + "example.com":
			_, _ = w.Write([]byte("ca-body"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	actionMarker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", actionMarker))

	certPath := filepath.Join(tmpDir, "certs", "example.com-cert.pem")
	keyPath := filepath.Join(tmpDir, "certs", "example.com-key.pem")
	caPath := filepath.Join(tmpDir, "certs", "example.com-ca.pem")
	configPath := filepath.Join(tmpDir, "config.yaml")

	config := fmt.Sprintf(`base_url: %q
disable_certificate_validation: false
certificates:
  - name: "example.com"
    cert_secret: "cert-secret"
    cert_path: %q
    key_secret: "key-secret"
    key_path: %q
    ca_path: %q
    action: %q
`, server.URL, certPath, keyPath, caPath, actionScript)
	writeFile(t, configPath, config)

	runBinary(t, binaryPath, "--dry-run", "-c", configPath)

	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("expected certificate file to be absent after dry-run, got err=%v", err)
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected key file to be absent after dry-run, got err=%v", err)
	}

	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Fatalf("expected CA file to be absent after dry-run, got err=%v", err)
	}

	if _, err := os.Stat(actionMarker); !os.IsNotExist(err) {
		t.Fatalf("expected action to be skipped during dry-run, got err=%v", err)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine current file path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	binaryPath := filepath.Join(t.TempDir(), "certwarden-deploy")

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/certwarden-deploy")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, string(output))
	}

	return binaryPath
}

func runBinary(t *testing.T, binaryPath string, args ...string) {
	t.Helper()

	runBinaryExpectingExitCode(t, 0, binaryPath, args...)
}

// runBinaryExpectingExitCode runs the binary and asserts its exit code.
//
// The exit code is part of the public contract of the tool, so it is asserted
// against plain numbers on purpose: the test must fail if the constants behind
// them ever move.
func runBinaryExpectingExitCode(t *testing.T, wantCode int, binaryPath string, args ...string) string {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	output, err := cmd.CombinedOutput()

	gotCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("binary execution failed: %v\n%s", err, string(output))
		}
		gotCode = exitErr.ExitCode()
	}

	if gotCode != wantCode {
		t.Fatalf("unexpected exit code: got %d want %d\n%s", gotCode, wantCode, string(output))
	}

	return string(output)
}

// e2eCert describes one certificate entry for the generated config file.
type e2eCert struct {
	name string

	// action is the string form of the action, rendered as a scalar.
	action string

	// actionArgs is the list form of the action, rendered as a sequence. It
	// takes precedence over action when both are set.
	actionArgs []string

	// runOn is rendered as run_on when non-empty, and omitted otherwise so the
	// default policy is exercised.
	runOn string

	certPath string
	keyPath  string
	caPath   string
}

func newE2ECert(tmpDir string, name string) e2eCert {
	return e2eCert{
		name:     name,
		certPath: filepath.Join(tmpDir, "certs", name+"-cert.pem"),
		keyPath:  filepath.Join(tmpDir, "certs", name+"-key.pem"),
		caPath:   filepath.Join(tmpDir, "certs", name+"-ca.pem"),
	}
}

// startCertServer serves certificate data for every requested name and answers
// with 401 for the names listed in unauthorized.
func startCertServer(t *testing.T, unauthorized ...string) *httptest.Server {
	t.Helper()

	denied := make(map[string]bool, len(unauthorized))
	for _, name := range unauthorized {
		denied[name] = true
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := path.Base(r.URL.Path)
		if denied[name] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, constants.CertificateApiPath):
			_, _ = w.Write([]byte("cert-body-" + name))
		case strings.HasPrefix(r.URL.Path, constants.KeyApiPath):
			_, _ = w.Write([]byte("key-body-" + name))
		case strings.HasPrefix(r.URL.Path, constants.CaCertificateApiPath):
			_, _ = w.Write([]byte("ca-body-" + name))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func writeE2EConfig(t *testing.T, configPath string, baseURL string, certs ...e2eCert) {
	t.Helper()

	writeE2EConfigWithActions(t, configPath, baseURL, "", certs...)
}

// writeE2EConfigWithActions renders a config file, optionally with a top-level
// actions block. An empty actionsBlock omits the key entirely, which is what
// exercises the default.
func writeE2EConfigWithActions(t *testing.T, configPath string, baseURL string, actionsBlock string, certs ...e2eCert) {
	t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "base_url: %q\ndisable_certificate_validation: false\n", baseURL)

	if actionsBlock != "" {
		b.WriteString(actionsBlock)
	}

	b.WriteString("certificates:\n")

	for _, cert := range certs {
		fmt.Fprintf(&b, `  - name: %q
    cert_secret: "cert-secret"
    cert_path: %q
    key_secret: "key-secret"
    key_path: %q
    ca_path: %q
`, cert.name, cert.certPath, cert.keyPath, cert.caPath)

		// An empty action must be omitted entirely: an action key that is
		// present but blank is a config error, not "no action".
		switch {
		case len(cert.actionArgs) > 0:
			b.WriteString("    action:\n")
			for _, arg := range cert.actionArgs {
				fmt.Fprintf(&b, "      - %q\n", arg)
			}
		case cert.action != "":
			fmt.Fprintf(&b, "    action: %q\n", cert.action)
		}

		if cert.runOn != "" {
			fmt.Fprintf(&b, "    run_on: %q\n", cert.runOn)
		}
	}

	writeFile(t, configPath, b.String())
}

func writeFailingAction(t *testing.T, tmpDir string, name string) string {
	t.Helper()

	script := filepath.Join(tmpDir, name+"-failing-action.sh")
	writeExecutableFile(t, script, "#!/bin/sh\nexit 7\n")

	return script
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file %s: %v", path, err)
	}
}

func writeExecutableFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("failed to write executable file %s: %v", path, err)
	}
}

func assertFileContents(t *testing.T, path string, want string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}

	if string(data) != want {
		t.Fatalf("unexpected contents for %s: got %q want %q", path, string(data), want)
	}
}

func assertActionCount(t *testing.T, path string, want int) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read action marker %s: %v", path, err)
	}

	got := len(strings.Fields(string(data)))
	if got != want {
		t.Fatalf("unexpected action count: got %d want %d", got, want)
	}
}

func TestCLI_ExitsZeroWhenEverythingSucceeds(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	actionMarker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", actionMarker))

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = actionScript

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)

	assertFileContents(t, cert.certPath, "cert-body-example.com")
	assertActionCount(t, actionMarker, 1)
}

func TestCLI_ExitsTwoWhenCertificateRolloutFails(t *testing.T) {
	server := startCertServer(t, "example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, newE2ECert(tmpDir, "example.com"))

	runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)
}

func TestCLI_ExitsThreeWhenOnlyActionFails(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = writeFailingAction(t, tmpDir, "example.com")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runBinaryExpectingExitCode(t, 3, binaryPath, "-c", configPath)

	// The certificate itself was deployed just fine, only the action broke.
	assertFileContents(t, cert.certPath, "cert-body-example.com")
}

func TestCLI_CertificateFailureOutranksActionFailure(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	broken := newE2ECert(tmpDir, "broken.example.com")
	working := newE2ECert(tmpDir, "working.example.com")
	working.action = writeFailingAction(t, tmpDir, "working.example.com")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, broken, working)

	runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)
}

// A single broken certificate must never keep the other certificates from being
// deployed. This is the regression guard for the "record, do not abort"
// behaviour of HandleCertificates.
func TestCLI_ContinuesProcessingAfterFailingCertificate(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	actionMarker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", actionMarker))

	broken := newE2ECert(tmpDir, "broken.example.com")
	healthy := newE2ECert(tmpDir, "healthy.example.com")
	healthy.action = actionScript

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, broken, healthy)

	runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)

	if _, err := os.Stat(broken.certPath); !os.IsNotExist(err) {
		t.Fatalf("expected broken certificate to be absent, got err=%v", err)
	}

	assertFileContents(t, healthy.certPath, "cert-body-healthy.example.com")
	assertFileContents(t, healthy.keyPath, "key-body-healthy.example.com")
	assertFileContents(t, healthy.caPath, "ca-body-healthy.example.com")
	assertActionCount(t, actionMarker, 1)
}

func TestCLI_ForceDoesNotMaskCertificateFailure(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	broken := newE2ECert(tmpDir, "broken.example.com")
	healthy := newE2ECert(tmpDir, "healthy.example.com")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, broken, healthy)

	runBinaryExpectingExitCode(t, 2, binaryPath, "--force", "-c", configPath)

	assertFileContents(t, healthy.certPath, "cert-body-healthy.example.com")
}

// A fetch failure during --dry-run is not hypothetical: the request really was
// sent and really did fail. Only the write and the action are simulated, so the
// run still reports the certificate failure with exit code 2.
func TestCLI_DryRunExitsTwoOnFetchFailure(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	broken := newE2ECert(tmpDir, "broken.example.com")
	writeE2EConfig(t, configPath, server.URL, broken)

	runBinaryExpectingExitCode(t, 2, binaryPath, "--dry-run", "-c", configPath)

	if _, err := os.Stat(broken.certPath); !os.IsNotExist(err) {
		t.Fatalf("expected no file to be written during dry-run, got err=%v", err)
	}
}

// TestCLI_FailingKeyLeavesOldCertificateOnDisk is the end-to-end guard for #28.
//
// A certificate is only usable next to the key it was issued for, so a run that
// cannot fetch the key must leave the pair on disk exactly as it found it. The
// old behaviour deployed the certificate first and bailed out on the key, which
// left a mismatched pair that only surfaced on the next unrelated restart of
// the TLS server.
func TestCLI_FailingKeyLeavesOldCertificateOnDisk(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, constants.KeyApiPath) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("new-body-" + path.Base(r.URL.Path)))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	cert := newE2ECert(tmpDir, "example.com")
	certDir := filepath.Dir(cert.certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("failed to create certificate directory: %v", err)
	}

	writeFile(t, cert.certPath, "old-cert-body")
	writeFile(t, cert.keyPath, "old-key-body")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)

	assertFileContents(t, cert.certPath, "old-cert-body")
	assertFileContents(t, cert.keyPath, "old-key-body")

	if _, err := os.Stat(cert.caPath); !os.IsNotExist(err) {
		t.Fatalf("expected CA to not be deployed, got err=%v", err)
	}

	// the aborted rollout must not litter the target directory either
	leftovers, err := filepath.Glob(filepath.Join(certDir, ".certwarden-deploy-*"))
	if err != nil {
		t.Fatalf("failed to glob for temporary files: %v", err)
	}

	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind in %s: %v", certDir, leftovers)
	}
}

// TestCLI_RunsShellFormAndListFormActions drives both action forms end to end,
// through the YAML parser and the real binary.
func TestCLI_RunsShellFormAndListFormActions(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	marker := filepath.Join(tmpDir, "actions.log")

	// string form: a && chain with redirects, none of which survive being
	// split on whitespace and exec'd directly
	shellCert := newE2ECert(tmpDir, "shell.example.com")
	shellCert.action = "printf 'shell cert renewed\\n' >> " + marker +
		" && printf 'chained\\n' >> " + marker

	// list form: arguments are handed to the binary untouched, so a space and
	// an && stay data instead of turning into syntax
	listScript := filepath.Join(tmpDir, "list-action.sh")
	writeExecutableFile(t, listScript, fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" >> %q\n", marker))

	listCert := newE2ECert(tmpDir, "list.example.com")
	listCert.actionArgs = []string{listScript, "cert renewed", "&&"}

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, shellCert, listCert)

	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)

	assertFileContents(t, marker, "shell cert renewed\nchained\ncert renewed\n&&\n")
}

// TestCLI_RejectsBlankAction pins that an action key that is present but empty
// is a config error rather than a silent no-op.
func TestCLI_RejectsBlankAction(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "config.yaml")

	cert := newE2ECert(tmpDir, "example.com")
	writeFile(t, configPath, fmt.Sprintf(`base_url: %q
certificates:
  - name: %q
    cert_secret: "cert-secret"
    cert_path: %q
    action: "   "
`, server.URL, cert.name, cert.certPath))

	output := runBinaryExpectingExitCode(t, 1, binaryPath, "-c", configPath)

	if !strings.Contains(output, "Field 'action' for certificate example.com cannot be blank!") {
		t.Fatalf("expected a blank-action validation error, got:\n%s", output)
	}
}

// TestCLI_RunOnChangedSkipsFirstDeployment drives run_on through the YAML
// parser: on the first run the file is created, which run_on: changed must not
// treat as a change. Only the second, differing rollout fires the action.
func TestCLI_RunOnChangedSkipsFirstDeployment(t *testing.T) {
	body := "cert-body-v1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	marker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", marker))

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = actionScript
	cert.runOn = "changed"

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)
	assertFileContents(t, cert.certPath, body)

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected run_on: changed not to fire on a first deployment, got err=%v", err)
	}

	// nothing moved, still no action
	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected run_on: changed not to fire on an unchanged run, got err=%v", err)
	}

	// now the content really changes
	body = "cert-body-v2"
	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)
	assertFileContents(t, cert.certPath, body)
	assertActionCount(t, marker, 1)
}

// TestCLI_RunOnAllRunsWithoutAnyChange covers the opposite end of the policy
// table: run_on: all fires even when nothing was written.
func TestCLI_RunOnAllRunsWithoutAnyChange(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	marker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", marker))

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = actionScript
	cert.runOn = "all"

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)
	assertActionCount(t, marker, 1)

	// second run changes nothing on disk, the action still runs
	runBinaryExpectingExitCode(t, 0, binaryPath, "-c", configPath)
	assertActionCount(t, marker, 2)
}

func TestCLI_RejectsUnknownRunOn(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	cert := newE2ECert(tmpDir, "example.com")
	cert.runOn = "on_change"

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	output := runBinaryExpectingExitCode(t, 1, binaryPath, "-c", configPath)

	if !strings.Contains(output, "Field 'run_on' for certificate example.com must be one of") {
		t.Fatalf("expected an unknown run_on validation error, got:\n%s", output)
	}

	if _, err := os.Stat(cert.certPath); !os.IsNotExist(err) {
		t.Fatalf("expected validation to stop the run before deploying, got err=%v", err)
	}
}

// TestCLI_ActionsToggle drives #46 end to end: files must deploy in every
// case, only the action is suppressed, and a suppressed action never turns a
// green run red.
func TestCLI_ActionsToggle(t *testing.T) {
	tests := []struct {
		name         string
		actionsBlock string
		args         []string
		wantAction   bool
	}{
		{
			name:       "default is on",
			wantAction: true,
		},
		{
			name:         "config on",
			actionsBlock: "actions:\n  enabled: true\n",
			wantAction:   true,
		},
		{
			name:         "config off",
			actionsBlock: "actions:\n  enabled: false\n",
			wantAction:   false,
		},
		{
			name:       "no-actions flag",
			args:       []string{"--no-actions"},
			wantAction: false,
		},
		{
			name:         "flag overrides config on",
			actionsBlock: "actions:\n  enabled: true\n",
			args:         []string{"--no-actions"},
			wantAction:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := startCertServer(t)

			tmpDir := t.TempDir()
			binaryPath := buildBinary(t)
			marker := filepath.Join(tmpDir, "action.log")
			actionScript := filepath.Join(tmpDir, "post-deploy.sh")
			writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", marker))

			cert := newE2ECert(tmpDir, "example.com")
			cert.action = actionScript

			configPath := filepath.Join(tmpDir, "config.yaml")
			writeE2EConfigWithActions(t, configPath, server.URL, tc.actionsBlock, cert)

			args := append([]string{"-c", configPath}, tc.args...)
			output := runBinaryExpectingExitCode(t, 0, binaryPath, args...)

			// The whole point of #46: deploy the files either way.
			assertFileContents(t, cert.certPath, "cert-body-example.com")
			assertFileContents(t, cert.keyPath, "key-body-example.com")
			assertFileContents(t, cert.caPath, "ca-body-example.com")

			if tc.wantAction {
				assertActionCount(t, marker, 1)
				return
			}

			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("expected the action to be suppressed, got err=%v", err)
			}

			if !strings.Contains(output, "Actions are disabled") || !strings.Contains(output, actionScript) {
				t.Fatalf("expected the skipped command to be logged, got:\n%s", output)
			}
		})
	}
}

// TestCLI_SuppressedActionDoesNotExitThree pins that switching actions off
// cannot produce an action failure, even for an action that always fails.
func TestCLI_SuppressedActionDoesNotExitThree(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = writeFailingAction(t, tmpDir, "example.com")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	// sanity: this very config exits 3 while actions are on
	runBinaryExpectingExitCode(t, 3, binaryPath, "-c", configPath)

	// and is green with them off, while still deploying
	os.Remove(cert.certPath)
	runBinaryExpectingExitCode(t, 0, binaryPath, "--no-actions", "-c", configPath)
	assertFileContents(t, cert.certPath, "cert-body-example.com")
}

// TestCLI_SummaryReportsMixedRun checks the record an operator sees at the end
// of a real run with a bit of everything in it.
func TestCLI_SummaryReportsMixedRun(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)

	broken := newE2ECert(tmpDir, "broken.example.com")

	unchanged := newE2ECert(tmpDir, "unchanged.example.com")
	fresh := newE2ECert(tmpDir, "fresh.example.com")

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, broken, unchanged, fresh)

	// first run deploys unchanged.example.com and fresh.example.com
	runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)

	// wipe one of them so the second run has a new one and an unchanged one
	for _, path := range []string{fresh.certPath, fresh.keyPath, fresh.caPath} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("failed to remove %s: %v", path, err)
		}
	}

	output := runBinaryExpectingExitCode(t, 2, binaryPath, "-c", configPath)

	summary := findOutputLine(t, output, "run summary")
	for _, want := range []string{
		"level=INFO",
		"new=1",
		"changed=0",
		"unchanged=1",
		"failed=1",
		"action_failed=0",
		"action_skipped=0",
		"total=3",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected %q in the summary, got: %s\nfull output:\n%s", want, summary, output)
		}
	}

	failure := findOutputLine(t, output, "msg=\"certificate failed\"")
	for _, want := range []string{"level=ERROR", "name=broken.example.com", "file-type=certificate"} {
		if !strings.Contains(failure, want) {
			t.Fatalf("expected %q in the failure line, got: %s", want, failure)
		}
	}
}

// TestCLI_QuietRunIsSilentOnSuccess and its failing counterpart below are the
// --quiet contract: nothing at all when the run worked, the summary and the
// failures when it did not.
func TestCLI_QuietRunIsSilentOnSuccess(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	marker := filepath.Join(tmpDir, "action.log")
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, fmt.Sprintf("#!/bin/sh\nprintf 'run\\n' >> %q\n", marker))

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = actionScript

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	output := runBinaryExpectingExitCode(t, 0, binaryPath, "--quiet", "-c", configPath)

	if strings.TrimSpace(output) != "" {
		t.Fatalf("expected a successful quiet run to print nothing, got:\n%s", output)
	}

	// it really did run, it was just quiet about it
	assertFileContents(t, cert.certPath, "cert-body-example.com")
	assertActionCount(t, marker, 1)
}

func TestCLI_QuietRunReportsFailures(t *testing.T) {
	server := startCertServer(t, "broken.example.com")

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, newE2ECert(tmpDir, "broken.example.com"))

	output := runBinaryExpectingExitCode(t, 2, binaryPath, "--quiet", "-c", configPath)

	// the summary must survive --quiet when the run failed
	summary := findOutputLine(t, output, "run summary")
	if !strings.Contains(summary, "level=ERROR") {
		t.Fatalf("expected the summary at ERROR under --quiet, got: %s", summary)
	}

	for _, want := range []string{"failed=1", "total=1"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected %q in the quiet summary, got: %s", want, summary)
		}
	}

	failure := findOutputLine(t, output, "msg=\"certificate failed\"")
	if !strings.Contains(failure, "name=broken.example.com") {
		t.Fatalf("expected the failing certificate to be named, got: %s", failure)
	}
}

func TestCLI_DryRunSummaryIsMarked(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, newE2ECert(tmpDir, "example.com"))

	output := runBinaryExpectingExitCode(t, 0, binaryPath, "--dry-run", "-c", configPath)

	summary := findOutputLine(t, output, "run summary")
	if !strings.Contains(summary, "DRY-RUN: run summary") {
		t.Fatalf("expected the dry-run summary to be marked, got: %s", summary)
	}

	if !strings.Contains(summary, "new=1") || !strings.Contains(summary, "total=1") {
		t.Fatalf("expected a dry run to still report what it would do, got: %s", summary)
	}
}

// TestCLI_SummaryReportsSkippedActions ties #46 to the summary: a run with
// actions off must say so rather than look like a run with nothing to do.
func TestCLI_SummaryReportsSkippedActions(t *testing.T) {
	server := startCertServer(t)

	tmpDir := t.TempDir()
	binaryPath := buildBinary(t)
	actionScript := filepath.Join(tmpDir, "post-deploy.sh")
	writeExecutableFile(t, actionScript, "#!/bin/sh\nexit 0\n")

	cert := newE2ECert(tmpDir, "example.com")
	cert.action = actionScript

	configPath := filepath.Join(tmpDir, "config.yaml")
	writeE2EConfig(t, configPath, server.URL, cert)

	output := runBinaryExpectingExitCode(t, 0, binaryPath, "--no-actions", "-c", configPath)

	summary := findOutputLine(t, output, "run summary")
	if !strings.Contains(summary, "action_skipped=1") || !strings.Contains(summary, "action_failed=0") {
		t.Fatalf("expected the skipped action to be counted, got: %s", summary)
	}
}

// findOutputLine returns the first line of binary output containing substr.
func findOutputLine(t *testing.T, output string, substr string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}

	t.Fatalf("no output line containing %q found in:\n%s", substr, output)
	return ""
}

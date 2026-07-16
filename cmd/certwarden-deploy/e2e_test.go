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
	name     string
	action   string
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

	var b strings.Builder
	fmt.Fprintf(&b, "base_url: %q\ndisable_certificate_validation: false\ncertificates:\n", baseURL)

	for _, cert := range certs {
		fmt.Fprintf(&b, `  - name: %q
    cert_secret: "cert-secret"
    cert_path: %q
    key_secret: "key-secret"
    key_path: %q
    ca_path: %q
    action: %q
`, cert.name, cert.certPath, cert.keyPath, cert.caPath, cert.action)
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

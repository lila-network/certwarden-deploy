package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"code.lila.network/lila-network/certwarden-deploy/internal/constants"
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

	cmd := exec.Command(binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("binary execution failed: %v\n%s", err, string(output))
	}
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

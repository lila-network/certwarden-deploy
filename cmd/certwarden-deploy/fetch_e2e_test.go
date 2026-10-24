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
	"strings"
	"sync"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
)

// keyMaterial stands in for a private key in the fetch tests.
//
// It is deliberately a distinctive string: several tests assert that it does
// not appear in the log, and a body like "key-body" would be too easy to match
// by accident.
const keyMaterial = "-----BEGIN PRIVATE KEY-----\nMIIsecretkeymaterialdonotlog\n-----END PRIVATE KEY-----\n"

// fetchServer records what the binary asked for, so a test can assert on the
// request rather than only on the response.
type fetchServer struct {
	*httptest.Server

	mu sync.Mutex

	// requests holds the path of every request, in order
	requests []string

	// apiKeys holds the X-API-Key of every request, in order
	apiKeys []string

	// formats holds the format query parameter of every request, in order
	formats []string
}

func (s *fetchServer) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests = append(s.requests, r.URL.Path)
	s.apiKeys = append(s.apiKeys, r.Header.Get(constants.ApiKeyHeaderName))
	s.formats = append(s.formats, r.URL.Query().Get("format"))
}

func (s *fetchServer) snapshot() ([]string, []string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.requests...),
		append([]string(nil), s.apiKeys...),
		append([]string(nil), s.formats...)
}

// startFetchServer serves the download endpoints for the fetch tests.
//
// keys maps a certificate name to the API key that is accepted for it. A name
// that is not in the map is served to anyone, a name whose key does not match
// is answered with 401.
func startFetchServer(t *testing.T, keys map[string]string) *fetchServer {
	t.Helper()

	server := &fetchServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.record(r)

		name := path.Base(r.URL.Path)
		if want, ok := keys[name]; ok && r.Header.Get(constants.ApiKeyHeaderName) != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, constants.CertificateApiPath):
			_, _ = w.Write([]byte("cert-body-" + name))
		case strings.HasPrefix(r.URL.Path, constants.KeyApiPath):
			_, _ = w.Write([]byte(keyMaterial))
		case strings.HasPrefix(r.URL.Path, constants.CaCertificateApiPath):
			_, _ = w.Write([]byte("ca-body-" + name))
		case strings.HasPrefix(r.URL.Path, constants.PrivateCertApiPath):
			_, _ = w.Write([]byte("privatecert-body-" + name))
		case strings.HasPrefix(r.URL.Path, constants.PrivateCertChainApiPath):
			_, _ = w.Write([]byte("privatecertchain-body-" + name))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

// runSplit runs the binary and returns stdout and stderr separately.
//
// The fetch subcommands only make sense if the two streams are separate, so the
// tests have to look at them separately too: CombinedOutput would happily pass
// a build in which every log record lands in the middle of the material.
func runSplit(t *testing.T, wantCode int, binaryPath string, args ...string) (string, string) {
	t.Helper()

	return runSplitInDir(t, wantCode, "", binaryPath, args...)
}

// runSplitInDir is runSplit with an explicit working directory, for the tests
// that depend on config file discovery.
func runSplitInDir(t *testing.T, wantCode int, dir string, binaryPath string, args ...string) (string, string) {
	t.Helper()

	var stdout, stderr strings.Builder

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	gotCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("binary execution failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
		}
		gotCode = exitErr.ExitCode()
	}

	if gotCode != wantCode {
		t.Fatalf("unexpected exit code: got %d want %d\nstdout: %s\nstderr: %s", gotCode, wantCode, stdout.String(), stderr.String())
	}

	return stdout.String(), stderr.String()
}

// writeFetchConfig renders a config file for a single certificate that carries
// no paths at all: fetch must not need them.
func writeFetchConfig(t *testing.T, configPath string, baseURL string, name string, certSecret string, keySecret string) {
	t.Helper()

	writeFile(t, configPath, fmt.Sprintf(`base_url: %q
certificates:
  - name: %q
    cert_secret: %q
    cert_path: "/dev/null"
    key_secret: %q
`, baseURL, name, certSecret, keySecret))
}

func TestCLI_FetchWritesEachArtefactToStdout(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	tests := []struct {
		subcommand string
		wantPath   string
		wantBody   string
	}{
		{"certificate", constants.CertificateApiPath + "example.com", "cert-body-example.com"},
		{"key", constants.KeyApiPath + "example.com", keyMaterial},
		{"ca", constants.CaCertificateApiPath + "example.com", "ca-body-example.com"},
		{"privatecert", constants.PrivateCertApiPath + "example.com", "privatecert-body-example.com"},
		{"privatecertchain", constants.PrivateCertChainApiPath + "example.com", "privatecertchain-body-example.com"},
	}

	for _, test := range tests {
		t.Run(test.subcommand, func(t *testing.T) {
			stdout, _ := runSplit(t, 0, binaryPath, "-c", configPath, "fetch", test.subcommand, "example.com")

			if stdout != test.wantBody {
				t.Errorf("unexpected stdout: got %q want %q", stdout, test.wantBody)
			}

			requests, _, _ := server.snapshot()
			if len(requests) == 0 || requests[len(requests)-1] != test.wantPath {
				t.Errorf("unexpected request path: got %q want %q", requests[len(requests)-1], test.wantPath)
			}
		})
	}
}

func TestCLI_FetchOutputWritesFileAtomically(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	// a directory that does not exist yet, so the write path has to create it
	outPath := filepath.Join(tmpDir, "out", "example.com.pem")

	stdout, _ := runSplit(t, 0, binaryPath, "-c", configPath, "fetch", "certificate", "example.com", "--output", outPath)

	if stdout != "" {
		t.Errorf("expected nothing on stdout when --output names a file, got %q", stdout)
	}

	assertFileContents(t, outPath, "cert-body-example.com")
	assertNoStagedFiles(t, filepath.Dir(outPath))
}

// assertNoStagedFiles fails when the atomic write path left a temporary file
// behind, which is what would happen if fetch bypassed the rename.
func assertNoStagedFiles(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read directory %s: %v", dir, err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".certwarden-deploy-") {
			t.Errorf("temporary file %s was left behind in %s", entry.Name(), dir)
		}
	}
}

// TestCLI_FetchWorksWithoutAnyConfigFile is the whole point of --base-url: the
// machine you debug an API key on does not necessarily have a config file.
func TestCLI_FetchWorksWithoutAnyConfigFile(t *testing.T) {
	server := startFetchServer(t, map[string]string{"example.com": "flag-key"})
	binaryPath := buildBinary(t)

	// an empty working directory and an empty XDG dir, so discovery finds
	// nothing at all
	workDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	stdout, _ := runSplitInDir(
		t, 0, workDir, binaryPath,
		"fetch", "certificate", "example.com", "--base-url", server.URL, "--api-key", "flag-key",
	)

	if stdout != "cert-body-example.com" {
		t.Errorf("unexpected stdout: got %q want %q", stdout, "cert-body-example.com")
	}
}

// TestCLI_FetchResolvesSecretFromConfigByName makes sure the certificate entry
// is matched by name, not simply taken as "the first one".
func TestCLI_FetchResolvesSecretFromConfigByName(t *testing.T) {
	server := startFetchServer(t, map[string]string{
		"first.example.com":  "first-secret",
		"second.example.com": "second-secret",
	})
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFile(t, configPath, fmt.Sprintf(`base_url: %q
certificates:
  - name: "first.example.com"
    cert_secret: "first-secret"
    cert_path: "/dev/null"
    key_secret: "first-key-secret"
  - name: "second.example.com"
    cert_secret: "second-secret"
    cert_path: "/dev/null"
    key_secret: "second-key-secret"
`, server.URL))

	stdout, _ := runSplit(t, 0, binaryPath, "-c", configPath, "fetch", "certificate", "second.example.com")

	if stdout != "cert-body-second.example.com" {
		t.Errorf("unexpected stdout: got %q want %q", stdout, "cert-body-second.example.com")
	}

	_, apiKeys, _ := server.snapshot()
	if len(apiKeys) != 1 || apiKeys[0] != "second-secret" {
		t.Errorf("unexpected API keys seen by the server: %v", apiKeys)
	}
}

// TestCLI_FetchResolvesSecretFromEnvironment covers the last link of the
// precedence chain, which is what makes a config-less fetch usable without
// putting the key into the shell history.
func TestCLI_FetchResolvesSecretFromEnvironment(t *testing.T) {
	server := startFetchServer(t, map[string]string{"example.com": "env-key"})
	binaryPath := buildBinary(t)

	workDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(configuration.APIKeyEnvVar, "env-key")

	stdout, _ := runSplitInDir(
		t, 0, workDir, binaryPath,
		"fetch", "certificate", "example.com", "--base-url", server.URL,
	)

	if stdout != "cert-body-example.com" {
		t.Errorf("unexpected stdout: got %q want %q", stdout, "cert-body-example.com")
	}
}

func TestCLI_FetchExitsNonZeroOnFetchFailure(t *testing.T) {
	server := startFetchServer(t, map[string]string{"example.com": "the-right-key"})
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "the-wrong-key", "key-secret")

	stdout, stderr := runSplit(t, 1, binaryPath, "-c", configPath, "fetch", "certificate", "example.com")

	if stdout != "" {
		t.Errorf("expected nothing on stdout for a failed fetch, got %q", stdout)
	}

	if !strings.Contains(stderr, "API-Key invalid") {
		t.Errorf("expected the failure to be reported on stderr, got: %s", stderr)
	}
}

// TestCLI_FetchFailureWritesNoOutputFile makes sure a failed fetch does not
// clobber the file the user pointed --output at.
func TestCLI_FetchFailureWritesNoOutputFile(t *testing.T) {
	server := startFetchServer(t, map[string]string{"example.com": "the-right-key"})
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "the-wrong-key", "key-secret")

	outPath := filepath.Join(tmpDir, "existing.pem")
	writeFile(t, outPath, "previous-content")

	runSplit(t, 1, binaryPath, "-c", configPath, "fetch", "certificate", "example.com", "--output", outPath)

	assertFileContents(t, outPath, "previous-content")
}

// TestCLI_FetchDoesNotLogKeyMaterial is the guard for the one thing this
// command must never do: a private key printed to stdout must not also end up
// in the journal.
func TestCLI_FetchDoesNotLogKeyMaterial(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	// --verbose, because a leak that only shows at debug level is still a leak
	stdout, stderr := runSplit(t, 0, binaryPath, "-v", "-c", configPath, "fetch", "key", "example.com")

	if stdout != keyMaterial {
		t.Fatalf("unexpected stdout: got %q want %q", stdout, keyMaterial)
	}

	for _, line := range strings.Split(keyMaterial, "\n") {
		if line == "" {
			continue
		}

		if strings.Contains(stderr, line) {
			t.Errorf("key material leaked into the log: %q appears in stderr:\n%s", line, stderr)
		}
	}

	// the secret used to fetch it must not be logged either
	if strings.Contains(stderr, "key-secret") {
		t.Errorf("the API key leaked into the log:\n%s", stderr)
	}
}

func TestCLI_FetchPrivateCertUsesCombinedSecret(t *testing.T) {
	server := startFetchServer(t, map[string]string{"example.com": "cert-secret.key-secret"})
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	for _, subcommand := range []string{"privatecert", "privatecertchain"} {
		t.Run(subcommand, func(t *testing.T) {
			runSplit(t, 0, binaryPath, "-c", configPath, "fetch", subcommand, "example.com")
		})
	}

	_, apiKeys, _ := server.snapshot()
	for _, key := range apiKeys {
		if key != "cert-secret.key-secret" {
			t.Errorf("unexpected API key: got %q want %q", key, "cert-secret.key-secret")
		}
	}
}

func TestCLI_FetchRequestsTheSelectedFormat(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	runSplit(t, 0, binaryPath, "-c", configPath, "fetch", "privatecert", "example.com", "--format", "pkcs12")

	_, _, formats := server.snapshot()
	if len(formats) != 1 || formats[0] != "pkcs12" {
		t.Fatalf("unexpected format query: %v", formats)
	}

	// pem is the server default and must stay unsent, exactly as in a rollout
	runSplit(t, 0, binaryPath, "-c", configPath, "fetch", "privatecert", "example.com", "--format", "pem")

	_, _, formats = server.snapshot()
	if formats[len(formats)-1] != "" {
		t.Fatalf("pem must not be sent as a query parameter, got %q", formats[len(formats)-1])
	}
}

func TestCLI_FetchRejectsUnknownFormat(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	runSplit(t, 1, binaryPath, "-c", configPath, "fetch", "privatecert", "example.com", "--format", "der")

	requests, _, _ := server.snapshot()
	if len(requests) != 0 {
		t.Fatalf("an unknown format must be rejected before any request, got %v", requests)
	}
}

// TestCLI_FetchDoesNotDoChangeDetection is the deliberate difference to the
// reference Python tool, whose one-off download prints "Certificate unchanged"
// and writes nothing.
//
// The file is rewritten even though its content is byte-identical, so the two
// writes are told apart by identity rather than by content: the atomic write
// path renames a fresh file over the target, so a second write is a second
// inode.
func TestCLI_FetchDoesNotDoChangeDetection(t *testing.T) {
	server := startFetchServer(t, nil)
	binaryPath := buildBinary(t)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeFetchConfig(t, configPath, server.URL, "example.com", "cert-secret", "key-secret")

	outPath := filepath.Join(tmpDir, "example.com.pem")

	_, firstStderr := runSplit(t, 0, binaryPath, "-v", "-c", configPath, "fetch", "certificate", "example.com", "--output", outPath)
	first, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("failed to stat %s: %v", outPath, err)
	}

	_, secondStderr := runSplit(t, 0, binaryPath, "-v", "-c", configPath, "fetch", "certificate", "example.com", "--output", outPath)
	second, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("failed to stat %s: %v", outPath, err)
	}

	assertFileContents(t, outPath, "cert-body-example.com")

	if os.SameFile(first, second) {
		t.Error("the second fetch did not write the file again, so something compared it to what was on disk")
	}

	for _, stderr := range []string{firstStderr, secondStderr} {
		if strings.Contains(stderr, "not changed") {
			t.Errorf("fetch reported change detection:\n%s", stderr)
		}
	}

	// both fetches really did hit the server
	requests, _, _ := server.snapshot()
	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d: %v", len(requests), requests)
	}
}

package certificates

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
)

func HandleCertificates(logger *slog.Logger, config *configuration.ConfigFileData) {
	for _, cert := range config.Certificates {
		certInfos := GenericCertificate{
			Name:     cert.Name,
			FilePath: cert.CertificatePath,
			Secret:   cert.CertificateSecret,
			Type:     CertificateFile,
		}

		keyInfos := GenericCertificate{
			Name:     cert.Name,
			FilePath: cert.KeyPath,
			Secret:   cert.KeySecret,
			Type:     KeyFile,
		}

		caInfos := GenericCertificate{
			Name:     cert.Name,
			FilePath: cert.CaPath,
			Secret:   cert.CertificateSecret,
			Type:     CaCertificateFile,
		}

		// Rollout Certificate
		certOnDiskChanged, err := certInfos.Rollout(logger, config.BaseURL, config.DisableCertificateValidation)
		if err != nil {
			logger.Error(
				"Failed to roll out Certificate", "path",
				certInfos.FilePath, "name", cert.Name, "error", err,
			)
			continue
		}

		// Rollout Key
		keyOnDiskChanged, err := keyInfos.Rollout(logger, config.BaseURL, config.DisableCertificateValidation)
		if err != nil {
			logger.Error(
				"Failed to roll out Key", "path",
				keyInfos.FilePath, "name", cert.Name, "error", err,
			)
			continue
		}

		caOnDiskChanged, err := caInfos.Rollout(logger, config.BaseURL, config.DisableCertificateValidation)
		if err != nil {
			logger.Error(
				"failed to roll out CA", "path",
				caInfos.FilePath, "name", cert.Name, "error", err,
			)
			continue
		}

		// if cert OR key changed OR --force
		if (certOnDiskChanged || keyOnDiskChanged || caOnDiskChanged) || configuration.Force {
			if configuration.DryRun {
				logger.Info("DRY-RUN: skipping post-rollout action", "name", cert.Name)
				continue
			}

			if configuration.Force {
				logger.Info("Forcing file system change due to --force", "name", cert.Name)
			}

			err = handleCertificateAction(cert.Action)
			if err != nil {
				logger.Error("Failed to execute post-rollout action", "name", cert.Name, "error", err)
			}
		}
	}
}

// Rollout handles getting the certificate/key data from the
// server and writing it to disk if the data differs.
//
// Returns error on error, true if certificate action needs to be executed, false if not
func (c *GenericCertificate) Rollout(logger *slog.Logger, baseUrl string, skipInsecure bool) (bool, error) {
	if c.FilePath == "" {
		logger.Info("File path is empty, skipping...", "file-type", c.Type)
		return false, nil
	}

	err := c.fetchFromServer(
		logger,
		baseUrl,
		skipInsecure,
	)
	if err != nil {
		return false, fmt.Errorf("failed to get certificate from server: %w", err)
	}

	fileNeedsRollout, err := c.needsRollout(logger)
	if err != nil {
		return false, fmt.Errorf("failed to check certificate on disk: %w", err)
	}

	if fileNeedsRollout || configuration.Force {
		if configuration.Force {
			logger.Info("Forcing file system change due to --force", "name", c.Name)
		}

		err = c.writeToDisk(logger)
		if err != nil {
			return false, fmt.Errorf("failed to handle certificate: %w", err)
		}

	}
	if fileNeedsRollout {
		logger.Info("New file deployed", "path", c.FilePath)
		return true, nil
	} else if configuration.Force {
		logger.Info("File deployed", "path", c.FilePath)
		return true, nil
	} else {
		logger.Info("File not changed, skipping...", "path", c.FilePath)
		return false, nil
	}
}

// readFromDisk reads file data from disk and populates the data []byte field.
//
// Returns error or nil on success
func (c *GenericCertificate) readFromDisk() error {
	filebytes, err := os.ReadFile(c.FilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		} else {
			return fmt.Errorf("failed to read file from disk: %w", err)
		}
	}

	c.diskBytes = filebytes
	return nil
}

// needsRollout checks the data []bytes against the data on disk.
//
// Returns true if file needs rollout, false if not
func (c *GenericCertificate) needsRollout(logger *slog.Logger) (bool, error) {
	err := c.readFromDisk()

	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		} else {
			return false, fmt.Errorf("failed to compare data to file on disk: %w", err)
		}
	}

	diskHash := sha256.Sum256(c.diskBytes)
	serverHash := sha256.Sum256(c.serverBytes)

	hashesAreDifferent := diskHash != serverHash
	if hashesAreDifferent {
		logger.Debug("File on disk differs from server source", "path", c.FilePath)
	} else {
		logger.Debug("File on disk is identical to server source", "path", c.FilePath)
	}

	return hashesAreDifferent, nil
}

// writeToDisk flushes the certificate data to disk.
//
// Returns error or nil on success.
func (c *GenericCertificate) writeToDisk(logger *slog.Logger) error {
	if configuration.DryRun {
		logger.Debug("DRY-RUN: writing data to file", "path", c.FilePath)
		return nil
	}

	dir := filepath.Dir(c.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	mode := fs.FileMode(0644)
	if stat, err := os.Stat(c.FilePath); err == nil {
		mode = stat.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to inspect file before writing: %w", err)
	}

	file, err := os.CreateTemp(dir, ".certwarden-deploy-*")
	if err != nil {
		return fmt.Errorf("failed to open temporary file for writing: %w", err)
	}

	tempPath := file.Name()
	cleanupTempFile := true
	defer func(l *slog.Logger) {
		if cleanupTempFile {
			if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				l.Error("failed to clean up temporary file", "path", tempPath, "error", removeErr)
			}
		}
	}(logger)

	if err := file.Chmod(mode); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("failed to close temporary file after chmod error", "path", tempPath, "error", closeErr)
		}
		return fmt.Errorf("failed to set temporary file permissions: %w", err)
	}

	w := bufio.NewWriter(file)

	if _, err := w.Write(c.serverBytes); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("failed to close temporary file after write error", "path", tempPath, "error", closeErr)
		}
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	if err = w.Flush(); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("failed to close temporary file after flush error", "path", tempPath, "error", closeErr)
		}
		return fmt.Errorf("failed to flush data to file: %w", err)
	}

	if err = file.Sync(); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("failed to close temporary file after sync error", "path", tempPath, "error", closeErr)
		}
		return fmt.Errorf("failed to sync data to file: %w", err)
	}

	if err = file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err = os.Rename(tempPath, c.FilePath); err != nil {
		return fmt.Errorf("failed to replace target file with temporary file: %w", err)
	}

	cleanupTempFile = false
	logger.Debug("Successfully wrote to file", "path", c.FilePath)
	return nil
}

// fetchFromServer fetches the cert/key data from the CertWarden server and
// fills the serverBytes field.
//
// Returns error or nil on success.
func (c *GenericCertificate) fetchFromServer(logger *slog.Logger, baseUrl string, skipInsecure bool) error {
	var apiPath string

	switch c.Type {
	case CertificateFile:
		apiPath = constants.CertificateApiPath
	case KeyFile:
		apiPath = constants.KeyApiPath
	case CaCertificateFile:
		apiPath = constants.CaCertificateApiPath
	default:
		return fmt.Errorf("unsupported file type: %v", c.Type)
	}

	url := baseUrl + apiPath + c.Name

	logger.Debug("Data request URL: "+url, "file-type", c.Type)
	var transport http.RoundTripper

	if skipInsecure {
		logger.Debug("Upstream Server TLS Certificate Validation is disabled")
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		logger.Debug("Upstream Server HTTP TLS Certificate Validation is enabled")
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to prepare to request data from server: %w", err)
	}

	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Add(constants.ApiKeyHeaderName, c.Secret)

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request data from server: %w", err)
	}

	defer func(l *slog.Logger) {
		if err := res.Body.Close(); err != nil {
			l.Error("failed to close http response body", "error", err)
		}
	}(logger)

	if res.StatusCode == http.StatusUnauthorized {
		body := errorBodyForLog(res)
		logger.Error(
			"API-Key for request is invalid, skipping certificate!",
			appendBodyArg([]any{"name", c.Name, "file-type", c.Type}, body)...,
		)
		if body == "" {
			return errors.New("API-Key invalid")
		}
		return fmt.Errorf("API-Key invalid: %v", body)
	} else if res.StatusCode != http.StatusOK {
		body := errorBodyForLog(res)
		logger.Error(
			"failed to get data from server",
			appendBodyArg([]any{"name", c.Name, "http-response", res.Status, "file-type", c.Type}, body)...,
		)
		if body == "" {
			return fmt.Errorf("got non-success error code from server: %v", res.Status)
		}
		return fmt.Errorf("got non-success error code from server: %v: %v", res.Status, body)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from server: %w", err)
	}

	c.serverBytes = bodyBytes
	return nil
}

// maxLoggedBodyBytes caps how much of an error response body is read for
// logging, so a verbose upstream error page cannot flood the log.
const maxLoggedBodyBytes = 4 << 10

// errorBodyForLog reads a bounded prefix of a response body and normalises it
// into a single-line string that can be attached to a log record or an error.
//
// It must only ever be called on non-success responses: on success the body is
// the certificate/key material itself and must never be logged.
//
// Returns an empty string if the body is empty, unreadable or not textual.
func errorBodyForLog(res *http.Response) string {
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}

	isTextual := strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" ||
		mediaType == "application/problem+json"
	if !isTextual {
		return ""
	}

	// read one byte past the cap so we can tell a full body from a truncated one
	bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, maxLoggedBodyBytes+1))
	if err != nil {
		return ""
	}

	truncated := len(bodyBytes) > maxLoggedBodyBytes
	if truncated {
		bodyBytes = bodyBytes[:maxLoggedBodyBytes]
	}

	// collapse newlines and whitespace runs so the log record stays on one line
	body := strings.Join(strings.Fields(string(bodyBytes)), " ")
	if body == "" {
		return ""
	}

	if truncated {
		body += " [truncated]"
	}

	return body
}

// appendBodyArg appends the server response body to a set of slog arguments,
// omitting it entirely when there is no usable body to report.
func appendBodyArg(args []any, body string) []any {
	if body == "" {
		return args
	}

	return append(args, "response-body", body)
}

// handleCertificateAction executes the user-defined action after successful certificate deployment
func handleCertificateAction(action string) error {
	sargs := strings.Fields(action)
	if len(sargs) == 0 {
		return nil
	}

	cmd := exec.Command(sargs[0], sargs[1:]...)
	err := cmd.Run()
	return err
}

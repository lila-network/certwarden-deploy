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
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"code.lila.network/lila-network/certwarden-deploy/internal/configuration"
	"code.lila.network/lila-network/certwarden-deploy/internal/constants"
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

	file, err := os.Create(c.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}

	defer func(l *slog.Logger) {
		if err := file.Close(); err != nil {
			l.Error("failed to close file", "path", c.FilePath, "error", err)
		}
	}(logger)

	w := bufio.NewWriter(file)

	if _, err := w.Write(c.serverBytes); err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	if err = w.Flush(); err != nil {
		return fmt.Errorf("failed to flush data to file: %w", err)
	}

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
		logger.Error("API-Key for request is invalid, skipping certificate!", "name", c.Name, "file-type", c.Type)
		return errors.New("API-Key invalid")
	} else if res.StatusCode != http.StatusOK {
		logger.Error("failed to get data from server", "name", c.Name, "http-response", res.Status, "file-type", c.Type)
		return fmt.Errorf("got non-success error code from server: %v", res.Status)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from server: %w", err)
	}

	c.serverBytes = bodyBytes
	return nil
}

// handleCertificateAction executes the user-defined action after successful certificate deployment
func handleCertificateAction(action string) error {
	if action == "" {
		return nil
	}

	sargs := strings.Split(action, " ")

	cmd := exec.Command(sargs[0], sargs[1:]...)
	err := cmd.Run()
	return err
}

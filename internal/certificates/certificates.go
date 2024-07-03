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
	"time"

	"code.lila.network/adoralaura/certwarden-deploy/internal/configuration"
	"code.lila.network/adoralaura/certwarden-deploy/internal/constants"
	"github.com/getsentry/sentry-go"
)

func HandleCertificates(logger *slog.Logger, config *configuration.ConfigFileData) {
	for _, cert := range config.Certificates {
		certBytes, err := getCertFromServer(
			logger,
			cert.Name,
			cert.ApiKey,
			config.BaseURL,
			config.DisableCertificateValidation,
		)
		if err != nil {
			logger.Error("Failed to get certificate from server", "cert-id", cert.Name, "error", err)
			return
		}

		certIsDifferent, err := checkCertIsDifferent(logger, cert.FilePath, certBytes)
		if err != nil {
			logger.Error("failed to handle certificate", "cert-id", cert.Name, "error", err)
			return
		}

		if certIsDifferent {
			err = updateCertOnFS(logger, cert.FilePath, certBytes)
			if err != nil {
				logger.Error("failed to handle certificate", "cert-id", cert.Name, "error", err)
				return
			}
		}

		logger.Info("Certificate updated successfully", "cert-id", cert.Name)
	}
}

func checkCertIsDifferent(logger *slog.Logger, path string, data []byte) (bool, error) {
	filebytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		} else {
			return false, fmt.Errorf("failed to read certificate file on disk: %w", err)
		}
	}

	existingSha256 := sha256.Sum256(filebytes)
	newSha256 := sha256.Sum256(data)

	sumsAreDifferent := existingSha256 != newSha256
	if sumsAreDifferent {
		logger.Debug("Certificate on file differs from the certificate on the server", "cert-path", path)
	} else {
		logger.Debug("Certificate on file is identical to the certificate on the server", "cert-path", path)
	}

	return sumsAreDifferent, nil
}

func updateCertOnFS(logger *slog.Logger, path string, data []byte) error {
	if configuration.DryRun {
		logger.Debug("DRY-RUN: writing certificate data to file", "cert-path", path)
		return nil
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to open certificate for writing: %w", err)
	}

	defer func(l *slog.Logger) {
		if err := file.Close(); err != nil {
			l.Error("failed to close file", "file-path", path, "error", err)
		}
	}(logger)

	w := bufio.NewWriter(file)

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write certificate data to file: %w", err)
	}

	if err = w.Flush(); err != nil {
		return fmt.Errorf("failed to flush certificate data to file: %w", err)
	}

	logger.Debug("wrote certificate to file", "file-path", path)
	return nil
}

func getCertFromServer(logger *slog.Logger, certName string, certKey string, baseUrl string, skipInsecure bool) ([]byte, error) {
	url := baseUrl + constants.CertificateApiPath + certName
	logger.Debug("Certificate request URL: " + url)
	var transport http.RoundTripper

	if skipInsecure {
		logger.Debug("TLS Certificate Validation is disabled")
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		logger.Debug("TLS Certificate Validation is enabled")
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to prepare to request certificate from server: %w", err)
	}

	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Add(constants.ApiKeyHeaderName, certKey)

	res, err := client.Do(req)
	if err != nil {
		e := fmt.Errorf("failed to request certificate from server: %w", err)
		sentry.CaptureException(e)
		return []byte{}, e
	}

	defer func(l *slog.Logger) {
		if err := res.Body.Close(); err != nil {
			l.Error("failed to close http response body", "error", err)
		}
	}(logger)

	if res.StatusCode == http.StatusUnauthorized {
		logger.Error("API-Key for Certificate is invalid, skipping certificate!", "cert-id", certName)
		return []byte{}, errors.New("API-Key invalid")
	} else if res.StatusCode != http.StatusOK {
		logger.Error("failed to get certificate from server", "cert-id", certName, "http-response", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		e := fmt.Errorf("failed to read certificate response from server: %w", err)
		sentry.CaptureException(e)
		return []byte{}, e
	}

	return body, nil
}

package certificates

import (
	"bufio"
	"bytes"
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

	"gitlab.lila.network/lila-network/certwarden-deploy/internal/configuration"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/constants"
)

// CertificateManager is a manager instance that holds commonly
// used things like logger and config
type CertificateManager struct {
	logger          *slog.Logger
	config          *configuration.ConfigFileData
	certificateList *[]Certificate
	httpclient      configuration.HTTPClient
}

// NewCertificateManager returns a new *CertificateManager
func NewCertificateManager(
	logger *slog.Logger,
	config *configuration.ConfigFileData,
) *CertificateManager {
	return &CertificateManager{
		config: config,
		logger: logger,
		httpclient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: config.DisableCertificateValidation,
				},
			},
		},
	}
}

// GetCertificatesFromConfig creates new Certificate objects from the given
// config values
func (cm *CertificateManager) GetCertificatesFromConfig() *[]Certificate {
	certList := []Certificate{}

	for _, cert := range cm.config.Certificates {
		certInfos := &CertificateData{
			Name:     cert.Name,
			FilePath: cert.CertificatePath,
			Secret:   cert.CertificateSecret,
			Type:     CertificateFile,
		}

		keyInfos := &CertificateData{
			Name:     cert.Name,
			FilePath: cert.KeyPath,
			Secret:   cert.KeySecret,
			Type:     KeyFile,
		}

		caInfos := &CertificateData{
			Name:     cert.Name,
			FilePath: cert.CaPath,
			Secret:   cert.CertificateSecret,
			Type:     CaCertificateFile,
		}

		certList = append(
			certList,
			Certificate{
				Certificate:          certInfos,
				Key:                  keyInfos,
				CertificateAuthority: caInfos,
				RolloutAction:        cert.Action,
				NeedsAction:          false,
			},
		)
	}

	return &certList
}

func (cm *CertificateManager) HandleCertificates(certificates *[]Certificate) {

	if len(*certificates) == 0 {
		cm.logger.Info("list of certificates is empty, nothing to do. Exiting...")
		return
	}

	for i := range *certificates {
		cert := &(*certificates)[i]
		fsFailed := false

		// Rollout Certificate
		certOnDiskChanged, err := cm.RolloutCertificateData(cert.Certificate)
		if err != nil {
			fsFailed = true
			cm.logger.Error(
				"Failed to roll out Certificate", "path",
				cert.Certificate.FilePath, "name", cert.Certificate.Name, "error", err,
			)
			continue
		}
		if certOnDiskChanged {
			cm.logger.Debug("Certificate file changed on disk", "name", cert.Certificate.Name)
			cert.NeedsAction = true
		}

		// Rollout key
		keyOnDiskChanged, err := cm.RolloutCertificateData(cert.Key)
		if err != nil {
			fsFailed = true
			cm.logger.Error(
				"Failed to roll out Key", "path",
				cert.Key.FilePath, "name", cert.Key.Name, "error", err,
			)
			continue
		}

		if keyOnDiskChanged {
			cm.logger.Debug("Key file changed on disk", "name", cert.Certificate.Name)
			cert.NeedsAction = true
		}

		// Rollout CA
		caOnDiskChanged, err := cm.RolloutCertificateData(cert.CertificateAuthority)
		if err != nil {
			fsFailed = true
			cm.logger.Error(
				"Failed to roll out CertificateAuthority", "path",
				cert.CertificateAuthority.FilePath, "name", cert.CertificateAuthority.Name, "error", err,
			)
			continue
		}

		if caOnDiskChanged {
			cm.logger.Debug("CA file changed on disk", "name", cert.Certificate.Name)
			cert.NeedsAction = true
		}

		if configuration.Force && !fsFailed {
			cm.logger.Info("Forcing file system change due to --force", "name", cert.Certificate.Name)
			cert.NeedsAction = true
		}

		if fsFailed {
			cm.logger.Info("One or more errors occured during file system operations, skipping certificate action.", "name", cert.Certificate.Name)
			cert.NeedsAction = false
		}
	}
}

// Rollout handles getting the certificate/key data from the
// server and writing it to disk if the data differs.
//
// Returns error on error, true if certificate action needs to be executed, false if not
func (cm *CertificateManager) RolloutCertificateData(c *CertificateData) (bool, error) {
	if c.FilePath == "" {
		cm.logger.Info("File path is empty, skipping...", "file-type", c.Type)
		return false, nil
	}

	err := cm.fetchDataFromServer(c)
	if err != nil {
		return false, fmt.Errorf("failed to get certificate from server: %w", err)
	}

	fileNeedsRollout, err := cm.needsRollout(c)
	if err != nil {
		return false, fmt.Errorf("failed to check certificate on disk: %w", err)
	}

	if fileNeedsRollout || configuration.Force {
		if configuration.Force {
			cm.logger.Info("Forcing file system change due to --force", "name", c.Name)
		}

		err = cm.writeToDisk(c)
		if err != nil {
			return false, fmt.Errorf("failed to handle certificate: %w", err)
		}

	}
	if fileNeedsRollout {
		cm.logger.Info("New file deployed", "path", c.FilePath)
		return true, nil
	} else if configuration.Force {
		cm.logger.Info("File deployed", "path", c.FilePath)
		return true, nil
	} else {
		cm.logger.Info("File not changed, skipping...", "path", c.FilePath)
		return false, nil
	}
}

// readFromDisk reads file data from disk and populates the data []byte field.
//
// Returns error or nil on success
func (c *CertificateData) readFromDisk() error {
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
func (cm *CertificateManager) needsRollout(c *CertificateData) (bool, error) {
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
		cm.logger.Debug("File on disk differs from server source", "path", c.FilePath)
	} else {
		cm.logger.Debug("File on disk is identical to server source", "path", c.FilePath)
	}

	return hashesAreDifferent, nil
}

// writeToDisk flushes the certificate data to disk.
//
// Returns error or nil on success.
func (cm *CertificateManager) writeToDisk(c *CertificateData) error {
	if configuration.DryRun {
		cm.logger.Debug("DRY-RUN: writing data to file", "path", c.FilePath)
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
	}(cm.logger)

	w := bufio.NewWriter(file)

	if _, err := w.Write(c.serverBytes); err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	if err = w.Flush(); err != nil {
		return fmt.Errorf("failed to flush data to file: %w", err)
	}

	cm.logger.Debug("Successfully wrote to file", "path", c.FilePath)
	return nil
}

// fetchFromServer fetches the cert/key data from the CertWarden server and
// fills the serverBytes field.
//
// Returns error or nil on success.
func (cm *CertificateManager) fetchDataFromServer(c *CertificateData) error {
	var apiPath string

	switch c.Type {
	case CertificateFile:
		apiPath = constants.CertificateApiPath
	case KeyFile:
		apiPath = constants.KeyApiPath
	case CaCertificateFile:
		apiPath = constants.CaCertificateApiPath
	}

	url := cm.config.BaseURL + apiPath + c.Name

	cm.logger.Debug("Data request URL: "+url, "file-type", c.Type)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to prepare to request data from server: %w", err)
	}

	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Add(constants.ApiKeyHeaderName, c.Secret)

	res, err := cm.httpclient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request data from server: %w", err)
	}

	defer func(l *slog.Logger) {
		if err := res.Body.Close(); err != nil {
			l.Error("failed to close http response body", "error", err)
		}
	}(cm.logger)

	if res.StatusCode == http.StatusUnauthorized {
		cm.logger.Error("API-Key for request is invalid, skipping certificate!", "name", c.Name, "file-type", c.Type)
		return errors.New("API-Key invalid")
	} else if res.StatusCode != http.StatusOK {
		cm.logger.Error("failed to get data from server", "name", c.Name, "http-response", res.Status, "file-type", c.Type)
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
//
// Returns error or nil, StdOut as string, and StdErr as string
func (cm *CertificateManager) handleSingleCertificateAction(action string) (error, string, string) {
	if action == "" {
		return nil, "", ""
	}

	sargs := strings.Split(action, " ")

	cmd := exec.Command(sargs[0], sargs[1:]...)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command was not successful: %q, : %w", action, err), stdout.String(), stderr.String()
	}

	return nil, "", ""
}

// HandleCertificateActions takes a list of Certificates and manages the rollout action
func (cm *CertificateManager) HandleCertificateActions(certificates *[]Certificate) error {
	actionMap := make(map[string][]Certificate)

	for i := range *certificates {

		cert := &(*certificates)[i]

		if cert.NeedsAction {
			actionMap[cert.RolloutAction] = append(actionMap[cert.RolloutAction], *cert)
		}
	}

	for action, actionCertificates := range actionMap {

	}

	err, stdout, stderr := cm.handleSingleCertificateAction(cert.RolloutAction)
	if err != nil {
		cm.logger.Error(
			"An error occured during rollout action",
			"error", err, "stdout")
	}
}

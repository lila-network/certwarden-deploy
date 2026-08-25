package certificates

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
)

// FetchArtefact downloads a single artefact of a certificate and hands back the
// bytes the server sent. It is the one-off read behind the `fetch` subcommands
// (#39).
//
// It is deliberately dumb: it fetches and returns. No filename template, no
// comparison against what is on disk, no staging. Change detection belongs to
// the deploy path, where "unchanged, wrote nothing" is the useful answer; for a
// command whose whole job is to show what the server returns, it would mean
// printing nothing at all.
//
// The returned bytes are certificate or key material. Neither this function nor
// fetchFromServer ever logs them, at any level. See
// TestFetchFromServerNeverLogsSuccessBody.
func FetchArtefact(
	logger *slog.Logger,
	config *configuration.ConfigFileData,
	cert configuration.CertificateData,
	fileType FileType,
	format string,
) ([]byte, error) {
	httpSettings, settingsErr := config.HTTPSettings()
	if settingsErr.HasMessages() {
		// A broken http block is a config error the caller already reports.
		// Carry on with the defaults rather than refusing to fetch over it: the
		// user is here because something is already wrong.
		settingsErr.Print(logger)
		httpSettings = configuration.DefaultHTTPSettings()
	}

	artefact := &GenericCertificate{
		Name:   cert.Name,
		Secret: secretForType(cert, fileType),
		HTTP:   httpSettings,
		Type:   fileType,
		Format: format,
	}

	if err := artefact.fetchFromServer(logger, config.BaseURL, config.DisableCertificateValidation); err != nil {
		return nil, fmt.Errorf("failed to fetch %v for certificate %s: %w", fileType, cert.Name, err)
	}

	return artefact.serverBytes, nil
}

// WriteFile writes data to path through the same stage-and-rename path a
// rollout uses, so a `fetch --output` cannot leave a half-written certificate
// behind either.
//
// Unlike a rollout it never looks at the content already on disk: fetch always
// writes.
func WriteFile(logger *slog.Logger, path string, data []byte) error {
	artefact := &GenericCertificate{FilePath: path, serverBytes: data}

	// This only picks the verb Commit logs. Nothing is compared, and the file
	// is written either way.
	artefact.state = Modified
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		artefact.state = Created
	}

	// Same guard the rollout uses: a staged file that never gets committed must
	// not be left lying next to the target. A no-op once Commit succeeded.
	defer artefact.Abort(logger)

	if err := artefact.writeTempFile(logger); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	if err := artefact.Commit(logger); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}

// secretForType returns the secret the endpoint for fileType authenticates
// with.
//
// It is the single place that mapping exists: artefactsOf reads it too, so a
// fetch cannot end up sending a different key than a deployment would.
func secretForType(cert configuration.CertificateData, fileType FileType) string {
	switch fileType {
	case KeyFile:
		return cert.KeySecret
	case PrivateCertFile, PrivateCertChainFile:
		return combinedSecret(cert)
	default:
		return cert.CertificateSecret
	}
}

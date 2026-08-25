package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lila-network/certwarden-deploy/internal/certificates"
	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/logger"
	"github.com/spf13/cobra"
)

// stdoutTarget is the --output value that means "write to stdout".
//
// It is the default, and the reason the whole command group is useful: the
// point of `fetch` is to pipe what the server returned into openssl, keytool or
// a diff, without a file ever existing.
const stdoutTarget = "-"

var (
	// fetchOutput holds --output. Shared by every fetch subcommand: exactly one
	// of them ever runs.
	fetchOutput string

	// fetchFormat holds --format, which only the two combined endpoints have.
	fetchFormat string
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Download a single certificate artefact ad hoc",
	Long: `Download one artefact of one certificate straight from CertWarden.

This is the debugging counterpart to the deploy path: it fetches, prints or
writes, and exits. It applies no filename template and it does no change
detection, so it always produces output, even when an identical file already
exists on disk. It never runs an action either.

By default the material is written to stdout, so it can be piped:

    certwarden-deploy fetch certificate example.com | openssl x509 -noout -text

Log records go to stderr, so they stay out of that pipe.

The secret is taken from --api-key, from the matching certificate entry in the
config file, or from CERTWARDEN_API_KEY, in that order. With --base-url and
--api-key it works without a config file at all.`,
	Args: cobra.NoArgs,
}

func init() {
	fetchCmd.AddCommand(
		newFetchCmd("certificate", "Download the certificate", certificates.CertificateFile, false),
		newFetchCmd("key", "Download the private key", certificates.KeyFile, false),
		newFetchCmd("ca", "Download the CA certificate chain", certificates.CaCertificateFile, false),
		newFetchCmd("privatecert", "Download the certificate and its private key in one file", certificates.PrivateCertFile, true),
		newFetchCmd("privatecertchain", "Download the certificate, its private key and the CA chain in one file", certificates.PrivateCertChainFile, true),
	)

	RootCmd.AddCommand(fetchCmd)
}

// newFetchCmd builds the subcommand for a single artefact type.
//
// withFormat is only true for the two combined endpoints: the other three
// return exactly one thing and have no container to choose, so offering them a
// --format that the server ignores would be a lie.
func newFetchCmd(use string, short string, fileType certificates.FileType, withFormat bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use + " <name>",
		Short: short,
		Args:  cobra.ExactArgs(1),

		// A fetch that fails failed on the network or on a secret, never
		// because the user typed the command wrong. Dumping the usage text
		// after the error would just bury it.
		SilenceUsage: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			return runFetch(cmd, args[0], fileType)
		},
	}

	cmd.Flags().StringVarP(&fetchOutput, "output", "o", stdoutTarget, `Where to write the material, "-" for stdout`)

	if withFormat {
		cmd.Flags().StringVar(
			&fetchFormat, "format", "",
			"Container to request: "+strings.Join(configuration.DownloadFormats, ", ")+". Default is pem",
		)
	}

	return cmd
}

func runFetch(cmd *cobra.Command, name string, fileType certificates.FileType) error {
	// stderr, always: stdout belongs to the material, and --output - is the
	// default.
	log := logger.InitializeTo(cmd.ErrOrStderr())

	if !configuration.IsValidDownloadFormat(fetchFormat) {
		return fmt.Errorf("--format must be one of %s, got %q", strings.Join(configuration.DownloadFormats, ", "), fetchFormat)
	}

	config, err := loadFetchConfig(cmd)
	if err != nil {
		return err
	}

	config.ApplyOverrides(log)

	scoped := scopeToCertificate(config, name)
	if validation := scoped.ResolveSecrets(log); validation.HasMessages() {
		return validationError(validation)
	}

	if validation := configuration.ValidateBaseURL(scoped.BaseURL); validation.HasMessages() {
		return validationError(validation)
	}

	cert := scoped.Certificates[0]
	if secretMissing(cert, fileType) {
		return fmt.Errorf(
			"no secret for certificate %s: set it with --api-key, in %s, or on the certificate in the config file",
			name, configuration.APIKeyEnvVar,
		)
	}

	data, err := certificates.FetchArtefact(log, scoped, cert, fileType, fetchFormat)
	if err != nil {
		return err
	}

	if fetchOutput == stdoutTarget {
		// Written, never logged: this is the certificate or key material
		// itself. See TestCLI_FetchDoesNotLogKeyMaterial.
		if _, err := cmd.OutOrStdout().Write(data); err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}

		return nil
	}

	return certificates.WriteFile(log, fetchOutput, data)
}

// loadFetchConfig loads the config file for a fetch, tolerating its absence.
//
// `fetch certificate example.com --base-url ... --api-key ...` has to work on a
// machine that has no config file, which is half the point of the command: it
// is what you reach for to check whether an API key works at all. So a failed
// discovery yields an empty config rather than an error.
//
// An explicit --config that cannot be read is still an error. The user named a
// file; quietly ignoring it would turn a typo into a puzzling 401.
func loadFetchConfig(cmd *cobra.Command) (*configuration.ConfigFileData, error) {
	config, path, err := loadConfig(cmd)
	if err == nil {
		return config, nil
	}

	// resolveConfigPath only fails when discovery came up empty, which it can
	// only do when --config was not given.
	if path == "" {
		return &configuration.ConfigFileData{}, nil
	}

	return nil, fmt.Errorf("failed to initialize config: %w", err)
}

// scopeToCertificate narrows a config down to the single certificate a fetch is
// about.
//
// Every other entry is dropped on purpose. fetch is the command reached for
// when a deployment is already broken, and an unset ${VAR} on an unrelated
// certificate must not be what keeps the user from downloading this one.
//
// A name the config does not know becomes an empty entry, so the secret chain
// falls through to CERTWARDEN_API_KEY or --api-key and a config-less fetch
// works.
func scopeToCertificate(config *configuration.ConfigFileData, name string) *configuration.ConfigFileData {
	scoped := *config
	entry := configuration.CertificateData{Name: name}

	for _, cert := range config.Certificates {
		if cert.Name == name {
			entry = cert
			break
		}
	}

	scoped.Certificates = []configuration.CertificateData{entry}

	return &scoped
}

// secretMissing reports whether the secret the endpoint needs is unset.
//
// The combined endpoints need both halves: without a key_secret the combined
// secret degenerates into "cert-secret." and the server answers 401, which is a
// far worse way to learn about it.
func secretMissing(cert configuration.CertificateData, fileType certificates.FileType) bool {
	switch fileType {
	case certificates.KeyFile:
		return cert.KeySecret == ""
	case certificates.PrivateCertFile, certificates.PrivateCertChainFile:
		return cert.CertificateSecret == "" || cert.KeySecret == ""
	default:
		return cert.CertificateSecret == ""
	}
}

// validationError renders collected validation messages into a single error.
//
// The subcommands report through their error return rather than by exiting, so
// the messages have to travel as one value. They are joined rather than
// summarised because a config error the user cannot read is not a report.
func validationError(validation configuration.ConfigValidationError) error {
	return errors.New(strings.Join(validation.ErrorMessages, "; "))
}

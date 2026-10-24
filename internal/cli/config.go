package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/logger"
	"github.com/spf13/cobra"
)

// initPath holds --path for `config init`.
var initPath string

// defaultInitPath is where `config init` writes when --path is not given.
//
// It is the first location DiscoverConfigFile searches, so `config init`
// followed by a bare `certwarden-deploy` in the same directory finds the file
// that was just written. TestConfigInitDefaultPathIsDiscoverable pins that.
const defaultInitPath = "./certwarden-deploy.yaml"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Scaffold, check and inspect the config file",
	Long: `Work on the config file without deploying anything.

None of these subcommands contacts the CertWarden server, so they are usable in
CI, in a pre-commit hook, or on a machine that cannot reach the server at all.`,
	Args: cobra.NoArgs,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a commented starter config file",
	Long: `Write a commented starter config file.

It refuses to overwrite an existing file unless --force is given, because the
file it would replace is the one holding your API keys.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runConfigInit,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check the config file and exit 0 or 1",
	Long: `Parse and validate the config file, then exit 0 if it is usable and 1 if it
is not, printing every problem found.

This makes NO network requests. It is the command for a CI job or a pre-commit
hook to run on a config that has never been near the server it names. --dry-run
is not a substitute: it still talks to the API.

It runs exactly the checks a real run runs before its first request:
placeholder substitution, the CLI overrides, secret resolution and validation.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runConfigValidate,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the effective config with every secret redacted",
	Long: `Print the config the tool will actually act on: placeholders expanded, CLI
overrides folded in, secrets resolved and defaults filled in.

Every secret and every http.headers value is printed as "` + configuration.RedactedSecret + `". There is no
flag to reveal them and there will not be one: this output is meant to be safe
to paste into a bug report.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runConfigShow,
}

func init() {
	configInitCmd.Flags().StringVar(&initPath, "path", defaultInitPath, "Where to write the starter config file")

	configCmd.AddCommand(configInitCmd, configValidateCmd, configShowCmd)
	RootCmd.AddCommand(configCmd)
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	// stderr: init reports, it does not produce data. Keeping every subcommand
	// consistent about that is worth more than the one line it costs here.
	log := logger.InitializeTo(cmd.ErrOrStderr())

	switch _, err := os.Stat(initPath); {
	case err == nil && !configuration.Force:
		// The file this would replace holds the API keys of a working
		// deployment. Clobbering it on a mistyped path is not recoverable.
		return fmt.Errorf("refusing to overwrite the existing file %s, pass --force to replace it", initPath)

	case err == nil:
		log.Warn("Overwriting the existing config file due to --force", "path", initPath)

	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("failed to inspect %s: %w", initPath, err)
	}

	if dir := filepath.Dir(initPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create the parent directory of %s: %w", initPath, err)
		}
	}

	// 0600: a config file is where the API keys live, and a starter file is
	// filled in and kept far more often than it is thrown away.
	if err := os.WriteFile(initPath, []byte(starterConfig), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", initPath, err)
	}

	log.Info("Wrote a starter config file", "path", initPath)

	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	log := logger.InitializeTo(cmd.ErrOrStderr())

	config, path, err := loadConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// Everything below this line is pure: prepareConfig is exactly what a run
	// does before its first request, and it makes no requests itself. Nothing
	// here may ever grow one. See TestCLI_ConfigValidateMakesNoNetworkRequests.
	if validation := prepareConfig(log, config); validation.HasMessages() {
		// every problem at once: a linter that reports the first error and
		// stops turns one broken config into five round trips
		validation.Print(log)
		return errors.New("the configuration file has errors")
	}

	log.Info("The configuration file is valid", "path", path)

	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	log := logger.InitializeTo(cmd.ErrOrStderr())

	config, _, err := loadConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	// An invalid config has no meaningful effective form: its secrets did not
	// resolve, so printing it would show blanks where the run would have
	// failed. Report it the way validate does instead.
	if validation := prepareConfig(log, config); validation.HasMessages() {
		validation.Print(log)
		return errors.New("the configuration file has errors")
	}

	redacted := config.Redacted()

	data, err := yaml.Marshal(&redacted)
	if err != nil {
		return fmt.Errorf("failed to render the config file: %w", err)
	}

	if _, err := cmd.OutOrStdout().Write(data); err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}

	return nil
}

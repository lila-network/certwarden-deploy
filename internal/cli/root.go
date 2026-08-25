package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/lila-network/certwarden-deploy/internal/certificates"
	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
	"github.com/lila-network/certwarden-deploy/internal/logger"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "certwarden-deploy",
	Short: "Deploy Certificates from CertWarden in a breeze",
	Long: `certwarden-deploy is a CLI utility to deploy certificates managed by CertWarden.
Configuration is handled by a single YAML file, so you can get started quickly.

Running it without a subcommand rolls out every certificate in the config file.
The subcommands are for the things around that: 'fetch' downloads a single
artefact ad hoc, 'config' scaffolds, lints and shows a config file.

For more information on how to configure this tool, visit the docs at https://certwarden-deploy.adora.codes`,
	Version:           constants.Version,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Args:              cobra.ExactArgs(0),
	Run:               handleRootCmd,
}

// resolveConfigPath determines which config file to load. An explicitly set
// --config is always used verbatim, only an unset flag triggers a search of the
// default locations.
func resolveConfigPath(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("config") {
		return configuration.ConfigFile, nil
	}

	path, err := configuration.DiscoverConfigFile()
	if err != nil {
		return "", fmt.Errorf("failed to discover config file: %w", err)
	}

	return path, nil
}

// loadConfig resolves the config file location and reads the file into memory.
//
// It returns the path it used alongside the config, because a command that
// reports on a config file has to be able to say which one it looked at.
func loadConfig(cmd *cobra.Command) (*configuration.ConfigFileData, string, error) {
	path, err := resolveConfigPath(cmd)
	if err != nil {
		return nil, "", err
	}

	cl := configuration.FileConfigLoader{Path: path}

	config, err := configuration.GetConfig(&cl)
	if err != nil {
		return nil, path, err
	}

	return config, path, nil
}

// prepareConfig runs everything a certificate rollout does to a freshly parsed
// config before the first request goes out, and reports what it found.
//
// It is shared with `config validate` and `config show` on purpose: a linter
// that checks anything other than what the real run checks is worse than no
// linter, because it hands out a green tick the run then disagrees with. That
// is also why the groups are desugared in here and not in handleRootCmd: a
// grouped config has to lint and print as the flat list a run really acts on,
// not as the sugar it was written as.
//
// Groups go first, before anything else reads the config: every step below then
// sees the one list it saw before groups existed, which is what lets {name} in a
// group path and a ${VAR} in a group secret work without any of them knowing.
//
// Secrets are resolved before the config is validated: the blank-secret check
// has to see the values the fallbacks produced, and an unresolvable ${VAR} or
// file: reference must fail before the first request. IsValid only runs when
// resolution produced no messages, because it would otherwise report every
// unresolved secret a second time as a blank one.
func prepareConfig(log *slog.Logger, config *configuration.ConfigFileData) configuration.ConfigValidationError {
	validation := config.ExpandGroups(log)

	config.SubstituteKeys(log)
	config.ApplyOverrides(log)

	validation.Merge(config.ResolveSecrets(log))
	if !validation.HasMessages() {
		validation.Merge(config.IsValid())
	}

	return validation
}

func handleRootCmd(cmd *cobra.Command, args []string) {
	config, _, err := loadConfig(cmd)
	if err != nil {
		slog.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}

	log := logger.Initialize()

	validation := prepareConfig(log, config)
	if validation.HasMessages() {
		validation.Print(log)
		slog.Error("The configuration file has errors! Application cannot start unless all errors are corrected!")
		os.Exit(1)
	}

	result := certificates.HandleCertificates(log, config)
	result.LogSummary(log)

	// Always exit explicitly, including on success: the exit code is the only
	// signal a supervisor (systemd, cron, CI) gets about a run that partially
	// failed. See RunResult.ExitCode for the contract.
	os.Exit(result.ExitCode())
}

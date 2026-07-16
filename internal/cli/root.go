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

func handleRootCmd(cmd *cobra.Command, args []string) {
	configPath, err := resolveConfigPath(cmd)
	if err != nil {
		slog.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}

	cl := configuration.FileConfigLoader{
		Path: configPath,
	}
	config, err := configuration.GetConfig(&cl)
	if err != nil {
		slog.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}
	log := logger.Initialize()

	// Groups are desugared into the flat certificates list first, before
	// anything else reads the config: every step below then sees the one list
	// it saw before groups existed, which is what lets {name} in a group path
	// and a ${VAR} in a group secret work without any of them knowing.
	validation := config.ExpandGroups(log)

	config.SubstituteKeys(log)
	config.ApplyOverrides(log)

	// Secrets are resolved before the config is validated, on purpose: the
	// blank-secret check has to see the values the fallbacks produced, and an
	// unresolvable ${VAR} or file: reference must fail the run before the first
	// request goes out.
	validation.Merge(config.ResolveSecrets(log))
	if !validation.HasMessages() {
		validation.Merge(config.IsValid())
	}

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

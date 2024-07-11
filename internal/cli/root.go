package cli

import (
	"log/slog"
	"os"

	"code.lila.network/adoralaura/certwarden-deploy/internal/certificates"
	"code.lila.network/adoralaura/certwarden-deploy/internal/configuration"
	"code.lila.network/adoralaura/certwarden-deploy/internal/constants"
	"code.lila.network/adoralaura/certwarden-deploy/internal/logger"
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

func handleRootCmd(cmd *cobra.Command, args []string) {
	config, err := configuration.InitializeConfig()
	if err != nil {
		slog.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}
	log := logger.InitializeLogger()
	config.SubstituteKeys(log)

	validation := config.IsValid()
	if validation.HasMessages() {
		validation.Print(log)
		slog.Error("The configuration file has errors! Application cannot start unless all errors are corrected!")
		panic(1)
	}

	certificates.HandleCertificates(log, config)
}

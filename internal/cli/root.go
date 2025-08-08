package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/certificates"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/configuration"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/constants"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/logger"
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
	cl := configuration.FileConfigLoader{
		Path: configuration.ConfigFile,
	}
	config, err := configuration.GetConfig(&cl)
	if err != nil {
		slog.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}
	log := logger.Initialize()
	config.SubstituteKeys(log)

	validation := config.IsValid()
	if validation.HasMessages() {
		validation.Print(log)
		slog.Error("The configuration file has errors! Application cannot start unless all errors are corrected!")
		os.Exit(1)
	}

	cm := certificates.NewCertificateManager(log, config)

	certs := cm.GetCertificatesFromConfig()

	cm.HandleCertificates(certs)

	cm.HandleCertificateActions(certs)
}

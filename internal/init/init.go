package init

import (
	"code.lila.network/adoralaura/certwarden-deploy/internal/cli"
	"code.lila.network/adoralaura/certwarden-deploy/internal/config"
	"code.lila.network/adoralaura/certwarden-deploy/internal/logger"
	"github.com/spf13/cobra"
)

func InitializeApp() {
	cobra.OnInitialize(config.InitializeConfig, logger.InitializeLogger)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	cli.RootCmd.PersistentFlags().StringVar(config.ConfigFile, "config", "", "config file (default is /etc/certwarden-deploy/config.yaml)")
}

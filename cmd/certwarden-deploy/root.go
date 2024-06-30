/*
Copyright © 2024 Laura Kalb <dev@lauka.net>
The code of this project is available under the MIT license. See the LICENSE file for more info.
*/
package cmd

import (
	"os"

	"code.lila.network/adoralaura/certwarden-deploy/internal/cli"
	"code.lila.network/adoralaura/certwarden-deploy/internal/config"
	"code.lila.network/adoralaura/certwarden-deploy/internal/logger"
	"github.com/spf13/cobra"
)

var cfgFile string

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := cli.RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(config.InitializeConfig, logger.InitializeLogger)

	cli.RootCmd.PersistentFlags().BoolVarP(&config.VerboseLogging, "verbose", "v", false, "Enable verbose logging")
	cli.RootCmd.PersistentFlags().BoolVarP(&config.DryRun, "dry-run", "d", false, "Just show the would-be changes without changing the file system")
	cli.RootCmd.PersistentFlags().BoolVarP(&config.QuietLogging, "quiet", "q", false, "Disable any logging (if both -q and -v are set, quiet wins)")
	cli.RootCmd.PersistentFlags().StringVarP(&config.ConfigFile, "config", "c", "/etc/certwarden-deploy/config.yaml", "Path to config file (default is /etc/certwarden-deploy/config.yaml)")

}

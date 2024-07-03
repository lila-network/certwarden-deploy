/*
Copyright © 2024 Laura Kalb <dev@lauka.net>
The code of this project is available under the MIT license. See the LICENSE file for more info.
*/
package cmd

import (
	"os"
	"time"

	"code.lila.network/adoralaura/certwarden-deploy/internal/cli"
	"code.lila.network/adoralaura/certwarden-deploy/internal/configuration"
	"github.com/getsentry/sentry-go"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := cli.RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
	defer sentry.Flush(2 * time.Second)
}

func init() {

	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.VerboseLogging, "verbose", "v", false, "Enable verbose logging")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.DryRun, "dry-run", "d", false, "Just show the would-be changes without changing the file system (turns on verbose logging)")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.QuietLogging, "quiet", "q", false, "Disable any logging (if both -q and -v are set, quiet wins)")
	cli.RootCmd.PersistentFlags().StringVarP(&configuration.ConfigFile, "config", "c", "/etc/certwarden-deploy/config.yaml", "Path to config file (default is /etc/certwarden-deploy/config.yaml)")

}

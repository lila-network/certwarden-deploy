/*
Copyright © 2024 Adora Kalb <me@adora.codes>
The code of this project is available under the MIT license. See the LICENSE file for more info.
*/
package main

import (
	"os"

	"code.lila.network/lila-network/certwarden-deploy/internal/cli"
	"code.lila.network/lila-network/certwarden-deploy/internal/configuration"
)

func main() {
	err := cli.RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.VerboseLogging, "verbose", "v", false, "Enable verbose logging")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.DryRun, "dry-run", "d", false, "Just show the would-be changes without changing the file system (turns on verbose logging)")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.QuietLogging, "quiet", "q", false, "Disable any logging (if both -q and -v are set, quiet wins)")
	cli.RootCmd.PersistentFlags().StringVarP(&configuration.ConfigFile, "config", "c", "/etc/certwarden-deploy/config.yaml", "Path to config file (default is /etc/certwarden-deploy/config.yaml)")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.Force, "force", "f", false, "Force overwriting and execution action to occur, regardless if certificate already exists")

}

/*
Copyright © 2024 Adora Kalb <me@adora.codes>
The code of this project is available under the MIT license. See the LICENSE file for more info.
*/
package main

import (
	"os"

	"github.com/lila-network/certwarden-deploy/internal/cli"
	"github.com/lila-network/certwarden-deploy/internal/configuration"
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
	cli.RootCmd.PersistentFlags().StringVarP(&configuration.ConfigFile, "config", "c", "/etc/certwarden-deploy/config.yaml", "Path to config file. If unset, the first existing of ./certwarden-deploy.yaml, $XDG_CONFIG_HOME/certwarden-deploy/config.yaml (or ~/.config/certwarden-deploy/config.yaml) and /etc/certwarden-deploy/config.yaml is used")
	cli.RootCmd.PersistentFlags().BoolVarP(&configuration.Force, "force", "f", false, "Force overwriting and execution action to occur, regardless if certificate already exists")
	cli.RootCmd.PersistentFlags().BoolVar(&configuration.NoActions, "no-actions", false, "Deploy files but skip every post-rollout action, overriding actions.enabled in the config file")
	cli.RootCmd.PersistentFlags().StringVar(&configuration.BaseURLOverride, "base-url", "", "Override base_url from the config file")
	cli.RootCmd.PersistentFlags().StringVar(&configuration.APIKeyOverride, "api-key", "", "Override cert_secret/key_secret for ALL certificates. Blunt on purpose, meant for one-off debugging, not for deployments")

}

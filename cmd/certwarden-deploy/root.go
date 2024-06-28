/*
Copyright © 2024 Laura Kalb <dev@lauka.net>
The code of this project is available under the MIT license. See the LICENSE file for more info.
*/
package cmd

import (
	"os"

	"code.lila.network/adoralaura/certwarden-deploy/internal/cli"
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

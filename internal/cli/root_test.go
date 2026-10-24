package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/spf13/cobra"
)

// newConfigCmd builds a command carrying the same --config flag that main.go
// registers, including its default value.
func newConfigCmd(t *testing.T) *cobra.Command {
	t.Helper()

	previous := configuration.ConfigFile
	t.Cleanup(func() { configuration.ConfigFile = previous })

	cmd := &cobra.Command{Use: "certwarden-deploy", Run: func(*cobra.Command, []string) {}}
	cmd.PersistentFlags().StringVarP(&configuration.ConfigFile, "config", "c", "/etc/certwarden-deploy/config.yaml", "Path to config file")

	return cmd
}

// writeLocalConfig drops a discoverable config into the current working directory.
func writeLocalConfig(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte("base_url: \"https://thisisatest.invalid\"\n"), 0644); err != nil {
		t.Fatalf("failed to write file %v: %v", path, err)
	}
}

// TestResolveConfigPathExplicitFlagDisablesDiscovery makes sure an explicit
// --config pointing at a missing file errors out instead of silently falling back
// to a discoverable config file.
func TestResolveConfigPathExplicitFlagDisablesDiscovery(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	discoverable := filepath.Join(workDir, "certwarden-deploy.yaml")
	writeLocalConfig(t, discoverable)

	missingPath := filepath.Join(workDir, "does-not-exist.yaml")

	cmd := newConfigCmd(t)
	if err := cmd.ParseFlags([]string{"--config", missingPath}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	path, err := resolveConfigPath(cmd)
	if err != nil {
		t.Fatalf("got error resolving config path: %v", err.Error())
	}

	if path != missingPath {
		t.Fatalf("explicit --config fell back to \"%v\", want \"%v\"", path, missingPath)
	}

	cl := configuration.FileConfigLoader{Path: path}
	if _, err := configuration.GetConfig(&cl); err == nil {
		t.Error("expected an error loading an explicitly configured missing file, got none")
	}
}

// TestResolveConfigPathUnsetFlagDiscovers documents that the untouched flag
// default does not short-circuit discovery.
func TestResolveConfigPathUnsetFlagDiscovers(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	writeLocalConfig(t, filepath.Join(workDir, "certwarden-deploy.yaml"))

	cmd := newConfigCmd(t)
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	path, err := resolveConfigPath(cmd)
	if err != nil {
		t.Fatalf("got error resolving config path: %v", err.Error())
	}

	if path != "./certwarden-deploy.yaml" {
		t.Errorf("got \"%v\", want \"%v\"", path, "./certwarden-deploy.yaml")
	}
}

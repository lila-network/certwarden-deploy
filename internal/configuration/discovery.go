package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// localConfigFile is looked up relative to the current working directory.
	localConfigFile = "./certwarden-deploy.yaml"

	// userConfigFile is looked up below the user's config directory.
	userConfigFile = "certwarden-deploy/config.yaml"

	// systemConfigFile is the last resort and matches the documented --config default.
	systemConfigFile = "/etc/certwarden-deploy/config.yaml"
)

// DiscoverConfigFile returns the first of the default config file locations that
// exists on disk. It is only meant to be used when the user did not set --config
// explicitly, an explicit path must never be subject to discovery.
func DiscoverConfigFile() (string, error) {
	return discoverConfigFile(defaultConfigPaths(systemConfigFile))
}

// defaultConfigPaths builds the ordered list of locations that are searched for a
// config file. systemPath is a parameter so tests do not depend on the real /etc.
func defaultConfigPaths(systemPath string) []string {
	paths := []string{localConfigFile}

	if dir := userConfigDir(); dir != "" {
		paths = append(paths, filepath.Join(dir, userConfigFile))
	}

	return append(paths, systemPath)
}

// userConfigDir resolves XDG_CONFIG_HOME and falls back to ~/.config when it is
// unset or empty. It returns an empty string if neither can be determined.
func userConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".config")
}

// discoverConfigFile returns the first path that points at an existing file. If no
// path matches, the returned error lists every location that was searched.
func discoverConfigFile(paths []string) (string, error) {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", fmt.Errorf("no config file found in any default location, searched: %s", strings.Join(paths, ", "))
}

package config

import (
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

func InitializeConfig() {
	if *ConfigFile != "" {
		*ConfigFile = "/etc/certwarden-deploy/config.yaml"
	}

	data, err := os.ReadFile(*ConfigFile)
	if err != nil {
		slog.Error("failed to read config file", "file", *ConfigFile, "error", err)
		os.Exit(1)
	}

	err = yaml.Unmarshal([]byte(data), &Config)
	if err != nil {
		slog.Error("failed to unmarshal config file", "file", *ConfigFile, "error", err)
		os.Exit(1)
	}
}

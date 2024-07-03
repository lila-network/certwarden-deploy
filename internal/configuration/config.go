package configuration

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func InitializeConfig() (*ConfigFileData, error) {
	var cfg ConfigFileData
	if ConfigFile == "" {
		ConfigFile = "/etc/certwarden-deploy/config.yaml"
	}

	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return &ConfigFileData{}, fmt.Errorf("failed to read config file: %w", err)
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return &ConfigFileData{}, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return &cfg, nil
}

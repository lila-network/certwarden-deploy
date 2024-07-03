package configuration

import (
	"log/slog"
	"os"
	"regexp"
)

func ValidateConfig(logger *slog.Logger, config ConfigFileData) {
	validationFailed := false

	if config.BaseURL == "" {
		logger.Error(`Field 'base_url' in config file is required!`)
		validationFailed = true
	}

	for _, cert := range config.Certificates {
		if cert.Name == "" {
			cert.Name = "unnamed_certificate"
			logger.Error(`Field 'name' for certificates cannot be blank!`)
			validationFailed = true
		}

		if cert.ApiKey == "" {
			logger.Error(`Field 'api_key' for certificate ` + cert.Name + " cannot be blank!")
			validationFailed = true
		}

		if cert.FilePath == "" {
			logger.Error(`Field 'file_path' for certificate ` + cert.Name + " cannot be blank!")
			validationFailed = true
		}

		re := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
		if !re.MatchString(cert.Name) {
			logger.Error(`Field 'name' for certificate may only contain -_. and alphanumeric characters!`)
			validationFailed = true
		}
	}

	if validationFailed {
		logger.Error("Config file has errors! Please fix errors above! Exiting...", "config-path", ConfigFile)
		os.Exit(1)
	}
}

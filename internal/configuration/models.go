package configuration

import "log/slog"

// Config file gets read into here
var Config *ConfigFileData

// ConfigFile contains the path to the config file on disk
var ConfigFile string

// Flag to show that the user wants a dry run
var DryRun bool

// Flag to show that the user wants quiet logging
var QuietLogging bool

// Flag to show that the user wants verbose logging
var VerboseLogging bool

// Flag to show that the user wants to force certificate update
var Force bool

// Struct to read the config file into when reading from disk
type ConfigFileData struct {
	BaseURL                      string            `yaml:"base_url"`
	DisableCertificateValidation bool              `yaml:"disable_certificate_validation"`
	Sentry                       SentryData        `yaml:"sentry,omitempty"`
	Certificates                 []CertificateData `yaml:"certificates"`
}

// Struct that holds the details of a single managed certificate
type CertificateData struct {
	Name              string `yaml:"name"`
	CertificateSecret string `yaml:"cert_secret"`
	CertificatePath   string `yaml:"cert_path"`
	KeySecret         string `yaml:"key_secret"`
	KeyPath           string `yaml:"key_path"`
	Action            string `yaml:"action"`
}

type SentryData struct {
	DSN string `yaml:"dsn"`
}

type ConfigValidationError struct {
	ErrorMessages []string
}

func (e *ConfigValidationError) Error() string {
	return "Configuration file has errors! Application cannot start unless the errors are corrected."
}

func (e *ConfigValidationError) Add(msg string) {
	e.ErrorMessages = append(e.ErrorMessages, msg)
}

func (e *ConfigValidationError) HasMessages() bool {
	return len(e.ErrorMessages) != 0
}

func (e *ConfigValidationError) Print(logger *slog.Logger) {
	for _, line := range e.ErrorMessages {
		logger.Error(line)
	}
}

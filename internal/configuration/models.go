package configuration

import "log/slog"

var Config *ConfigFileData
var ConfigFile string
var Logger *slog.Logger
var DryRun bool
var QuietLogging bool
var VerboseLogging bool

type ConfigFileData struct {
	BaseURL                      string            `yaml:"base_url"`
	DisableCertificateValidation bool              `yaml:"disable_certificate_validation"`
	Sentry                       SentryData        `yaml:"sentry,omitempty"`
	Certificates                 []CertificateData `yaml:"certificates"`
}

type CertificateData struct {
	Name     string `yaml:"name"`
	ApiKey   string `yaml:"api_key"`
	Action   string `yaml:"action"`
	FilePath string `yaml:"file_path"`
}

type SentryData struct {
	DSN string `yaml:"dsn"`
}

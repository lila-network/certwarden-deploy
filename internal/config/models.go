package config

import "log/slog"

var Config *ConfigFileData
var ConfigFile *string
var Logger *slog.Logger

type ConfigFileData struct {
	BaseURL                      string            `yaml:"base_url"`
	DisableCertificateValidation bool              `yaml:"disable_certificate_validation"`
	Certificates                 []CertificateData `yaml:"certificates"`
}

type CertificateData struct {
	Name     string `yaml:"name"`
	ApiKey   string `yaml:"api_key"`
	Action   string `yaml:"action"`
	FilePath string `yaml:"file_path"`
}

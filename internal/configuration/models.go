package configuration

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
	Name     string `yaml:"name"`
	ApiKey   string `yaml:"api_key"`
	Action   string `yaml:"action"`
	FilePath string `yaml:"file_path"`
}

type SentryData struct {
	DSN string `yaml:"dsn"`
}

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

// Flag to show that the user wants to skip every post-rollout action
var NoActions bool

// Struct to read the config file into when reading from disk
//
// DefaultCertificateSecret/DefaultKeySecret are deliberately two fields and not
// one api_key: the reference Python tool uses a single api_key, but this repo
// split cert and key secrets in 0.2.0 on purpose, and a single key cannot
// express that split.
type ConfigFileData struct {
	BaseURL                      string            `yaml:"base_url"`
	DisableCertificateValidation bool              `yaml:"disable_certificate_validation"`
	Actions                      ActionsConfig     `yaml:"actions"`
	DefaultCertificateSecret     string            `yaml:"default_cert_secret"`
	DefaultKeySecret             string            `yaml:"default_key_secret"`
	Certificates                 []CertificateData `yaml:"certificates"`
}

// ActionsConfig holds the run-wide switches for post-rollout actions.
type ActionsConfig struct {
	// Enabled turns post-rollout actions on or off for the whole run.
	//
	// It is a pointer so an omitted key can be told apart from an explicit
	// false. Omitted means enabled: see ConfigFileData.ActionsEnabled.
	Enabled *bool `yaml:"enabled"`
}

// Struct that holds the details of a single managed certificate
type CertificateData struct {
	Name              string `yaml:"name"`
	CertificateSecret string `yaml:"cert_secret"`
	CertificatePath   string `yaml:"cert_path"`
	KeySecret         string `yaml:"key_secret"`
	KeyPath           string `yaml:"key_path"`
	CaPath            string `yaml:"ca_path"`

	// PrivateCertPath is the destination for the combined certificate and
	// private key. Optional: an empty value skips that download entirely.
	PrivateCertPath string `yaml:"privatecert_path"`

	// PrivateCertFormat selects the container the privatecerts endpoint
	// returns: pem, pkcs12 or jks. Empty means pem.
	PrivateCertFormat string `yaml:"privatecert_format"`

	// PrivateCertChainPath is the destination for the combined certificate,
	// private key and CA chain. Optional, same as PrivateCertPath.
	PrivateCertChainPath string `yaml:"privatecertchain_path"`

	// PrivateCertChainFormat selects the container the privatecertchains
	// endpoint returns: pem, pkcs12 or jks. Empty means pem.
	PrivateCertChainFormat string `yaml:"privatecertchain_format"`

	Action Action `yaml:"action"`

	// RunOn selects when Action is executed. Empty means DefaultRunOn.
	// Validated by IsValid, read through EffectiveRunOn.
	RunOn string `yaml:"run_on"`
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

// Merge folds the messages of another validation error into this one, so that
// several validation passes can be reported to the user as a single list.
func (e *ConfigValidationError) Merge(other ConfigValidationError) {
	e.ErrorMessages = append(e.ErrorMessages, other.ErrorMessages...)
}

func (e *ConfigValidationError) HasMessages() bool {
	return len(e.ErrorMessages) != 0
}

func (e *ConfigValidationError) Print(logger *slog.Logger) {
	for _, line := range e.ErrorMessages {
		logger.Error(line)
	}
}

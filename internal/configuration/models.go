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

// BaseURLOverride holds --base-url, which replaces base_url from the config file
var BaseURLOverride string

// APIKeyOverride holds --api-key, which replaces cert_secret and key_secret for
// every certificate. See ResolveSecrets for why it is applied there.
var APIKeyOverride string

// Struct to read the config file into when reading from disk
//
// DefaultCertificateSecret/DefaultKeySecret are deliberately two fields and not
// one api_key: the reference Python tool uses a single api_key, but this repo
// split cert and key secrets in 0.2.0 on purpose, and a single key cannot
// express that split.
type ConfigFileData struct {
	BaseURL                      string        `yaml:"base_url"`
	DisableCertificateValidation bool          `yaml:"disable_certificate_validation"`
	Actions                      ActionsConfig `yaml:"actions"`
	DefaultCertificateSecret     string        `yaml:"default_cert_secret"`
	DefaultKeySecret             string        `yaml:"default_key_secret"`
	HTTP                         HTTPConfig    `yaml:"http"`

	// Groups is optional sugar over Certificates: each group holds the values
	// its members share, and ExpandGroups folds every member into Certificates
	// before anything else reads the config. Both keys may be used together.
	Groups map[string]CertificateGroup `yaml:"groups"`

	Certificates []CertificateData `yaml:"certificates"`
}

// ActionsConfig holds the run-wide switches for post-rollout actions.
type ActionsConfig struct {
	// Enabled turns post-rollout actions on or off for the whole run.
	//
	// It is a pointer so an omitted key can be told apart from an explicit
	// false. Omitted means enabled: see ConfigFileData.ActionsEnabled.
	Enabled *bool `yaml:"enabled"`
}

// HTTPConfig holds the optional http block, which tunes how requests to
// CertWarden are made rather than what is requested.
//
// Every field is optional and the zero value reproduces the behaviour this tool
// had before the block existed, bar the retries, which default to 2.
type HTTPConfig struct {
	// Headers are sent with every request. Values support the same ${VAR} and
	// file: references as the secrets, because a header that a reverse proxy
	// gates on is usually a secret itself.
	Headers map[string]string `yaml:"headers"`

	// Timeout is a Go duration string bounding a single attempt, e.g. "10s"
	Timeout string `yaml:"timeout"`

	// Retries is the number of attempts made after the first one, 0 disables
	// retrying entirely.
	//
	// A pointer so that an explicit "retries: 0" can be told apart from the key
	// being absent, which is what makes a non-zero default possible at all.
	Retries *int `yaml:"retries"`

	// RetryBackoff is the base for the exponential backoff between attempts
	RetryBackoff string `yaml:"retry_backoff"`
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

	// group names the group this certificate was defined in, or "" when it came
	// from the flat certificates list. It is set by ExpandGroups.
	//
	// It is unexported and read by validation messages only. Desugaring is the
	// point of groups, so a certificate's group is deliberately invisible
	// everywhere downstream of the config package: it is context for telling
	// the user where in their file to look, not data the rollout acts on.
	group string
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

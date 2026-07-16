package configuration

import (
	"regexp"
	"strings"

	"github.com/lila-network/certwarden-deploy/internal/constants"
)

// validDownloadFormats lists the containers the privatecerts and
// privatecertchains endpoints can return.
var validDownloadFormats = []string{constants.FormatPEM, constants.FormatPKCS12, constants.FormatJKS}

// isValidDownloadFormat reports whether format is empty (meaning the pem
// default) or one of the supported containers.
func isValidDownloadFormat(format string) bool {
	if format == "" {
		return true
	}

	for _, valid := range validDownloadFormats {
		if format == valid {
			return true
		}
	}

	return false
}

// unnamedCertificate stands in for the name of a certificate that has none, so
// that a message about it still points at something.
const unnamedCertificate = "unnamed_certificate"

// certificateName returns a name that is safe to put into a validation message.
func certificateName(name string) string {
	if name == "" {
		return unnamedCertificate
	}

	return name
}

// IsValid tests if the config read from file has all required parameters set.
//
// Exits the app if errors are detected
func (c *ConfigFileData) IsValid() ConfigValidationError {
	err := ConfigValidationError{}

	if c.BaseURL == "" {
		err.Add(`Field 'base_url' in config file is required!`)
	}

	for _, cert := range c.Certificates {
		if cert.Name == "" {
			cert.Name = unnamedCertificate
			err.Add(`Field 'name' for certificates cannot be blank!`)
		}

		if cert.CertificateSecret == "" {
			err.Add(`Field 'cert_secret' for certificate ` + cert.Name + " cannot be blank!")
		}

		if cert.CertificatePath == "" {
			err.Add(`Field 'cert_path' for certificate ` + cert.Name + " cannot be blank!")
		}

		// An omitted or empty action simply means "nothing to run".
		//
		// A present-but-empty action is a likely mistake, but deliberately NOT
		// a validation error: refusing to start would stop every certificate in
		// the config from being deployed because one action line is blank, and
		// a config that deploys nothing is far worse than one that runs
		// nothing. HandleCertificates warns about it at rollout time instead.

		if !cert.EffectiveRunOn().IsValid() {
			err.Add(`Field 'run_on' for certificate ` + cert.Name + ` must be one of 'new', 'changed', 'new_or_changed' or 'all', got '` + cert.RunOn + `'!`)
		}

		// The privatecert and privatecertchain endpoints authenticate with the
		// certificate secret and the key secret joined by a dot, so without a
		// key_secret the combined secret cannot be built at all.
		if cert.KeySecret == "" {
			if cert.PrivateCertPath != "" {
				err.Add(`Field 'key_secret' for certificate ` + cert.Name + " is required when 'privatecert_path' is set!")
			}

			if cert.PrivateCertChainPath != "" {
				err.Add(`Field 'key_secret' for certificate ` + cert.Name + " is required when 'privatecertchain_path' is set!")
			}
		}

		if !isValidDownloadFormat(cert.PrivateCertFormat) {
			err.Add(`Field 'privatecert_format' for certificate ` + cert.Name +
				" must be one of " + strings.Join(validDownloadFormats, ", ") + "!")
		}

		if !isValidDownloadFormat(cert.PrivateCertChainFormat) {
			err.Add(`Field 'privatecertchain_format' for certificate ` + cert.Name +
				" must be one of " + strings.Join(validDownloadFormats, ", ") + "!")
		}

		re := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
		if !re.MatchString(cert.Name) {
			err.Add(`Field 'name' for certificate may only contain -_. and alphanumeric characters!`)
		}
	}

	return err
}

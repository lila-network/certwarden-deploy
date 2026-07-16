package configuration

import (
	"net/url"
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

// certificateSubject names a certificate in a validation message, pointing at
// the group it was defined in when it came from one.
//
// A certificate from the flat certificates list renders exactly as it did
// before groups existed, so no pre-existing message changed. A grouped one
// names both, because "certificate b.example.com" is not enough to find the
// offending line in a file where the value at fault may well be the group's.
func (c CertificateData) certificateSubject() string {
	if c.group == "" {
		return "certificate " + certificateName(c.Name)
	}

	return "group '" + c.group + "', certificate '" + certificateName(c.Name) + "'"
}

// isAbsoluteURL reports whether raw is a URL this tool can build a request from.
//
// url.Parse alone is not enough: it happily accepts "certwarden.example.com" as
// a relative reference, which would then be concatenated into a nonsense request
// URL, so the scheme and the host have to be there as well.
func isAbsoluteURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return parsed.Scheme != "" && parsed.Host != ""
}

// IsValid tests if the config read from file has all required parameters set.
//
// It has to run after ResolveSecrets: the cert_secret check below looks at the
// effective secret, so it may only ever see values that the config-level
// defaults and the CERTWARDEN_API_KEY fallback have already been applied to.
// Checking the raw file value would tell users to fix something they left out
// on purpose.
//
// Exits the app if errors are detected
func (c *ConfigFileData) IsValid() ConfigValidationError {
	err := ConfigValidationError{}

	if c.BaseURL == "" {
		err.Add(`Field 'base_url' in config file is required!`)
	} else if !isAbsoluteURL(c.BaseURL) {
		// this also covers --base-url: the override is folded into BaseURL
		// before validation, so a typo on the command line is caught here
		// rather than by a confusing failure on the first request
		err.Add(`Field 'base_url' must be an absolute URL including the scheme, got "` + c.BaseURL + `"!`)
	}

	if _, httpErr := c.HTTPSettings(); httpErr.HasMessages() {
		err.Merge(httpErr)
	}

	for _, cert := range c.Certificates {
		if cert.Name == "" {
			cert.Name = unnamedCertificate

			// this message names no certificate, there being none to name, so
			// the group is the only pointer at the offending line there is
			if cert.group == "" {
				err.Add(`Field 'name' for certificates cannot be blank!`)
			} else {
				err.Add(`Field 'name' for certificates in group '` + cert.group + `' cannot be blank!`)
			}
		}

		if cert.CertificateSecret == "" {
			err.Add(`Field 'cert_secret' for ` + cert.certificateSubject() +
				` is set neither on the certificate nor as 'default_cert_secret', and ` +
				APIKeyEnvVar + ` is not set either!`)
		}

		if cert.CertificatePath == "" {
			err.Add(`Field 'cert_path' for ` + cert.certificateSubject() + " cannot be blank!")
		}

		// An omitted or empty action simply means "nothing to run".
		//
		// A present-but-empty action is a likely mistake, but deliberately NOT
		// a validation error: refusing to start would stop every certificate in
		// the config from being deployed because one action line is blank, and
		// a config that deploys nothing is far worse than one that runs
		// nothing. HandleCertificates warns about it at rollout time instead.

		if !cert.EffectiveRunOn().IsValid() {
			err.Add(`Field 'run_on' for ` + cert.certificateSubject() + ` must be one of 'new', 'changed', 'new_or_changed' or 'all', got '` + cert.RunOn + `'!`)
		}

		// The privatecert and privatecertchain endpoints authenticate with the
		// certificate secret and the key secret joined by a dot, so without a
		// key_secret the combined secret cannot be built at all.
		if cert.KeySecret == "" {
			if cert.PrivateCertPath != "" {
				err.Add(`Field 'key_secret' for ` + cert.certificateSubject() + " is required when 'privatecert_path' is set!")
			}

			if cert.PrivateCertChainPath != "" {
				err.Add(`Field 'key_secret' for ` + cert.certificateSubject() + " is required when 'privatecertchain_path' is set!")
			}
		}

		if !isValidDownloadFormat(cert.PrivateCertFormat) {
			err.Add(`Field 'privatecert_format' for ` + cert.certificateSubject() +
				" must be one of " + strings.Join(validDownloadFormats, ", ") + "!")
		}

		if !isValidDownloadFormat(cert.PrivateCertChainFormat) {
			err.Add(`Field 'privatecertchain_format' for ` + cert.certificateSubject() +
				" must be one of " + strings.Join(validDownloadFormats, ", ") + "!")
		}

		re := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
		if !re.MatchString(cert.Name) {
			// the flat form of this message has never named the certificate;
			// it is left that way rather than churning it for every existing
			// config, while a grouped one gets the full subject
			if cert.group == "" {
				err.Add(`Field 'name' for certificate may only contain -_. and alphanumeric characters!`)
			} else {
				err.Add(`Field 'name' for ` + cert.certificateSubject() + ` may only contain -_. and alphanumeric characters!`)
			}
		}
	}

	return err
}

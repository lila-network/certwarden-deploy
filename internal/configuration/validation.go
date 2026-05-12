package configuration

import (
	"net/url"
	"regexp"
)

// IsValid tests if the config read from file has all required parameters set.
//
// Exits the app if errors are detected
func (c *ConfigFileData) IsValid() ConfigValidationError {
	err := ConfigValidationError{}

	if !isValidUrl(c.BaseURL) {
		err.Add(`Field base_url must be a valid url (e.g. http[s]://example.com)`)
	}

	if c.Notifications.Ntfy.Enabled {
		if !isValidUrl(c.Notifications.Ntfy.Endpoint) {
			err.Add(`Field notifications.ntfy.endpoint must be a valid url (e.g. http[s]://example.com) if Ntfy is enabled`)
		}

		if c.Notifications.Ntfy.Topic == "" {
			err.Add(`Field notifications.ntfy.topic can't be empty if Ntfy is enabled`)
		}

	}

	for _, cert := range c.Certificates {
		if cert.Name == "" {
			cert.Name = "unnamed_certificate"
			err.Add(`Field 'name' for certificates cannot be blank`)
		}

		if cert.CertificateSecret == "" {
			err.Add(`Field 'cert_secret' for certificate ` + cert.Name + " cannot be blank")
		}

		if cert.CertificatePath == "" {
			err.Add(`Field 'cert_path' for certificate ` + cert.Name + " cannot be blank")
		}

		re := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
		if !re.MatchString(cert.Name) {
			err.Add(`Field 'name' for certificate may only contain -_. and alphanumeric characters`)
		}
	}

	return err
}

func isValidUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

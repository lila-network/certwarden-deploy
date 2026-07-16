package configuration

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// APIKeyEnvVar names the environment variable that is used for every
// certificate whose cert_secret/key_secret is left empty. It is the last
// fallback in the precedence chain implemented by pickSecret.
const APIKeyEnvVar = "CERTWARDEN_API_KEY"

const (
	// envRefEscape is the escape hatch for a literal "${": "$${FOO}" resolves
	// to the string "${FOO}" instead of the environment variable FOO.
	envRefEscape = "$${"

	// envRefPrefix marks a value as an environment variable reference.
	envRefPrefix = "${"

	// fileRefPrefix marks a value as a reference to a file on disk, which is the
	// shape systemd's LoadCredential= and most secret managers hand secrets over in.
	fileRefPrefix = "file:"
)

// envRefPattern matches a complete environment variable reference.
//
// A value that starts with "${" has to match this fully. A partial reference
// such as "prefix${VAR}" is rejected instead of being passed through as a
// literal: silently sending "prefix${VAR}" to the server as an API key would
// surface as a puzzling 401 rather than as the config error it is.
var envRefPattern = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// secretSource names where an effective secret came from.
//
// It exists to make the precedence chain debuggable without logging the secret:
// a source identifies the place to look, never the value found there.
type secretSource string

const (
	secretFromCertificate secretSource = "certificate"
	secretFromDefault     secretSource = "config default"
	secretFromEnv         secretSource = "environment " + APIKeyEnvVar
	secretUnset           secretSource = "unset"
)

// resolveValue expands a single config value into the literal it stands for.
//
//	"${FOO}"      -> the value of the environment variable FOO
//	"file:/path"  -> the contents of /path, whitespace trimmed
//	"$${FOO}"     -> the literal string "${FOO}"
//	anything else -> itself, exactly as before this indirection existed
//
// Errors name the environment variable or the file path that could not be
// resolved and never the value itself, so that a resolution failure cannot leak
// a secret into the log.
func resolveValue(raw string) (string, error) {
	switch {
	case strings.HasPrefix(raw, envRefEscape):
		return strings.TrimPrefix(raw, "$"), nil

	case strings.HasPrefix(raw, envRefPrefix):
		match := envRefPattern.FindStringSubmatch(raw)
		if match == nil {
			return "", fmt.Errorf(
				"malformed environment variable reference, the whole value must be of the form ${NAME}, use $${ for a literal",
			)
		}

		value, ok := os.LookupEnv(match[1])
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", match[1])
		}

		return value, nil

	case strings.HasPrefix(raw, fileRefPrefix):
		path := strings.TrimPrefix(raw, fileRefPrefix)
		if path == "" {
			return "", fmt.Errorf("file reference is missing a path")
		}

		data, err := os.ReadFile(path)
		if err != nil {
			// os errors carry the path and never the file contents
			return "", fmt.Errorf("failed to read file %s: %w", path, err)
		}

		return strings.TrimSpace(string(data)), nil

	default:
		return raw, nil
	}
}

// resolveField resolves one config value and records a validation message if it
// cannot be resolved.
//
// The message names the field plus the offending variable or path. It never
// contains the value, resolved or not.
func resolveField(err *ConfigValidationError, field string, subject string, raw string) string {
	resolved, resolveErr := resolveValue(raw)
	if resolveErr == nil {
		return resolved
	}

	message := "Field '" + field + "'"
	if subject != "" {
		message += " " + subject
	}
	err.Add(message + " could not be resolved: " + resolveErr.Error())

	return ""
}

// pickSecret applies the secret precedence chain, most specific first:
//
//	per-certificate -> config-level default -> CERTWARDEN_API_KEY -> nothing
//
// An empty result is not an error here. Whether a certificate may end up without
// a secret is IsValid's call, and it can only make that call once every fallback
// has been applied.
func pickSecret(certValue string, defaultValue string, envValue string) (string, secretSource) {
	switch {
	case certValue != "":
		return certValue, secretFromCertificate
	case defaultValue != "":
		return defaultValue, secretFromDefault
	case envValue != "":
		return envValue, secretFromEnv
	default:
		return "", secretUnset
	}
}

// ResolveSecrets turns every configured secret into the literal value that is
// sent to the server: it expands ${VAR} and file: references and falls back to
// the CERTWARDEN_API_KEY environment variable for certificates that carry no
// secret of their own.
//
// It has to run before IsValid, for two reasons: the blank-secret check may only
// ever look at fully resolved values, and an unresolvable reference has to fail
// the run before the first request goes out.
//
// Resolved secrets are never logged, at any level. Only the name of the source a
// secret came from is.
func (c *ConfigFileData) ResolveSecrets(logger *slog.Logger) ConfigValidationError {
	err := ConfigValidationError{}

	c.resolveCertificateSecrets(&err, logger)

	return err
}

// resolveCertificateSecrets fills in the effective cert_secret/key_secret of
// every configured certificate.
func (c *ConfigFileData) resolveCertificateSecrets(err *ConfigValidationError, logger *slog.Logger) {
	envFallback := os.Getenv(APIKeyEnvVar)
	defaultCertSecret := resolveField(err, "default_cert_secret", "", c.DefaultCertificateSecret)
	defaultKeySecret := resolveField(err, "default_key_secret", "", c.DefaultKeySecret)

	for index := range c.Certificates {
		cert := &c.Certificates[index]
		subject := "for certificate " + certificateName(cert.Name)

		// the per-certificate value is resolved even when a default would win
		// anyway: a reference the user wrote down explicitly has to be reported
		// when it is broken, not quietly stepped over
		certSecret, certSource := pickSecret(
			resolveField(err, "cert_secret", subject, cert.CertificateSecret),
			defaultCertSecret,
			envFallback,
		)
		keySecret, keySource := pickSecret(
			resolveField(err, "key_secret", subject, cert.KeySecret),
			defaultKeySecret,
			envFallback,
		)

		cert.CertificateSecret = certSecret
		cert.KeySecret = keySecret

		logger.Debug(
			"Resolved certificate secrets",
			"name", certificateName(cert.Name),
			"cert_secret-source", string(certSource),
			"key_secret-source", string(keySource),
		)
	}
}

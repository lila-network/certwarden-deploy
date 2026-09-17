package configuration

import (
	"log/slog"
	"maps"
	"regexp"
	"time"
)

// placeholderPattern matches anything shaped like a placeholder.
//
// It is used both to expand the known placeholders and to find the ones that
// no substitution recognised, so a typo like {cert-path} is reported instead of
// silently ending up in a file path or on an action command line.
var placeholderPattern = regexp.MustCompile(`\{[a-z_]+\}`)

// dateLayout renders the run date as YYYYMMDD.
const dateLayout = "20060102"

// SubstituteKeys expands every supported placeholder in the certificate paths
// and in the action.
func (c *ConfigFileData) SubstituteKeys(logger *slog.Logger) {
	// The run date is resolved once for the whole run, not once per
	// substitution: a run that starts before midnight and ends after it must
	// not write one {date} into cert_path and a different one into key_path.
	runDate := time.Now().Format(dateLayout)

	for index := range c.Certificates {
		c.substituteCertificate(logger, &c.Certificates[index], runDate)
	}
}

// substituteCertificate expands the placeholders of a single certificate.
func (c *ConfigFileData) substituteCertificate(logger *slog.Logger, cert *CertificateData, runDate string) {
	// Placeholders that may appear in a path.
	//
	// {common_name} and {cert_id} are migration aliases of {name}: CertWarden
	// addresses a certificate by a single identifier, so all three expand to
	// the same value.
	pathValues := map[string]string{
		"{name}":        cert.Name,
		"{common_name}": cert.Name,
		"{cert_id}":     cert.Name,
		"{date}":        runDate,
		"{base_url}":    c.BaseURL,
	}

	cert.CertificatePath = expandPlaceholders(cert.CertificatePath, pathValues)
	cert.KeyPath = expandPlaceholders(cert.KeyPath, pathValues)
	cert.CaPath = expandPlaceholders(cert.CaPath, pathValues)
	cert.PrivateCertPath = expandPlaceholders(cert.PrivateCertPath, pathValues)
	cert.PrivateCertChainPath = expandPlaceholders(cert.PrivateCertChainPath, pathValues)

	// The action is expanded last and reads the already expanded paths, so
	// {cert_path} in an action resolves to the final on-disk location rather
	// than to the raw config value.
	actionValues := map[string]string{
		"{cert_path}":             cert.CertificatePath,
		"{key_path}":              cert.KeyPath,
		"{ca_path}":               cert.CaPath,
		"{privatecert_path}":      cert.PrivateCertPath,
		"{privatecertchain_path}": cert.PrivateCertChainPath,
	}
	maps.Copy(actionValues, pathValues)

	// Both action forms go through the same single-pass engine. A list action
	// is expanded argument by argument, so a placeholder that is a whole
	// argument stays a single argument no matter what it expands to: a path
	// with a space in it cannot silently split into two arguments.
	cert.Action = cert.Action.substitute(func(value string) string {
		return expandPlaceholders(value, actionValues)
	})

	warnUnresolved(logger, cert.Name, "cert_path", cert.CertificatePath)
	warnUnresolved(logger, cert.Name, "key_path", cert.KeyPath)
	warnUnresolved(logger, cert.Name, "ca_path", cert.CaPath)
	warnUnresolved(logger, cert.Name, "privatecert_path", cert.PrivateCertPath)
	warnUnresolved(logger, cert.Name, "privatecertchain_path", cert.PrivateCertChainPath)
	warnUnresolvedAction(logger, cert.Name, cert.Action)
}

// expandPlaceholders replaces every known placeholder in a single pass.
//
// One pass matters twice over: a substituted value that itself looks like a
// placeholder is never expanded again, and the result does not depend on the
// order in which the replacements happen.
func expandPlaceholders(value string, values map[string]string) string {
	if value == "" {
		return value
	}

	return placeholderPattern.ReplaceAllStringFunc(value, func(placeholder string) string {
		if replacement, ok := values[placeholder]; ok {
			return replacement
		}

		// Unknown placeholders are left untouched so warnUnresolved can point
		// at the original text.
		return placeholder
	})
}

// warnUnresolved reports every placeholder that survived substitution.
//
// An unresolved placeholder is almost always a typo or a placeholder used in a
// field that does not support it, and it would otherwise reach the file system
// or the action command line verbatim.
func warnUnresolved(logger *slog.Logger, name string, field string, value string) {
	if logger == nil || value == "" {
		return
	}

	for _, placeholder := range placeholderPattern.FindAllString(value, -1) {
		logger.Warn(
			"Unrecognised placeholder was left unsubstituted",
			"placeholder", placeholder, "name", name, "field", field,
		)
	}
}

// warnUnresolvedAction reports unresolved placeholders in either action form.
//
// The list form is checked argument by argument: a typo hidden in one argument
// of a list action is exactly as broken as one in a string action, and reading
// the arguments back as a single joined string would let a placeholder that
// spans two arguments look resolved when it is not.
func warnUnresolvedAction(logger *slog.Logger, name string, action Action) {
	if len(action.Args) > 0 {
		for _, arg := range action.Args {
			warnUnresolved(logger, name, "action", arg)
		}

		return
	}

	warnUnresolved(logger, name, "action", action.Command)
}

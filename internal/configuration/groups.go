package configuration

import (
	"log/slog"
	"maps"
	"slices"
)

// CertificateGroup holds the values shared by a set of certificates that are
// deployed the same way, so that they only have to be written once.
//
// Every field is a default for the certificates in the group and nothing more:
// a group is desugared into plain entries of the flat certificates list before
// anything else looks at the config, so no part of this tool downstream of
// ExpandGroups knows that groups exist at all.
//
// The fields mirror CertificateData, minus the one that cannot sensibly be
// shared: name is what tells the certificates of a group apart, so it stays
// per-certificate.
type CertificateGroup struct {
	CertificateSecret string `yaml:"cert_secret"`
	CertificatePath   string `yaml:"cert_path"`
	KeySecret         string `yaml:"key_secret"`
	KeyPath           string `yaml:"key_path"`
	CaPath            string `yaml:"ca_path"`

	PrivateCertPath   string `yaml:"privatecert_path"`
	PrivateCertFormat string `yaml:"privatecert_format"`

	PrivateCertChainPath   string `yaml:"privatecertchain_path"`
	PrivateCertChainFormat string `yaml:"privatecertchain_format"`

	Action Action `yaml:"action"`
	RunOn  string `yaml:"run_on"`

	// Certificates are the members of the group. They are ordinary certificate
	// definitions and may override any value the group sets.
	Certificates []CertificateData `yaml:"certificates"`
}

// override picks the effective value of a single field.
//
// The rule is deliberately the simplest one that can be explained in a
// sentence: a value set on the certificate replaces the group's value whole,
// and nothing is ever merged, concatenated or interpolated between the two.
func override(certValue string, groupValue string) string {
	if certValue != "" {
		return certValue
	}

	return groupValue
}

// merge fills in every value the certificate leaves unset from the group.
//
// Placeholders are not touched here. A group path like
// "/etc/nginx/ssl/{name}.crt" is copied to each certificate verbatim and is
// expanded per certificate later by SubstituteKeys, which is what makes a
// single group-level path usable by every member of the group.
func (g CertificateGroup) merge(groupName string, cert CertificateData) CertificateData {
	merged := cert
	merged.group = groupName

	merged.CertificateSecret = override(cert.CertificateSecret, g.CertificateSecret)
	merged.CertificatePath = override(cert.CertificatePath, g.CertificatePath)
	merged.KeySecret = override(cert.KeySecret, g.KeySecret)
	merged.KeyPath = override(cert.KeyPath, g.KeyPath)
	merged.CaPath = override(cert.CaPath, g.CaPath)

	merged.PrivateCertPath = override(cert.PrivateCertPath, g.PrivateCertPath)
	merged.PrivateCertFormat = override(cert.PrivateCertFormat, g.PrivateCertFormat)
	merged.PrivateCertChainPath = override(cert.PrivateCertChainPath, g.PrivateCertChainPath)
	merged.PrivateCertChainFormat = override(cert.PrivateCertChainFormat, g.PrivateCertChainFormat)

	merged.RunOn = override(cert.RunOn, g.RunOn)

	// The action is the one field where "empty" is not the same as "unset":
	// `action: ""` on a certificate is how a single member of a group opts out
	// of the group's action, so presence of the key decides here, not content.
	if !cert.Action.IsSet() {
		merged.Action = g.Action
	}

	return merged
}

// ExpandGroups desugars every configured group into plain entries of the flat
// certificates list.
//
// This runs before substitution, secret resolution and validation, which is the
// whole design of the feature: by the time anything else sees the config there
// is only the flat list that existed before groups did, so IsValid,
// ResolveSecrets, SubstituteKeys and HandleCertificates need to know nothing
// about groups. The only trace a group leaves behind is the name recorded on
// each certificate, which validation messages read and nothing else does.
//
// The expanded certificates are placed before the flat list and the groups are
// walked in sorted order, so the deployment order of a given config file is
// stable across runs even though groups are a map.
func (c *ConfigFileData) ExpandGroups(logger *slog.Logger) ConfigValidationError {
	err := ConfigValidationError{}

	if len(c.Groups) == 0 {
		// Without a groups key this is a config as it existed before this
		// feature, and it is left exactly as it was found: not even the
		// uniqueness check below runs, because a flat list with a repeated name
		// has always been accepted and failing it now would break the configs
		// this feature is meant to leave alone.
		return err
	}

	expanded := make([]CertificateData, 0, len(c.Certificates))

	for _, groupName := range slices.Sorted(maps.Keys(c.Groups)) {
		group := c.Groups[groupName]

		for _, cert := range group.Certificates {
			expanded = append(expanded, group.merge(groupName, cert))
		}

		logger.Debug(
			"Expanded certificate group",
			"group", groupName,
			"certificates", len(group.Certificates),
		)
	}

	c.Certificates = append(expanded, c.Certificates...)

	c.reportDuplicateNames(&err)

	return err
}

// reportDuplicateNames rejects a name that appears more than once in the merged
// set of certificates.
//
// Two certificates of the same name are always a mistake, and a quiet one: they
// address the same certificate on the server and, with group paths keyed on
// {name}, they write to the same files, so the second silently overwrites the
// first and the action runs twice for no reason.
//
// A blank name is not reported here. That is IsValid's business, and reporting
// it twice would only bury the message that says what to actually fix.
func (c *ConfigFileData) reportDuplicateNames(err *ConfigValidationError) {
	seen := make(map[string]struct{}, len(c.Certificates))

	for _, cert := range c.Certificates {
		if cert.Name == "" {
			continue
		}

		if _, duplicate := seen[cert.Name]; duplicate {
			err.Add(`Field 'name' for ` + cert.certificateSubject() +
				` is not unique: certificate names must be unique across all groups and the 'certificates' list!`)

			continue
		}

		seen[cert.Name] = struct{}{}
	}
}

package configuration

// RedactedSecret stands in for every secret in the output of Redacted.
//
// There is no flag to turn this off, and there must not be one. The only thing
// a --show-secrets could ever accomplish is putting an API key into a terminal
// scrollback, a CI log or a pasted bug report, which is exactly the set of
// places a secret gets copied out of. The reference Python tool's `config view`
// dumps the parsed YAML including plaintext keys; this deliberately does not.
const RedactedSecret = "<redacted>"

// Redacted returns a copy of the config that is safe to print.
//
// It answers "what will the tool actually act on": the defaults a run would
// apply are filled in, so an omitted actions.enabled or http.timeout shows the
// value that is really used rather than a null. It is meant to be called after
// ExpandGroups, SubstituteKeys, ApplyOverrides and ResolveSecrets, so the
// groups are desugared, the paths are expanded and the secrets are the ones
// that would be sent.
//
// Every secret and every custom HTTP header value is replaced. Header values
// are not optional to redact: a header that gates a reverse proxy
// (CF-Access-Client-Secret and friends) is a secret in every deployment that
// has one, and it goes through the same resolution the API keys do.
//
// The copy is deep wherever a secret lives, so no caller can reach a real
// secret through a map or slice the copy still shares.
func (c *ConfigFileData) Redacted() ConfigFileData {
	out := *c

	enabled := c.ActionsEnabled()
	out.Actions.Enabled = &enabled

	// A broken http block keeps its raw values rather than being replaced by
	// defaults that would not actually be used: the point of the output is to
	// show what happens, and what happens is that the run refuses to start.
	if settings, err := c.HTTPSettings(); !err.HasMessages() {
		retries := settings.Retries

		out.HTTP.Timeout = settings.Timeout.String()
		out.HTTP.Retries = &retries
		out.HTTP.RetryBackoff = settings.RetryBackoff.String()
	}

	// Groups are dropped rather than redacted. ExpandGroups has already folded
	// every member into Certificates by the time this runs, so the groups key
	// holds nothing the certificates below do not state outright, and printing
	// the sugar next to what it desugared to would only invite the reader to
	// diff the two. Dropping it is also what keeps the promise this output
	// makes: a group's cert_secret and key_secret are real secrets that
	// ExpandGroups copied into the certificates, where they are redacted, and
	// echoing the group back would put the plaintext in a file meant to be
	// pasted into a bug report.
	out.Groups = nil

	out.DefaultCertificateSecret = redactSecret(c.DefaultCertificateSecret)
	out.DefaultKeySecret = redactSecret(c.DefaultKeySecret)
	out.HTTP.Headers = redactHeaders(c.HTTP.Headers)
	out.Certificates = redactCertificates(c.Certificates)

	return out
}

// redactHeaders replaces every header value, keeping the names.
//
// The names are worth showing: "is CF-Access-Client-Id being sent at all" is
// the question this output exists to answer, and it can be answered without
// the value.
func redactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}

	out := make(map[string]string, len(headers))
	for name := range headers {
		out[name] = RedactedSecret
	}

	return out
}

// redactCertificates copies the certificate entries with their secrets removed.
func redactCertificates(certificates []CertificateData) []CertificateData {
	if certificates == nil {
		return nil
	}

	out := make([]CertificateData, len(certificates))
	copy(out, certificates)

	for index := range out {
		out[index].CertificateSecret = redactSecret(out[index].CertificateSecret)
		out[index].KeySecret = redactSecret(out[index].KeySecret)

		// an omitted run_on is not "no policy", it is the default one, and the
		// output is about what happens rather than about what was typed
		out[index].RunOn = string(out[index].EffectiveRunOn())
	}

	return out
}

// redactSecret replaces a secret, leaving an unset one unset.
//
// The distinction carries the information: RedactedSecret has to mean "there is
// a value here", otherwise the output cannot answer whether a fallback kicked
// in, which is most of what it is read for.
func redactSecret(value string) string {
	if value == "" {
		return ""
	}

	return RedactedSecret
}

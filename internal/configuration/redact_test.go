package configuration

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// newSecretConfig builds a config whose every secret-bearing field holds a
// value that is trivial to search for.
func newSecretConfig() ConfigFileData {
	return ConfigFileData{
		BaseURL:                  "https://certwarden.example.com",
		DefaultCertificateSecret: "default-cert-secret",
		DefaultKeySecret:         "default-key-secret",
		HTTP: HTTPConfig{
			Headers: map[string]string{
				"CF-Access-Client-Id":     "header-client-id",
				"CF-Access-Client-Secret": "header-client-secret",
			},
		},
		Certificates: []CertificateData{
			{
				Name:              "example.com",
				CertificateSecret: "cert-secret",
				CertificatePath:   "/tmp/cert.pem",
				KeySecret:         "key-secret",
			},
		},
	}
}

// secretValues lists every value in newSecretConfig that must never be
// printed.
var secretValues = []string{
	"default-cert-secret",
	"default-key-secret",
	"header-client-id",
	"header-client-secret",
	"cert-secret",
	"key-secret",
}

func TestRedactedReplacesEverySecret(t *testing.T) {
	config := newSecretConfig()
	redacted := config.Redacted()

	if redacted.DefaultCertificateSecret != RedactedSecret {
		t.Errorf("default_cert_secret was not redacted: %q", redacted.DefaultCertificateSecret)
	}

	if redacted.DefaultKeySecret != RedactedSecret {
		t.Errorf("default_key_secret was not redacted: %q", redacted.DefaultKeySecret)
	}

	for name, value := range redacted.HTTP.Headers {
		if value != RedactedSecret {
			t.Errorf("header %s was not redacted: %q", name, value)
		}
	}

	cert := redacted.Certificates[0]
	if cert.CertificateSecret != RedactedSecret {
		t.Errorf("cert_secret was not redacted: %q", cert.CertificateSecret)
	}

	if cert.KeySecret != RedactedSecret {
		t.Errorf("key_secret was not redacted: %q", cert.KeySecret)
	}
}

// TestRedactedKeepsTheStructureWorthShowing makes sure redaction did not take
// the answers with it: the output has to stay useful.
func TestRedactedKeepsTheStructureWorthShowing(t *testing.T) {
	config := newSecretConfig()
	redacted := config.Redacted()

	if redacted.BaseURL != config.BaseURL {
		t.Errorf("base_url was changed: %q", redacted.BaseURL)
	}

	if redacted.Certificates[0].Name != "example.com" {
		t.Errorf("the certificate name was changed: %q", redacted.Certificates[0].Name)
	}

	if redacted.Certificates[0].CertificatePath != "/tmp/cert.pem" {
		t.Errorf("cert_path was changed: %q", redacted.Certificates[0].CertificatePath)
	}

	for _, name := range []string{"CF-Access-Client-Id", "CF-Access-Client-Secret"} {
		if _, ok := redacted.HTTP.Headers[name]; !ok {
			t.Errorf("header name %s was dropped", name)
		}
	}
}

// TestRedactedLeavesUnsetSecretsUnset pins the distinction the output is read
// for: "<redacted>" has to mean there is a value, so an empty field must stay
// empty rather than claim a secret that is not there.
func TestRedactedLeavesUnsetSecretsUnset(t *testing.T) {
	config := ConfigFileData{
		BaseURL:      "https://certwarden.example.com",
		Certificates: []CertificateData{{Name: "example.com"}},
	}

	redacted := config.Redacted()

	if redacted.DefaultCertificateSecret != "" {
		t.Errorf("an unset default_cert_secret was reported as a secret: %q", redacted.DefaultCertificateSecret)
	}

	if redacted.Certificates[0].CertificateSecret != "" {
		t.Errorf("an unset cert_secret was reported as a secret: %q", redacted.Certificates[0].CertificateSecret)
	}

	if redacted.Certificates[0].KeySecret != "" {
		t.Errorf("an unset key_secret was reported as a secret: %q", redacted.Certificates[0].KeySecret)
	}
}

// TestRedactedDoesNotShareSecretsWithTheCopy is the guard against the subtle
// version of the leak: a redacted copy that still points at the original map or
// slice hands a caller the plaintext through the back door.
func TestRedactedDoesNotShareSecretsWithTheCopy(t *testing.T) {
	config := newSecretConfig()
	redacted := config.Redacted()

	// mutating the copy must not reach the original
	redacted.HTTP.Headers["CF-Access-Client-Id"] = "mutated"
	redacted.Certificates[0].CertificateSecret = "mutated"

	if config.HTTP.Headers["CF-Access-Client-Id"] != "header-client-id" {
		t.Error("the redacted copy shares its headers map with the original")
	}

	if config.Certificates[0].CertificateSecret != "cert-secret" {
		t.Error("the redacted copy shares its certificates slice with the original")
	}

	// and the original still holds what it held
	if config.HTTP.Headers["CF-Access-Client-Secret"] != "header-client-secret" {
		t.Error("Redacted modified the config it was called on")
	}
}

// TestRedactedFillsInTheDefaultsARunWouldApply covers the other half of the
// promise: the output is what the tool acts on, not a re-dump of the file.
func TestRedactedFillsInTheDefaultsARunWouldApply(t *testing.T) {
	config := ConfigFileData{
		BaseURL:      "https://certwarden.example.com",
		Certificates: []CertificateData{{Name: "example.com"}},
	}

	redacted := config.Redacted()

	if redacted.Actions.Enabled == nil || !*redacted.Actions.Enabled {
		t.Error("an omitted actions.enabled should show as the default, true")
	}

	if redacted.HTTP.Timeout != DefaultHTTPTimeout.String() {
		t.Errorf("an omitted http.timeout should show the default: %q", redacted.HTTP.Timeout)
	}

	if redacted.HTTP.Retries == nil || *redacted.HTTP.Retries != DefaultHTTPRetries {
		t.Error("an omitted http.retries should show the default")
	}

	if redacted.Certificates[0].RunOn != string(DefaultRunOn) {
		t.Errorf("an omitted run_on should show the default: %q", redacted.Certificates[0].RunOn)
	}
}

// TestRedactedReflectsTheOverrides makes sure the flags that change what a run
// does are visible in what a run is said to do.
func TestRedactedReflectsTheOverrides(t *testing.T) {
	previous := NoActions
	t.Cleanup(func() { NoActions = previous })
	NoActions = true

	config := ConfigFileData{BaseURL: "https://certwarden.example.com"}

	redacted := config.Redacted()
	if redacted.Actions.Enabled == nil || *redacted.Actions.Enabled {
		t.Error("--no-actions should show as actions.enabled: false")
	}
}

// TestActionMarshalsBackToTheFormItWasWrittenIn keeps `config show` printing
// something the user recognises.
func TestActionMarshalsBackToTheFormItWasWrittenIn(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   interface{}
	}{
		{"string form", ShellAction("systemctl reload nginx"), "systemctl reload nginx"},
		{"list form", ExecAction("systemctl", "reload", "nginx"), []string{"systemctl", "reload", "nginx"}},
		{"omitted", Action{}, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.action.MarshalYAML()
			if err != nil {
				t.Fatalf("got an error marshalling the action: %v", err)
			}

			switch want := test.want.(type) {
			case string:
				if got != want {
					t.Errorf("got %v, want %q", got, want)
				}
			case []string:
				gotArgs, ok := got.([]string)
				if !ok {
					t.Fatalf("got %T, want a []string", got)
				}

				if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
					t.Errorf("got %v, want %v", gotArgs, want)
				}
			}
		})
	}
}

// TestRedactedDropsTheGroupsItWasDesugaredFrom pins the one thing the groups
// feature and this one have to agree on.
//
// Redacted runs after ExpandGroups, so the certificates it prints already hold
// everything the groups said. Echoing the groups back on top of that would put
// a group's cert_secret and key_secret into the output in plaintext, because
// nothing redacts them there: they are only ever redacted on the certificates
// they were copied to.
func TestRedactedDropsTheGroupsItWasDesugaredFrom(t *testing.T) {
	config := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Groups: map[string]CertificateGroup{
			"nginx": {
				CertificateSecret: "group-cert-secret",
				KeySecret:         "group-key-secret",
				CertificatePath:   "/etc/nginx/ssl/{name}.crt",
				Certificates:      []CertificateData{{Name: "a.example.com"}},
			},
		},
	}

	config.ExpandGroups(discardLogger())

	redacted := config.Redacted()

	if redacted.Groups != nil {
		t.Errorf("expected the desugared groups to be dropped, got %v", redacted.Groups)
	}

	// the rendered form is what `config show` actually prints, and it is the
	// form the leak would have appeared in: an unredacted group under a
	// `groups:` key of its own
	data, err := yaml.Marshal(&redacted)
	if err != nil {
		t.Fatalf("got an error marshalling the redacted config: %v", err)
	}

	rendered := string(data)
	for _, secret := range []string{"group-cert-secret", "group-key-secret"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("group secret %q leaked into the output:\n%s", secret, rendered)
		}
	}

	if strings.Contains(rendered, "groups:") {
		t.Errorf("expected no groups key in the effective config:\n%s", rendered)
	}
}

// TestRedactedKeepsTheCertificatesAGroupExpandedTo is the other half: dropping
// the groups may not drop what they defined.
func TestRedactedKeepsTheCertificatesAGroupExpandedTo(t *testing.T) {
	config := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Groups: map[string]CertificateGroup{
			"nginx": {
				CertificateSecret: "group-cert-secret",
				CertificatePath:   "/etc/nginx/ssl/{name}.crt",
				Action:            Action{Command: "systemctl reload nginx"},
				Certificates:      []CertificateData{{Name: "a.example.com"}, {Name: "b.example.com"}},
			},
		},
	}

	config.ExpandGroups(discardLogger())
	config.SubstituteKeys(discardLogger())

	redacted := config.Redacted()

	if len(redacted.Certificates) != 2 {
		t.Fatalf("expected both members of the group to survive, got %d", len(redacted.Certificates))
	}

	for index, wantPath := range []string{"/etc/nginx/ssl/a.example.com.crt", "/etc/nginx/ssl/b.example.com.crt"} {
		cert := redacted.Certificates[index]

		if cert.CertificatePath != wantPath {
			t.Errorf("expected cert_path %q, got %q", wantPath, cert.CertificatePath)
		}

		// the group's value reaches the output the only way it may: on the
		// certificate, redacted
		if cert.CertificateSecret != RedactedSecret {
			t.Errorf("expected the group's secret to show as redacted on %s, got %q", cert.Name, cert.CertificateSecret)
		}
	}
}

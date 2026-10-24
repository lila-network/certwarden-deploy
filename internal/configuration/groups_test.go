package configuration

import (
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

// discardLogger is a logger for the tests that only care about the config the
// expansion produced, not about what it said while producing it.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// loadConfig unmarshals a YAML document the way the real config loader does, so
// that the tests exercise the yaml tags and Action's scalar-or-list decoding
// rather than a hand-built struct that could not have come from a file.
func loadConfig(t *testing.T, document string) *ConfigFileData {
	t.Helper()

	loader := stringConfigLoader{data: document}

	cfg, err := GetConfig(&loader)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	return cfg
}

type stringConfigLoader struct {
	data string
}

func (s *stringConfigLoader) readDataFromFile() ([]byte, error) {
	return []byte(s.data), nil
}

func (s *stringConfigLoader) unmarshalDataToConfig(data []byte) (ConfigFileData, error) {
	file := FileConfigLoader{}

	return file.unmarshalDataToConfig(data)
}

// certByName finds an expanded certificate, failing the test when the expansion
// did not produce it at all.
func certByName(t *testing.T, cfg *ConfigFileData, name string) CertificateData {
	t.Helper()

	for _, cert := range cfg.Certificates {
		if cert.Name == name {
			return cert
		}
	}

	t.Fatalf("certificate %q is missing from the expanded config, got %v", name, certNames(cfg))

	return CertificateData{}
}

func certNames(cfg *ConfigFileData) []string {
	names := make([]string, 0, len(cfg.Certificates))
	for _, cert := range cfg.Certificates {
		names = append(names, cert.Name)
	}

	return names
}

// TestExpandGroupsAppliesGroupValuesToEveryMember covers the point of the
// feature: values written once on the group reach every certificate in it.
func TestExpandGroupsAppliesGroupValuesToEveryMember(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "group-cert-secret"
    key_secret: "group-key-secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    key_path: "/etc/nginx/ssl/{name}.key"
    ca_path: "/etc/nginx/ssl/{name}-ca.crt"
    privatecert_path: "/etc/nginx/ssl/{name}.pem"
    privatecert_format: "pkcs12"
    privatecertchain_path: "/etc/nginx/ssl/{name}-full.pem"
    privatecertchain_format: "jks"
    action: "systemctl reload nginx"
    run_on: "changed"
    certificates:
      - name: a.example.com
      - name: b.example.com
`)

	if err := cfg.ExpandGroups(discardLogger()); err.HasMessages() {
		t.Fatalf("expected no validation messages, got %v", err.ErrorMessages)
	}

	if len(cfg.Certificates) != 2 {
		t.Fatalf("expected 2 expanded certificates, got %v", certNames(cfg))
	}

	for _, name := range []string{"a.example.com", "b.example.com"} {
		cert := certByName(t, cfg, name)

		if cert.CertificateSecret != "group-cert-secret" {
			t.Errorf("cert_secret for %v is %q, want the group value", name, cert.CertificateSecret)
		}

		if cert.KeySecret != "group-key-secret" {
			t.Errorf("key_secret for %v is %q, want the group value", name, cert.KeySecret)
		}

		if cert.PrivateCertFormat != "pkcs12" {
			t.Errorf("privatecert_format for %v is %q, want pkcs12", name, cert.PrivateCertFormat)
		}

		if cert.PrivateCertChainFormat != "jks" {
			t.Errorf("privatecertchain_format for %v is %q, want jks", name, cert.PrivateCertChainFormat)
		}

		if cert.Action.Command != "systemctl reload nginx" {
			t.Errorf("action for %v is %q, want the group value", name, cert.Action.Command)
		}

		if cert.EffectiveRunOn() != RunOnChanged {
			t.Errorf("run_on for %v is %q, want changed", name, cert.EffectiveRunOn())
		}
	}
}

// TestExpandGroupsResolvesNamePlaceholderPerCertificate is the reason group
// paths are worth having: one path template, a different path per member.
func TestExpandGroupsResolvesNamePlaceholderPerCertificate(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    key_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    key_path: "/etc/nginx/ssl/{name}.key"
    ca_path: "/etc/nginx/ssl/{name}-ca.crt"
    privatecert_path: "/etc/nginx/ssl/{name}.pem"
    privatecertchain_path: "/etc/nginx/ssl/{name}-full.pem"
    action: "cat {cert_path}"
    certificates:
      - name: a.example.com
      - name: b.example.com
`)

	cfg.ExpandGroups(discardLogger())
	cfg.SubstituteKeys(discardLogger())

	first := certByName(t, cfg, "a.example.com")
	second := certByName(t, cfg, "b.example.com")

	if first.CertificatePath != "/etc/nginx/ssl/a.example.com.crt" {
		t.Errorf("cert_path is %q, want the {name} of the certificate itself", first.CertificatePath)
	}

	if first.KeyPath != "/etc/nginx/ssl/a.example.com.key" {
		t.Errorf("key_path is %q, want the {name} of the certificate itself", first.KeyPath)
	}

	if first.CaPath != "/etc/nginx/ssl/a.example.com-ca.crt" {
		t.Errorf("ca_path is %q, want the {name} of the certificate itself", first.CaPath)
	}

	if first.PrivateCertPath != "/etc/nginx/ssl/a.example.com.pem" {
		t.Errorf("privatecert_path is %q, want the {name} of the certificate itself", first.PrivateCertPath)
	}

	if first.PrivateCertChainPath != "/etc/nginx/ssl/a.example.com-full.pem" {
		t.Errorf("privatecertchain_path is %q, want the {name} of the certificate itself", first.PrivateCertChainPath)
	}

	if second.CertificatePath != "/etc/nginx/ssl/b.example.com.crt" {
		t.Errorf("cert_path is %q, want the {name} of the certificate itself", second.CertificatePath)
	}

	// the group action reads a path that was itself expanded per certificate
	if first.Action.Command != "cat /etc/nginx/ssl/a.example.com.crt" {
		t.Errorf("action is %q, want the certificate's own expanded cert_path", first.Action.Command)
	}

	if second.Action.Command != "cat /etc/nginx/ssl/b.example.com.crt" {
		t.Errorf("action is %q, want the certificate's own expanded cert_path", second.Action.Command)
	}
}

// TestExpandGroupsCertificateValueOverridesGroupValue pins the merge rule: the
// certificate wins, wholesale, for every kind of field.
func TestExpandGroupsCertificateValueOverridesGroupValue(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "group-cert-secret"
    key_secret: "group-key-secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    key_path: "/etc/nginx/ssl/{name}.key"
    action: "systemctl reload nginx"
    run_on: "changed"
    certificates:
      - name: inherits.example.com
      - name: overrides.example.com
        cert_secret: "own-cert-secret"
        key_secret: "own-key-secret"
        cert_path: "/srv/own/{name}.crt"
        action: "systemctl reload haproxy"
        run_on: "all"
`)

	if err := cfg.ExpandGroups(discardLogger()); err.HasMessages() {
		t.Fatalf("expected no validation messages, got %v", err.ErrorMessages)
	}

	overrides := certByName(t, cfg, "overrides.example.com")

	if overrides.CertificateSecret != "own-cert-secret" {
		t.Errorf("cert_secret is %q, want the per-certificate value to win", overrides.CertificateSecret)
	}

	if overrides.KeySecret != "own-key-secret" {
		t.Errorf("key_secret is %q, want the per-certificate value to win", overrides.KeySecret)
	}

	if overrides.CertificatePath != "/srv/own/{name}.crt" {
		t.Errorf("cert_path is %q, want the per-certificate value to win", overrides.CertificatePath)
	}

	if overrides.Action.Command != "systemctl reload haproxy" {
		t.Errorf("action is %q, want the per-certificate value to win", overrides.Action.Command)
	}

	if overrides.EffectiveRunOn() != RunOnAll {
		t.Errorf("run_on is %q, want the per-certificate value to win", overrides.EffectiveRunOn())
	}

	// an override on one member must not leak into its siblings
	inherits := certByName(t, cfg, "inherits.example.com")

	if inherits.CertificateSecret != "group-cert-secret" {
		t.Errorf("cert_secret is %q, want the group value", inherits.CertificateSecret)
	}

	if inherits.KeyPath != "/etc/nginx/ssl/{name}.key" {
		t.Errorf("key_path is %q, want the group value", inherits.KeyPath)
	}

	if inherits.Action.Command != "systemctl reload nginx" {
		t.Errorf("action is %q, want the group value", inherits.Action.Command)
	}

	if inherits.EffectiveRunOn() != RunOnChanged {
		t.Errorf("run_on is %q, want the group value", inherits.EffectiveRunOn())
	}
}

// TestExpandGroupsCertificateOverridesGroupActionWithListForm makes sure the
// override rule is about the key being present, not about its shape: a list
// action on a member replaces a string action on the group whole.
func TestExpandGroupsCertificateOverridesGroupActionWithListForm(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    action: "systemctl reload nginx"
    certificates:
      - name: list.example.com
        action:
          - /usr/bin/systemctl
          - reload
          - haproxy
`)

	cfg.ExpandGroups(discardLogger())

	cert := certByName(t, cfg, "list.example.com")

	if cert.Action.Command != "" {
		t.Errorf("the group's string action survived as %q, want it replaced wholesale", cert.Action.Command)
	}

	if len(cert.Action.Args) != 3 || cert.Action.Args[2] != "haproxy" {
		t.Errorf("action args are %v, want the per-certificate list", cert.Action.Args)
	}
}

// TestExpandGroupsCertificateOptsOutOfGroupActionWithEmptyAction covers the one
// field where an empty value is a statement and not an omission.
func TestExpandGroupsCertificateOptsOutOfGroupActionWithEmptyAction(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    action: "systemctl reload nginx"
    certificates:
      - name: quiet.example.com
        action: ""
`)

	cfg.ExpandGroups(discardLogger())

	cert := certByName(t, cfg, "quiet.example.com")

	if !cert.Action.IsEmpty() {
		t.Errorf("action is %q, want an explicit empty action to suppress the group's", cert.Action.String())
	}
}

// TestExpandGroupsMergesGroupsWithFlatList covers both keys being used at once,
// which is the migration path off a fully flat config.
func TestExpandGroupsMergesGroupsWithFlatList(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "group-secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: grouped.example.com
certificates:
  - name: standalone.example.com
    cert_secret: "flat-secret"
    cert_path: "/etc/ssl/standalone.crt"
`)

	if err := cfg.ExpandGroups(discardLogger()); err.HasMessages() {
		t.Fatalf("expected no validation messages, got %v", err.ErrorMessages)
	}

	if len(cfg.Certificates) != 2 {
		t.Fatalf("expected the group and the flat list to be merged, got %v", certNames(cfg))
	}

	standalone := certByName(t, cfg, "standalone.example.com")

	if standalone.CertificateSecret != "flat-secret" {
		t.Errorf("cert_secret of the flat certificate is %q, want it untouched by the group", standalone.CertificateSecret)
	}

	if standalone.CertificatePath != "/etc/ssl/standalone.crt" {
		t.Errorf("cert_path of the flat certificate is %q, want it untouched by the group", standalone.CertificatePath)
	}

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected the merged config to validate, got %v", err.ErrorMessages)
	}
}

// TestExpandGroupsWithOnlyGroupsAndNoFlatList makes sure the flat key is not
// required once groups carry everything.
func TestExpandGroupsWithOnlyGroupsAndNoFlatList(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: only.example.com
`)

	if err := cfg.ExpandGroups(discardLogger()); err.HasMessages() {
		t.Fatalf("expected no validation messages, got %v", err.ErrorMessages)
	}

	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "only.example.com" {
		t.Fatalf("expected the sole grouped certificate, got %v", certNames(cfg))
	}

	if err := cfg.IsValid(); err.HasMessages() {
		t.Fatalf("expected a groups-only config to validate, got %v", err.ErrorMessages)
	}
}

// TestExpandGroupsWithoutGroupsLeavesFlatListUntouched is the regression guard
// for every config that predates this feature.
func TestExpandGroupsWithoutGroupsLeavesFlatListUntouched(t *testing.T) {
	document := `
base_url: "https://certwarden.example.invalid"
certificates:
  - name: first.example.com
    cert_secret: "first-secret"
    cert_path: "/etc/ssl/first.crt"
    action: "systemctl reload nginx"
  - name: second.example.com
    cert_secret: "second-secret"
    cert_path: "/etc/ssl/second.crt"
`

	cfg := loadConfig(t, document)
	before := loadConfig(t, document)

	err := cfg.ExpandGroups(discardLogger())

	if err.HasMessages() {
		t.Fatalf("a config without groups must not produce validation messages, got %v", err.ErrorMessages)
	}

	if len(cfg.Certificates) != len(before.Certificates) {
		t.Fatalf("expansion changed the certificate list: got %v, want %v", certNames(cfg), certNames(before))
	}

	for index, cert := range cfg.Certificates {
		if !reflect.DeepEqual(cert, before.Certificates[index]) {
			t.Errorf("expansion changed certificate %v: got %+v, want %+v", index, cert, before.Certificates[index])
		}

		if cert.group != "" {
			t.Errorf("certificate %v was tagged with group %q, want no group", cert.Name, cert.group)
		}
	}
}

// TestExpandGroupsWithoutGroupsAllowsDuplicateNames pins the deliberate limit of
// the uniqueness check: a repeated name in a flat list has always been accepted
// and stays accepted, so no config that works today starts failing.
func TestExpandGroupsWithoutGroupsAllowsDuplicateNames(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
certificates:
  - name: same.example.com
    cert_secret: "secret"
    cert_path: "/etc/ssl/one.crt"
  - name: same.example.com
    cert_secret: "secret"
    cert_path: "/etc/ssl/two.crt"
`)

	if err := cfg.ExpandGroups(discardLogger()); err.HasMessages() {
		t.Fatalf("a groupless config must keep its historical behaviour, got %v", err.ErrorMessages)
	}
}

func TestExpandGroupsReportsDuplicateNames(t *testing.T) {
	tests := map[string]struct {
		document string
		want     string
	}{
		"across a group and the flat list": {
			document: `
groups:
  nginx:
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: clash.example.com
certificates:
  - name: clash.example.com
    cert_path: "/etc/ssl/clash.crt"
`,
			want: `Field 'name' for certificate clash.example.com is not unique: certificate names must be unique across all groups and the 'certificates' list!`,
		},
		"within a single group": {
			document: `
groups:
  nginx:
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: clash.example.com
      - name: clash.example.com
`,
			want: `Field 'name' for group 'nginx', certificate 'clash.example.com' is not unique: certificate names must be unique across all groups and the 'certificates' list!`,
		},
		"across two groups": {
			document: `
groups:
  alpha:
    cert_path: "/etc/alpha/{name}.crt"
    certificates:
      - name: clash.example.com
  zulu:
    cert_path: "/etc/zulu/{name}.crt"
    certificates:
      - name: clash.example.com
`,
			want: `Field 'name' for group 'zulu', certificate 'clash.example.com' is not unique: certificate names must be unique across all groups and the 'certificates' list!`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(t, test.document)

			err := cfg.ExpandGroups(discardLogger())

			if !err.HasMessages() {
				t.Fatal("expected a duplicate name to be reported")
			}

			found := false
			for _, message := range err.ErrorMessages {
				if message == test.want {
					found = true
				}
			}

			if !found {
				t.Fatalf("expected message %q, got %v", test.want, err.ErrorMessages)
			}
		})
	}
}

// TestExpandGroupsOrdersGroupsBeforeFlatListDeterministically pins the
// processing order: groups are a map, so without sorting the order would drift
// between runs of the same file.
func TestExpandGroupsOrdersGroupsBeforeFlatListDeterministically(t *testing.T) {
	document := `
groups:
  zulu:
    cert_path: "/etc/zulu/{name}.crt"
    certificates:
      - name: z1.example.com
      - name: z2.example.com
  alpha:
    cert_path: "/etc/alpha/{name}.crt"
    certificates:
      - name: a1.example.com
certificates:
  - name: flat.example.com
    cert_path: "/etc/ssl/flat.crt"
`

	want := []string{"a1.example.com", "z1.example.com", "z2.example.com", "flat.example.com"}

	// repeated because a map iteration order bug shows up only sometimes
	for attempt := 0; attempt < 20; attempt++ {
		cfg := loadConfig(t, document)
		cfg.ExpandGroups(discardLogger())

		got := certNames(cfg)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("expansion order is %v, want %v", got, want)
		}
	}
}

// TestValidationOfGroupedCertificateNamesGroupAndCertificate makes sure a user
// staring at a group of twenty certificates is told which line to fix.
func TestValidationOfGroupedCertificateNamesGroupAndCertificate(t *testing.T) {
	tests := map[string]struct {
		document string
		want     string
	}{
		"blank cert_path": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    certificates:
      - name: b.example.com
`,
			want: `Field 'cert_path' for group 'nginx', certificate 'b.example.com' cannot be blank!`,
		},
		"missing cert_secret": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: b.example.com
`,
			want: `Field 'cert_secret' for group 'nginx', certificate 'b.example.com' is set neither on the certificate nor as 'default_cert_secret', and ` + APIKeyEnvVar + ` is not set either!`,
		},
		"invalid run_on inherited from the group": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    run_on: "on_change"
    certificates:
      - name: b.example.com
`,
			want: `Field 'run_on' for group 'nginx', certificate 'b.example.com' must be one of 'new', 'changed', 'new_or_changed' or 'all', got 'on_change'!`,
		},
		"invalid format inherited from the group": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    key_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    privatecert_path: "/etc/nginx/ssl/{name}.pem"
    privatecert_format: "der"
    certificates:
      - name: b.example.com
`,
			want: `Field 'privatecert_format' for group 'nginx', certificate 'b.example.com' must be one of pem, pkcs12, jks!`,
		},
		"key_secret missing for privatecert_path": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    privatecert_path: "/etc/nginx/ssl/{name}.pem"
    certificates:
      - name: b.example.com
`,
			want: `Field 'key_secret' for group 'nginx', certificate 'b.example.com' is required when 'privatecert_path' is set!`,
		},
		"invalid characters in a grouped name": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: "invalid name"
`,
			want: `Field 'name' for group 'nginx', certificate 'invalid name' may only contain -_. and alphanumeric characters!`,
		},
		"blank name in a group": {
			document: `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - cert_path: "/etc/nginx/ssl/nameless.crt"
`,
			want: `Field 'name' for certificates in group 'nginx' cannot be blank!`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(t, test.document)

			// exactly the order the real run uses: desugaring first, so that
			// validation only ever sees the flat list
			validation := cfg.ExpandGroups(discardLogger())
			validation.Merge(cfg.IsValid())

			found := false
			for _, message := range validation.ErrorMessages {
				if message == test.want {
					found = true
				}
			}

			if !found {
				t.Fatalf("expected message %q, got %v", test.want, validation.ErrorMessages)
			}
		})
	}
}

// TestExpandGroupsResolvesEnvReferencesInGroupSecrets verifies the claim that
// desugaring buys the secret indirection for free: ResolveSecrets never learns
// that the value came from a group.
func TestExpandGroupsResolvesEnvReferencesInGroupSecrets(t *testing.T) {
	t.Setenv("TEST_GROUP_CERT_SECRET", "resolved-cert-secret")
	t.Setenv("TEST_GROUP_KEY_SECRET", "resolved-key-secret")

	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "${TEST_GROUP_CERT_SECRET}"
    key_secret: "${TEST_GROUP_KEY_SECRET}"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: a.example.com
      - name: b.example.com
`)

	cfg.ExpandGroups(discardLogger())

	if err := cfg.ResolveSecrets(discardLogger()); err.HasMessages() {
		t.Fatalf("expected the group references to resolve, got %v", err.ErrorMessages)
	}

	for _, name := range []string{"a.example.com", "b.example.com"} {
		cert := certByName(t, cfg, name)

		if cert.CertificateSecret != "resolved-cert-secret" {
			t.Errorf("cert_secret for %v is %q, want the environment value", name, cert.CertificateSecret)
		}

		if cert.KeySecret != "resolved-key-secret" {
			t.Errorf("key_secret for %v is %q, want the environment value", name, cert.KeySecret)
		}
	}
}

// TestExpandGroupsResolvesFileReferencesInGroupSecrets covers the other
// indirection form for a group-level secret.
func TestExpandGroupsResolvesFileReferencesInGroupSecrets(t *testing.T) {
	secretPath := t.TempDir() + "/group-secret"
	if err := os.WriteFile(secretPath, []byte("secret-from-file\n"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "file:`+secretPath+`"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: a.example.com
`)

	cfg.ExpandGroups(discardLogger())

	if err := cfg.ResolveSecrets(discardLogger()); err.HasMessages() {
		t.Fatalf("expected the group file reference to resolve, got %v", err.ErrorMessages)
	}

	if got := certByName(t, cfg, "a.example.com").CertificateSecret; got != "secret-from-file" {
		t.Errorf("cert_secret is %q, want the trimmed file contents", got)
	}
}

// TestExpandGroupsReportsUnresolvableGroupSecretWithGroupContext makes sure the
// message points at the group even though the group is gone by then.
func TestExpandGroupsReportsUnresolvableGroupSecretWithGroupContext(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
groups:
  nginx:
    cert_secret: "${TEST_GROUP_SECRET_THAT_IS_NOT_SET}"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: a.example.com
`)

	cfg.ExpandGroups(discardLogger())

	err := cfg.ResolveSecrets(discardLogger())

	if !err.HasMessages() {
		t.Fatal("expected an unresolvable group secret to be reported")
	}

	want := `Field 'cert_secret' for group 'nginx', certificate 'a.example.com' could not be resolved: environment variable TEST_GROUP_SECRET_THAT_IS_NOT_SET is not set`
	if err.ErrorMessages[0] != want {
		t.Fatalf("got message %q, want %q", err.ErrorMessages[0], want)
	}
}

// TestExpandGroupsAppliesDefaultSecretsToGroupedCertificates makes sure the
// config-level defaults still reach a certificate whose group sets no secret,
// which only works because expansion happens before resolution.
func TestExpandGroupsAppliesDefaultSecretsToGroupedCertificates(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
default_cert_secret: "default-cert-secret"
default_key_secret: "default-key-secret"
groups:
  nginx:
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: a.example.com
`)

	cfg.ExpandGroups(discardLogger())

	if err := cfg.ResolveSecrets(discardLogger()); err.HasMessages() {
		t.Fatalf("expected resolution to succeed, got %v", err.ErrorMessages)
	}

	cert := certByName(t, cfg, "a.example.com")

	if cert.CertificateSecret != "default-cert-secret" {
		t.Errorf("cert_secret is %q, want the config-level default", cert.CertificateSecret)
	}

	if cert.KeySecret != "default-key-secret" {
		t.Errorf("key_secret is %q, want the config-level default", cert.KeySecret)
	}
}

// TestGroupSecretBeatsConfigDefault pins where a group sits in the precedence
// chain: it is more specific than the config-wide default and less specific
// than the certificate.
func TestGroupSecretBeatsConfigDefault(t *testing.T) {
	cfg := loadConfig(t, `
base_url: "https://certwarden.example.invalid"
default_cert_secret: "default-cert-secret"
groups:
  nginx:
    cert_secret: "group-cert-secret"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    certificates:
      - name: a.example.com
      - name: b.example.com
        cert_secret: "own-cert-secret"
`)

	cfg.ExpandGroups(discardLogger())
	cfg.ResolveSecrets(discardLogger())

	if got := certByName(t, cfg, "a.example.com").CertificateSecret; got != "group-cert-secret" {
		t.Errorf("cert_secret is %q, want the group value to beat default_cert_secret", got)
	}

	if got := certByName(t, cfg, "b.example.com").CertificateSecret; got != "own-cert-secret" {
		t.Errorf("cert_secret is %q, want the certificate value to beat the group value", got)
	}
}

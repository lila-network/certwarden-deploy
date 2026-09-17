package configuration

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// capturingLogger returns a logger that writes every level down to Debug into
// buf. The certificates package has its own copy: an unexported test helper
// cannot cross a package boundary.
func capturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestStringSubstitutionWithPlaceholders tests the string substitution feature.
// It ensures that {name}, {cert_path} and {key_path} get substituted correctly.
func TestStringSubstitutionWithPlaceholders(t *testing.T) {
	cert := CertificateData{
		Name:            "qwer",
		CertificatePath: "/fake/path/{name}",
		KeyPath:         "/fake/path/{name}-key",
		CaPath:          "/fake/path/{name}-ca",
		Action:          ShellAction("./fake action {cert_path} {key_path} {ca_path}"),
	}

	cfg := ConfigFileData{
		Certificates: []CertificateData{cert},
	}

	cfg.SubstituteKeys(nil)

	if cfg.Certificates[0].CertificatePath != "/fake/path/qwer" {
		t.Fail()
		t.Logf(`CertificatePath = %q, want "/fake/path/qwer"`, cfg.Certificates[0].CertificatePath)
	}
	if cfg.Certificates[0].KeyPath != "/fake/path/qwer-key" {
		t.Fail()
		t.Logf(`KeyPath = %q, want "/fake/path/qwer-key"`, cfg.Certificates[0].KeyPath)
	}
	if cfg.Certificates[0].CaPath != "/fake/path/qwer-ca" {
		t.Fail()
		t.Logf(`CaPath = %q, want "/fake/path/qwer-ca"`, cfg.Certificates[0].CaPath)
	}
	if cfg.Certificates[0].Action.Command != "./fake action /fake/path/qwer /fake/path/qwer-key /fake/path/qwer-ca" {
		t.Fail()
		t.Logf(`Action = %q, want "./fake action /fake/path/qwer /fake/path/qwer-key /fake/path/qwer-ca"`, cfg.Certificates[0].Action.Command)
	}
}

// TestStringSubstitutionWithPlaceholders tests the string substitution feature.
// It ensures that if no substitutes are present, the config values are not changed.
func TestStringSubstitutionWithoutPlaceholders(t *testing.T) {
	cert := CertificateData{
		Name:            "qwer",
		CertificatePath: "/fake/path/asd",
		KeyPath:         "/fake/path/asdf-key",
		CaPath:          "/fake/path/asdf-ca",
		Action:          ShellAction("./fake action abcd efgh"),
	}

	cfg := ConfigFileData{
		Certificates: []CertificateData{cert},
	}

	cfg.SubstituteKeys(nil)

	if cfg.Certificates[0].CertificatePath != "/fake/path/asd" {
		t.Fail()
		t.Logf(`CertificatePath = %q, want "/fake/path/asd"`, cfg.Certificates[0].CertificatePath)
	}
	if cfg.Certificates[0].KeyPath != "/fake/path/asdf-key" {
		t.Fail()
		t.Logf(`KeyPath = %q, want "/fake/path/asdf-key"`, cfg.Certificates[0].KeyPath)
	}
	if cfg.Certificates[0].CaPath != "/fake/path/asdf-ca" {
		t.Fail()
		t.Logf(`CaPath = %q, want "/fake/path/asdf-ca"`, cfg.Certificates[0].CaPath)
	}
	if cfg.Certificates[0].Action.Command != "./fake action abcd efgh" {
		t.Fail()
		t.Logf(`Action = %q, want "./fake action abcd efgh"`, cfg.Certificates[0].Action.Command)
	}
}

// TestStringSubstitutionInListAction makes sure the list form gets the same
// placeholders as the string form, per argument.
func TestStringSubstitutionInListAction(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "qwer",
				CertificatePath: "/fake/path/{name}",
				KeyPath:         "/fake/path/{name}-key",
				CaPath:          "/fake/path/{name}-ca",
				Action:          ExecAction("/fake/deploy", "--note", "{name} renewed", "{cert_path}", "{key_path}", "{ca_path}"),
			},
		},
	}

	cfg.SubstituteKeys(nil)

	want := []string{"/fake/deploy", "--note", "qwer renewed", "/fake/path/qwer", "/fake/path/qwer-key", "/fake/path/qwer-ca"}
	got := cfg.Certificates[0].Action.Args

	if len(got) != len(want) {
		t.Fatalf("Action.Args = %v, want %v", got, want)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("Action.Args[%d] = %q, want %q", index, got[index], want[index])
		}
	}

	if cfg.Certificates[0].Action.Command != "" {
		t.Fatalf("Action.Command = %q, want it to stay empty for the list form", cfg.Certificates[0].Action.Command)
	}
}

// {name} must work in the two new path keys exactly like it does in the
// existing ones.
func TestStringSubstitutionInPrivateCertPaths(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:                 "example.com",
				CertificatePath:      "/fake/path/{name}-cert.pem",
				PrivateCertPath:      "/fake/path/{name}.pem",
				PrivateCertChainPath: "/fake/path/{name}-fullchain.pem",
			},
		},
	}

	cfg.SubstituteKeys(nil)

	if got := cfg.Certificates[0].PrivateCertPath; got != "/fake/path/example.com.pem" {
		t.Fatalf(`PrivateCertPath = %q, want "/fake/path/example.com.pem"`, got)
	}

	if got := cfg.Certificates[0].PrivateCertChainPath; got != "/fake/path/example.com-fullchain.pem" {
		t.Fatalf(`PrivateCertChainPath = %q, want "/fake/path/example.com-fullchain.pem"`, got)
	}
}

// Every supported placeholder must resolve, in the action and in every path
// key, so that adding one to the table above cannot silently miss a field.
func TestStringSubstitutionResolvesEveryPlaceholderInEveryField(t *testing.T) {
	today := time.Now().Format("20060102")

	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Certificates: []CertificateData{
			{
				Name:                 "example.com",
				CertificatePath:      "/certs/{name}/{common_name}/{cert_id}/{date}/cert.pem",
				KeyPath:              "/certs/{name}/{date}/key.pem",
				CaPath:               "/certs/{cert_id}/{date}/ca.pem",
				PrivateCertPath:      "/certs/{common_name}/{date}/app.pem",
				PrivateCertChainPath: "/certs/{name}/{date}/app-fullchain.pem",
				Action:               ShellAction("reload {name} {common_name} {cert_id} {date} {base_url} {cert_path} {key_path} {ca_path} {privatecert_path} {privatecertchain_path}"),
			},
		},
	}

	cfg.SubstituteKeys(nil)
	cert := cfg.Certificates[0]

	tests := []struct {
		field string
		got   string
		want  string
	}{
		{"cert_path", cert.CertificatePath, "/certs/example.com/example.com/example.com/" + today + "/cert.pem"},
		{"key_path", cert.KeyPath, "/certs/example.com/" + today + "/key.pem"},
		{"ca_path", cert.CaPath, "/certs/example.com/" + today + "/ca.pem"},
		{"privatecert_path", cert.PrivateCertPath, "/certs/example.com/" + today + "/app.pem"},
		{"privatecertchain_path", cert.PrivateCertChainPath, "/certs/example.com/" + today + "/app-fullchain.pem"},
		{
			"action",
			cert.Action.Command,
			"reload example.com example.com example.com " + today + " https://certwarden.example.com " +
				"/certs/example.com/example.com/example.com/" + today + "/cert.pem " +
				"/certs/example.com/" + today + "/key.pem " +
				"/certs/example.com/" + today + "/ca.pem " +
				"/certs/example.com/" + today + "/app.pem " +
				"/certs/example.com/" + today + "/app-fullchain.pem",
		},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("%s = %q, want %q", test.field, test.got, test.want)
		}
	}
}

// {common_name} and {cert_id} are migration aliases: CertWarden identifies a
// certificate by one value, so both must expand to exactly what {name} does.
func TestStringSubstitutionAliasesResolveToName(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{name}.pem",
				KeyPath:         "/certs/{common_name}.pem",
				CaPath:          "/certs/{cert_id}.pem",
			},
		},
	}

	cfg.SubstituteKeys(nil)
	cert := cfg.Certificates[0]

	if cert.CertificatePath != cert.KeyPath || cert.CertificatePath != cert.CaPath {
		t.Fatalf("aliases diverged: name=%q common_name=%q cert_id=%q", cert.CertificatePath, cert.KeyPath, cert.CaPath)
	}

	if cert.CertificatePath != "/certs/example.com.pem" {
		t.Fatalf("unexpected substitution result: got %q", cert.CertificatePath)
	}
}

// An unrecognised placeholder must be reported by name, together with the
// certificate it belongs to, instead of reaching disk verbatim.
func TestStringSubstitutionWarnsAboutUnresolvedPlaceholder(t *testing.T) {
	var buf bytes.Buffer

	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{foo}/cert.pem",
			},
		},
	}

	cfg.SubstituteKeys(capturingLogger(&buf))

	logs := buf.String()
	if !strings.Contains(logs, "level=WARN") {
		t.Fatalf("expected a warning, got: %s", logs)
	}

	if !strings.Contains(logs, "placeholder={foo}") {
		t.Fatalf("expected the warning to name the placeholder {foo}, got: %s", logs)
	}

	if !strings.Contains(logs, "name=example.com") {
		t.Fatalf("expected the warning to name the certificate, got: %s", logs)
	}

	if !strings.Contains(logs, "field=cert_path") {
		t.Fatalf("expected the warning to name the field, got: %s", logs)
	}
}

// An unresolved placeholder in the action must be reported too, not just in the
// path keys.
func TestStringSubstitutionWarnsAboutUnresolvedPlaceholderInAction(t *testing.T) {
	var buf bytes.Buffer

	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:   "example.com",
				Action: ShellAction("reload {nope}"),
			},
		},
	}

	cfg.SubstituteKeys(capturingLogger(&buf))

	if logs := buf.String(); !strings.Contains(logs, "placeholder={nope}") || !strings.Contains(logs, "field=action") {
		t.Fatalf("expected a warning naming {nope} in the action, got: %s", logs)
	}
}

// An unresolved placeholder must be reported in a list action too. The two
// action forms go through the same expansion, so they must go through the same
// reporting: a typo buried in one argument of a list action is exactly as
// broken as one in a string action, and is easier to miss by eye.
func TestStringSubstitutionWarnsAboutUnresolvedPlaceholderInListAction(t *testing.T) {
	var buf bytes.Buffer

	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{name}/cert.pem",
				Action:          ExecAction("/fake/deploy", "{cert_path}", "{nope}"),
			},
		},
	}

	cfg.SubstituteKeys(capturingLogger(&buf))

	logs := buf.String()
	if !strings.Contains(logs, "placeholder={nope}") || !strings.Contains(logs, "field=action") {
		t.Fatalf("expected a warning naming {nope} in the list action, got: %s", logs)
	}

	// the argument that did resolve must not be reported
	if strings.Contains(logs, "placeholder={cert_path}") {
		t.Fatalf("expected no warning for the resolved {cert_path} argument, got: %s", logs)
	}
}

// A fully resolved config must stay silent: a warning on every run would train
// operators to ignore them.
func TestStringSubstitutionDoesNotWarnWhenEverythingResolves(t *testing.T) {
	var buf bytes.Buffer

	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{name}/cert.pem",
				Action:          ShellAction("reload {cert_path}"),
			},
		},
	}

	cfg.SubstituteKeys(capturingLogger(&buf))

	if logs := buf.String(); strings.Contains(logs, "level=WARN") {
		t.Fatalf("expected no warning for a fully resolved config, got: %s", logs)
	}
}

// A value that was substituted in must never be substituted again, and the
// result must not depend on the order of the replacements. Here cert_path
// legitimately contains the literal text "{key_path}", which a sequential
// replace-one-after-another implementation would expand a second time when it
// reaches {key_path}.
func TestStringSubstitutionDoesNotSubstituteTwice(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{key_path}/cert.pem",
				KeyPath:         "/certs/real-key.pem",
				Action:          ShellAction("reload {cert_path} {key_path}"),
			},
		},
	}

	cfg.SubstituteKeys(nil)

	want := "reload /certs/{key_path}/cert.pem /certs/real-key.pem"
	if got := cfg.Certificates[0].Action.Command; got != want {
		t.Fatalf("Action = %q, want %q (the {key_path} inside cert_path must survive verbatim)", got, want)
	}
}

// The action is expanded from the already expanded paths, so a {name} inside a
// path reaches the action fully resolved.
func TestStringSubstitutionExpandsPathsBeforeAction(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{
				Name:            "example.com",
				CertificatePath: "/certs/{name}/cert.pem",
				Action:          ShellAction("reload {cert_path}"),
			},
		},
	}

	cfg.SubstituteKeys(nil)

	if got := cfg.Certificates[0].Action.Command; got != "reload /certs/example.com/cert.pem" {
		t.Fatalf("Action = %q, want %q", got, "reload /certs/example.com/cert.pem")
	}
}

// {date} is resolved once per run and threaded through, so every field of every
// certificate sees the same value even if the run crosses midnight.
func TestSubstitutionDateIsStableAcrossTheWholeRun(t *testing.T) {
	cfg := ConfigFileData{
		Certificates: []CertificateData{
			{Name: "a.example.com", CertificatePath: "/certs/{date}/a.pem", KeyPath: "/keys/{date}/a.pem"},
			{Name: "b.example.com", CertificatePath: "/certs/{date}/b.pem", Action: ShellAction("reload {date}")},
		},
	}

	cfg.SubstituteKeys(nil)

	want := time.Now().Format("20060102")
	values := []string{
		cfg.Certificates[0].CertificatePath,
		cfg.Certificates[0].KeyPath,
		cfg.Certificates[1].CertificatePath,
		cfg.Certificates[1].Action.Command,
	}

	for _, value := range values {
		if !strings.Contains(value, want) {
			t.Fatalf("expected %q to contain the run date %q", value, want)
		}
	}
}

// The run date enters substitution as a parameter rather than being read from
// the clock per field. This pins that plumbing: a fixed date must be used
// verbatim everywhere.
func TestSubstituteCertificateUsesTheSuppliedRunDate(t *testing.T) {
	cfg := ConfigFileData{}
	cert := CertificateData{
		Name:            "example.com",
		CertificatePath: "/certs/{date}/cert.pem",
		KeyPath:         "/keys/{date}/key.pem",
		Action:          ShellAction("reload {date}"),
	}

	cfg.substituteCertificate(nil, &cert, "20240101")

	if cert.CertificatePath != "/certs/20240101/cert.pem" {
		t.Fatalf("CertificatePath = %q, want %q", cert.CertificatePath, "/certs/20240101/cert.pem")
	}

	if cert.KeyPath != "/keys/20240101/key.pem" {
		t.Fatalf("KeyPath = %q, want %q", cert.KeyPath, "/keys/20240101/key.pem")
	}

	if cert.Action.Command != "reload 20240101" {
		t.Fatalf("Action = %q, want %q", cert.Action.Command, "reload 20240101")
	}
}

// {base_url} comes from the top-level config, not from the certificate.
func TestStringSubstitutionResolvesBaseURL(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		Certificates: []CertificateData{
			{Name: "example.com", Action: ShellAction("notify {base_url}")},
		},
	}

	cfg.SubstituteKeys(nil)

	if got := cfg.Certificates[0].Action.Command; got != "notify https://certwarden.example.com" {
		t.Fatalf("Action = %q, want %q", got, "notify https://certwarden.example.com")
	}
}

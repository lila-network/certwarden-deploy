package configuration

import (
	"testing"
)

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

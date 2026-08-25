package configuration

import (
	"strings"
	"testing"
)

func TestActionUnmarshalsStringForm(t *testing.T) {
	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
    action: "cp a b && systemctl reload nginx"
`))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	action := cfg.Certificates[0].Action

	if action.Command != "cp a b && systemctl reload nginx" {
		t.Fatalf("Action.Command = %q, want %q", action.Command, "cp a b && systemctl reload nginx")
	}

	if action.Args != nil {
		t.Fatalf("Action.Args = %v, want nil for the string form", action.Args)
	}

	if !action.IsSet() || action.IsEmpty() {
		t.Fatalf("expected a set, non-empty action, got set=%v empty=%v", action.IsSet(), action.IsEmpty())
	}
}

func TestActionUnmarshalsListForm(t *testing.T) {
	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
    action:
      - /usr/bin/systemctl
      - reload
      - nginx
`))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	action := cfg.Certificates[0].Action

	if action.Command != "" {
		t.Fatalf("Action.Command = %q, want empty for the list form", action.Command)
	}

	want := []string{"/usr/bin/systemctl", "reload", "nginx"}
	if len(action.Args) != len(want) {
		t.Fatalf("Action.Args = %v, want %v", action.Args, want)
	}

	for index, arg := range want {
		if action.Args[index] != arg {
			t.Fatalf("Action.Args[%d] = %q, want %q", index, action.Args[index], arg)
		}
	}
}

// TestActionListFormKeepsArgumentsWithSpacesIntact guards the whole point of
// the list form: an argument is whatever the user wrote, spaces included.
func TestActionListFormKeepsArgumentsWithSpacesIntact(t *testing.T) {
	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
    action:
      - /usr/local/bin/deploy
      - --note
      - "cert renewed"
`))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	args := cfg.Certificates[0].Action.Args
	if len(args) != 3 {
		t.Fatalf("expected 3 arguments, got %v", args)
	}

	if args[2] != "cert renewed" {
		t.Fatalf("Action.Args[2] = %q, want %q", args[2], "cert renewed")
	}
}

func TestActionUnmarshalsEmptyFormsAsSetButEmpty(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{name: "empty string", yaml: `    action: ""`},
		{name: "whitespace-only string", yaml: `    action: "   "`},
		{name: "empty list", yaml: `    action: []`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cl := FileConfigLoader{}

			cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
` + tc.yaml + "\n"))
			if err != nil {
				t.Fatalf("got error unmarshaling data: %v", err)
			}

			action := cfg.Certificates[0].Action

			if !action.IsSet() {
				t.Fatal("expected a present action key to be reported as set")
			}

			if !action.IsEmpty() {
				t.Fatalf("expected action to be empty, got %q", action.String())
			}
		})
	}
}

func TestActionOmittedIsNeitherSetNorRunnable(t *testing.T) {
	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
`))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	action := cfg.Certificates[0].Action

	if action.IsSet() {
		t.Fatal("expected an omitted action key to be reported as unset")
	}

	if !action.IsEmpty() {
		t.Fatalf("expected an omitted action to be empty, got %q", action.String())
	}
}

func TestActionRejectsUnsupportedYamlForm(t *testing.T) {
	cl := FileConfigLoader{}

	_, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
certificates:
  - name: "example.com"
    action:
      command: /usr/bin/systemctl
`))
	if err == nil {
		t.Fatal("expected a mapping action to be rejected")
	}

	if !strings.Contains(err.Error(), "must be a string or a list of strings") {
		t.Fatalf("expected an explanatory error, got %v", err)
	}
}

func TestActionStringRendersBothForms(t *testing.T) {
	if got := ShellAction("systemctl reload nginx").String(); got != "systemctl reload nginx" {
		t.Fatalf("string form rendered as %q", got)
	}

	if got := ExecAction("/usr/bin/systemctl", "reload", "nginx").String(); got != "/usr/bin/systemctl reload nginx" {
		t.Fatalf("list form rendered as %q", got)
	}
}

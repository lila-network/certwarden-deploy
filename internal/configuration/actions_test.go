package configuration

import "testing"

// TestActionsEnabledDefaultsToTrue is the guard for the one decision in #46
// that cannot be walked back: a config that never mentions actions must keep
// running them. Defaulting to off would silently stop every reload out there.
func TestActionsEnabledDefaultsToTrue(t *testing.T) {
	t.Cleanup(func() { NoActions = false })
	NoActions = false

	cfg := ConfigFileData{}
	if !cfg.ActionsEnabled() {
		t.Fatal("expected actions to be enabled when the config does not mention them")
	}
}

func TestActionsEnabledFromConfig(t *testing.T) {
	t.Cleanup(func() { NoActions = false })

	enabled := true
	disabled := false

	tests := []struct {
		name       string
		configured *bool
		noActions  bool
		want       bool
	}{
		{name: "omitted", configured: nil, noActions: false, want: true},
		{name: "explicitly enabled", configured: &enabled, noActions: false, want: true},
		{name: "explicitly disabled", configured: &disabled, noActions: false, want: false},
		{name: "flag overrides omitted", configured: nil, noActions: true, want: false},
		{name: "flag overrides config-on", configured: &enabled, noActions: true, want: false},
		{name: "flag agrees with config-off", configured: &disabled, noActions: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			NoActions = tc.noActions

			cfg := ConfigFileData{Actions: ActionsConfig{Enabled: tc.configured}}
			if got := cfg.ActionsEnabled(); got != tc.want {
				t.Fatalf("ActionsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestActionsEnabledUnmarshalsFromYaml(t *testing.T) {
	t.Cleanup(func() { NoActions = false })
	NoActions = false

	cl := FileConfigLoader{}

	cfg, err := cl.unmarshalDataToConfig([]byte(`
base_url: "https://example.invalid"
actions:
  enabled: false
certificates:
  - name: "example.com"
`))
	if err != nil {
		t.Fatalf("got error unmarshaling data: %v", err)
	}

	if cfg.Actions.Enabled == nil {
		t.Fatal("expected actions.enabled to be read from the config file")
	}

	if cfg.ActionsEnabled() {
		t.Fatal("expected actions.enabled: false to disable actions")
	}
}

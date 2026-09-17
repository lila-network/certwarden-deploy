package configuration

import (
	"strings"
	"testing"
	"time"
)

func intPtr(v int) *int { return &v }

// TestHTTPSettingsDefaults pins the defaults, including the one that is not a
// zero value: retries default to 2 because losing a certificate to a transient
// 502 until the next timer tick is not something users should have to opt out of.
func TestHTTPSettingsDefaults(t *testing.T) {
	cfg := ConfigFileData{}

	settings, err := cfg.HTTPSettings()
	assertNoMessages(t, err)

	if settings.Timeout != DefaultHTTPTimeout {
		t.Fatalf("unexpected default timeout: got %v want %v", settings.Timeout, DefaultHTTPTimeout)
	}

	if settings.Retries != DefaultHTTPRetries {
		t.Fatalf("unexpected default retries: got %d want %d", settings.Retries, DefaultHTTPRetries)
	}

	if settings.RetryBackoff != DefaultHTTPRetryBackoff {
		t.Fatalf("unexpected default backoff: got %v want %v", settings.RetryBackoff, DefaultHTTPRetryBackoff)
	}
}

// TestHTTPSettingsDefaultTimeoutPreservesOldBehaviour is the compatibility guard
// for the value that used to be hard-coded.
func TestHTTPSettingsDefaultTimeoutPreservesOldBehaviour(t *testing.T) {
	if DefaultHTTPTimeout != 10*time.Second {
		t.Fatalf("the default timeout must stay at the previously hard-coded 10s, got %v", DefaultHTTPTimeout)
	}
}

func TestHTTPSettingsParsesConfiguredValues(t *testing.T) {
	cfg := ConfigFileData{
		HTTP: HTTPConfig{Timeout: "30s", Retries: intPtr(5), RetryBackoff: "2s"},
	}

	settings, err := cfg.HTTPSettings()
	assertNoMessages(t, err)

	if settings.Timeout != 30*time.Second {
		t.Fatalf("unexpected timeout: got %v", settings.Timeout)
	}

	if settings.Retries != 5 {
		t.Fatalf("unexpected retries: got %d", settings.Retries)
	}

	if settings.RetryBackoff != 2*time.Second {
		t.Fatalf("unexpected backoff: got %v", settings.RetryBackoff)
	}
}

// TestHTTPSettingsExplicitZeroRetriesDisablesRetrying is why Retries is a
// pointer: "retries: 0" has to be distinguishable from the key being absent.
func TestHTTPSettingsExplicitZeroRetriesDisablesRetrying(t *testing.T) {
	cfg := ConfigFileData{HTTP: HTTPConfig{Retries: intPtr(0)}}

	settings, err := cfg.HTTPSettings()
	assertNoMessages(t, err)

	if settings.Retries != 0 {
		t.Fatalf("explicit retries: 0 must disable retrying, got %d", settings.Retries)
	}
}

func TestHTTPSettingsRejectsBrokenValues(t *testing.T) {
	tests := []struct {
		name string
		http HTTPConfig
		want string
	}{
		{name: "unparseable timeout", http: HTTPConfig{Timeout: "ten seconds"}, want: "http.timeout"},
		{name: "zero timeout", http: HTTPConfig{Timeout: "0s"}, want: "http.timeout"},
		{name: "negative timeout", http: HTTPConfig{Timeout: "-5s"}, want: "http.timeout"},
		{name: "negative retries", http: HTTPConfig{Retries: intPtr(-1)}, want: "http.retries"},
		{name: "unparseable backoff", http: HTTPConfig{RetryBackoff: "soon"}, want: "http.retry_backoff"},
		{name: "negative backoff", http: HTTPConfig{RetryBackoff: "-1s"}, want: "http.retry_backoff"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ConfigFileData{HTTP: tc.http}

			settings, err := cfg.HTTPSettings()
			message := onlyMessage(t, err)

			if !strings.Contains(message, tc.want) {
				t.Fatalf("expected the message to name %s, got %q", tc.want, message)
			}

			// a rejected field keeps its default, so the settings stay usable
			if settings.Timeout <= 0 {
				t.Fatalf("expected a usable timeout even after a rejection, got %v", settings.Timeout)
			}
		})
	}
}

// TestConfigValidationRejectsBrokenHTTPBlock makes sure the http block is
// checked by IsValid, which is what keeps a broken block from reaching a request.
func TestConfigValidationRejectsBrokenHTTPBlock(t *testing.T) {
	cfg := ConfigFileData{
		BaseURL: "https://certwarden.example.com",
		HTTP:    HTTPConfig{Timeout: "ten seconds", Retries: intPtr(-1)},
	}

	err := cfg.IsValid()
	joined := strings.Join(err.ErrorMessages, "\n")

	for _, want := range []string{"http.timeout", "http.retries"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected IsValid to report %s, got %v", want, err.ErrorMessages)
		}
	}
}

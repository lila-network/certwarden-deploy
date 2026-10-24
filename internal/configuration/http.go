package configuration

import (
	"time"
)

// Defaults for the http block.
//
// DefaultHTTPTimeout is the timeout this tool always had, hard-coded, so the
// default keeps existing setups behaving exactly as they did.
//
// DefaultHTTPRetries is deliberately not 0: the failure this fixes is a
// transient 502 losing a certificate until the next timer tick, which can be
// days away, and that is not something a user should have to opt out of.
const (
	DefaultHTTPTimeout      = 10 * time.Second
	DefaultHTTPRetries      = 2
	DefaultHTTPRetryBackoff = 1 * time.Second
)

// HTTPSettings holds the effective HTTP settings for a run, with every default
// already filled in and every value already resolved and parsed.
//
// It exists so that the packages making requests never have to know about the
// raw config shape, the defaults, or the ${VAR} indirection: they get values
// they can use directly.
type HTTPSettings struct {
	// Headers are sent with every request, on top of the ones this tool owns
	Headers map[string]string

	// Timeout bounds a single attempt
	Timeout time.Duration

	// Retries is the number of attempts made after the first one
	Retries int

	// RetryBackoff is the base for the exponential backoff between attempts
	RetryBackoff time.Duration
}

// DefaultHTTPSettings returns the settings used when the config carries no http
// block at all.
func DefaultHTTPSettings() HTTPSettings {
	return HTTPSettings{
		Timeout:      DefaultHTTPTimeout,
		Retries:      DefaultHTTPRetries,
		RetryBackoff: DefaultHTTPRetryBackoff,
	}
}

// HTTPSettings turns the raw http block into the effective settings, applying
// defaults for everything the user did not set.
//
// Problems are reported the way IsValid reports them, so a broken http block is
// one more line in the same list of config errors rather than a separate failure
// mode. IsValid calls this, which is what keeps a broken block from ever
// reaching a request. A rejected field keeps its default in the returned
// settings, so the result is always usable.
func (c *ConfigFileData) HTTPSettings() (HTTPSettings, ConfigValidationError) {
	err := ConfigValidationError{}
	settings := DefaultHTTPSettings()

	settings.Headers = c.HTTP.Headers

	if c.HTTP.Timeout != "" {
		timeout, parseErr := time.ParseDuration(c.HTTP.Timeout)
		switch {
		case parseErr != nil:
			err.Add(`Field 'http.timeout' is not a valid duration: ` + parseErr.Error())
		case timeout <= 0:
			err.Add(`Field 'http.timeout' must be greater than zero, got "` + c.HTTP.Timeout + `"!`)
		default:
			settings.Timeout = timeout
		}
	}

	if c.HTTP.Retries != nil {
		if *c.HTTP.Retries < 0 {
			err.Add(`Field 'http.retries' cannot be negative!`)
		} else {
			settings.Retries = *c.HTTP.Retries
		}
	}

	if c.HTTP.RetryBackoff != "" {
		backoff, parseErr := time.ParseDuration(c.HTTP.RetryBackoff)
		switch {
		case parseErr != nil:
			err.Add(`Field 'http.retry_backoff' is not a valid duration: ` + parseErr.Error())
		case backoff < 0:
			err.Add(`Field 'http.retry_backoff' cannot be negative!`)
		default:
			settings.RetryBackoff = backoff
		}
	}

	return settings, err
}

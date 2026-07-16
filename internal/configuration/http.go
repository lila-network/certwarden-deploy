package configuration

// HTTPSettings holds the effective HTTP settings for a run, with every default
// already filled in and every value already resolved.
//
// It exists so that the packages making requests never have to know about the
// raw config shape, the defaults, or the ${VAR} indirection: they get values
// they can use directly.
type HTTPSettings struct {
	// Headers are sent with every request, on top of the ones this tool owns
	Headers map[string]string
}

// DefaultHTTPSettings returns the settings used when the config carries no http
// block at all. They reproduce the behaviour this tool had before the block
// existed.
func DefaultHTTPSettings() HTTPSettings {
	return HTTPSettings{}
}

// HTTPSettings turns the raw http block into the effective settings, applying
// defaults for everything the user did not set.
//
// Problems are reported the same way IsValid reports them, so a broken http
// block is one more line in the same list of config errors rather than a
// separate failure mode. IsValid calls this, which is what stops a broken block
// from ever reaching a request.
func (c *ConfigFileData) HTTPSettings() (HTTPSettings, ConfigValidationError) {
	err := ConfigValidationError{}
	settings := DefaultHTTPSettings()

	settings.Headers = c.HTTP.Headers

	return settings, err
}

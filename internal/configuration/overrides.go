package configuration

import (
	"log/slog"
)

// ApplyOverrides folds the CLI overrides into the loaded config, so that
// everything downstream only ever sees one effective value per setting.
//
// The overall precedence is CLI flag > environment variable > config file. The
// flag wins because it is the most explicit thing the user can say: they typed
// it for this one run.
//
// Only the name of the flag that took effect is logged. --base-url is not a
// secret and is logged with its value; --api-key is applied in ResolveSecrets,
// where the rest of the secret precedence chain lives, and its value is never
// logged anywhere.
func (c *ConfigFileData) ApplyOverrides(logger *slog.Logger) {
	if BaseURLOverride != "" {
		logger.Debug("Overriding config file value from CLI flag", "flag", "--base-url", "base_url", BaseURLOverride)
		c.BaseURL = BaseURLOverride
	}
}

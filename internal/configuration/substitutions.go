package configuration

import (
	"log/slog"
	"strings"
)

func (c *ConfigFileData) SubstituteKeys(logger *slog.Logger) {
	for index, cert := range c.Certificates {
		c.Certificates[index].CertificatePath = strings.ReplaceAll(cert.CertificatePath, "{name}", c.Certificates[index].Name)
		c.Certificates[index].KeyPath = strings.ReplaceAll(cert.KeyPath, "{name}", c.Certificates[index].Name)
		c.Certificates[index].CaPath = strings.ReplaceAll(cert.CaPath, "{name}", c.Certificates[index].Name)

		// The paths above are already substituted at this point, so the path
		// placeholders below expand to the final on-disk paths.
		c.Certificates[index].Action = cert.Action.substitute(func(s string) string {
			s = strings.ReplaceAll(s, "{name}", c.Certificates[index].Name)
			s = strings.ReplaceAll(s, "{cert_path}", c.Certificates[index].CertificatePath)
			s = strings.ReplaceAll(s, "{key_path}", c.Certificates[index].KeyPath)
			s = strings.ReplaceAll(s, "{ca_path}", c.Certificates[index].CaPath)
			return s
		})
	}
}

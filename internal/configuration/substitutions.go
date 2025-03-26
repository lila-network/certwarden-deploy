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

		c.Certificates[index].Action = strings.ReplaceAll(cert.Action, "{name}", c.Certificates[index].Name)
		c.Certificates[index].Action = strings.ReplaceAll(c.Certificates[index].Action, "{cert_path}", c.Certificates[index].CertificatePath)
		c.Certificates[index].Action = strings.ReplaceAll(c.Certificates[index].Action, "{key_path}", c.Certificates[index].KeyPath)
		c.Certificates[index].Action = strings.ReplaceAll(c.Certificates[index].Action, "{ca_path}", c.Certificates[index].CaPath)
	}
}

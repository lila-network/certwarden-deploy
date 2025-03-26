package certificates

type FileType int

const (
	CertificateFile FileType = iota
	KeyFile
	CaCertificateFile
)

func (file FileType) String() string {
	switch file {
	case CertificateFile:
		return "certificate"
	case KeyFile:
		return "key"
	case CaCertificateFile:
		return "ca"
	}

	return "unknown"
}

// GenericCertificate is a generic container to enable us to
// handle both certificates and keys with one function
type GenericCertificate struct {
	Name     string
	FilePath string
	Secret   string

	// Type of the certificate
	Type FileType

	// Bytes fetched from the server
	serverBytes []byte

	// Bytes fetched from disk
	diskBytes []byte
}

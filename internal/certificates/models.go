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

// A Certificate combines certificate, key and CA data in one struct
type Certificate struct {
	Certificate          *CertificateData
	Key                  *CertificateData
	CertificateAuthority *CertificateData
	RolloutAction        string
	NeedsAction          bool
}

// CertificateData is a generic container to enable us to
// handle both certificates and keys with one function
type CertificateData struct {
	Name     string
	FilePath string
	Secret   string

	// Type of the certificate
	Type FileType

	// Bytes fetched from the server
	ServerBytes []byte

	// Bytes fetched from disk
	DiskBytes []byte
}

package certificates

// GenericCertificate is a generic container to enable us to
// handle both certificates and keys with one function
type GenericCertificate struct {
	Name     string
	FilePath string
	Secret   string

	// True if key, false if certificate
	IsKey bool

	// Bytes fetched from the server
	serverBytes []byte

	// Bytes fetched from disk
	diskBytes []byte
}

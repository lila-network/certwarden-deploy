package constants

var Version string

var UserAgent = "certwarden-deploy/" + Version + " +https://github.com/lila-network/certwarden-deploy"

const CertificateApiPath = "/certwarden/api/v1/download/certificates/"
const KeyApiPath = "/certwarden/api/v1/download/privatekeys/"
const CaCertificateApiPath = "/certwarden/api/v1/download/certrootchains/"

// PrivateCertApiPath serves the certificate and its private key in one file.
const PrivateCertApiPath = "/certwarden/api/v1/download/privatecerts/"

// PrivateCertChainApiPath serves the certificate, its private key and the CA
// chain in one file.
const PrivateCertChainApiPath = "/certwarden/api/v1/download/privatecertchains/"

const ApiKeyHeaderName = "X-API-Key"

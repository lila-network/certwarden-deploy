package constants

var Version string

var UserAgent = "certwarden-deploy/" + Version + " +https://code.lila.network/adoralaura/certwarden-deploy"

const CertificateApiPath = "/certwarden/api/v1/download/certificates/"
const KeyApiPath = "/certwarden/api/v1/download/privatekeys/"
const ApiKeyHeaderName = "X-API-Key"

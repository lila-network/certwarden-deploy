package cli

// starterConfig is what `config init` writes.
//
// It is deliberately much shorter than examples/config.yaml: a starter file is
// meant to be filled in, and a new user reading about jks containers and
// Cloudflare Access headers before their first certificate is a new user who
// has not deployed a certificate yet. Every key that is not required is
// commented out and points at the docs.
const starterConfig = `# certwarden-deploy configuration
# Full reference: https://certwarden-deploy.adora.codes/configuration/

# Base URL of the CertWarden instance, including the scheme.
# required
base_url: "https://certwarden.example.com"

# Set to true if the CertWarden instance uses a self-signed certificate.
# default is false
disable_certificate_validation: false

# API keys for every certificate below that does not set its own.
# Instead of a literal key these may reference the value:
#   "${CERTWARDEN_CERT_SECRET}"                 read from the environment
#   "file:/run/credentials/cw.service/cert"     read from a file, trimmed
# The CERTWARDEN_API_KEY environment variable is the last fallback.
# optional
# default_cert_secret: "${CERTWARDEN_CERT_SECRET}"
# default_key_secret: "${CERTWARDEN_KEY_SECRET}"

certificates:

    # The certificate name in CertWarden. May contain a-zA-Z0-9._-
    # required
  - name: "example.com"

    # API key for the certificate, and where to write it.
    # required, unless a default or CERTWARDEN_API_KEY is set
    cert_secret: "replace-me"
    cert_path: "/etc/ssl/example.com/fullchain.pem"

    # API key for the private key, and where to write it.
    # optional: omit key_path to not download the key at all
    key_secret: "replace-me-too"
    key_path: "/etc/ssl/example.com/privkey.pem"

    # Where to write the CA chain.
    # optional
    # ca_path: "/etc/ssl/example.com/chain.pem"

    # Command to run after this certificate changed.
    # A string is run through /bin/sh, so pipes and && work. A list is executed
    # directly, without a shell.
    # The paths above and the command support {name}, {date}, {base_url} and,
    # in the command, {cert_path}, {key_path} and {ca_path}.
    # optional
    # action: "/usr/bin/systemctl reload nginx"

    # When to run the action: new, changed, new_or_changed or all.
    # default is new_or_changed
    # run_on: "new_or_changed"

# Tunes how requests are made. Every key is optional.
# http:
#   timeout: 10s
#   retries: 2
#   retry_backoff: 1s
#   headers:
#     CF-Access-Client-Id: "${CF_ACCESS_CLIENT_ID}"
`

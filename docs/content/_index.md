---
title: CertWarden-Deploy
type: docs
---

[CertWarden](https://www.certwarden.com/) is a self-hosted Centralized ACME Certificate Management platform. With it you can manage and aquire Let's Encrypt certificates.

However, to deploy them to your hosts, for now there only was a docker client, and that was too bloated for me.

So I built `certwarden-deploy`, a dependency-less binary that can run via crontab/systemd timers and that can fetch new certificates and run actions after new certificates got rolled out.

## Quick Start

Installation of the required CertWarden instance is out of scope of this documentation. For detailed instructions regarding CertWarden, please visit [it's documentation](https://www.certwarden.com/docs/introduction/)


To quickly get started with `certwarden-deploy`, just download the binary...

```shell
# this downloads certwarden-deploy version 0.2.1
# to /usr/local/bin/certwarden-deploy
sudo wget https://code.lila.network/adoralaura/certwarden-deploy/releases/download/0.2.1/certwarden-deploy-0.2.1-linux-amd64 -O /usr/local/bin/certwarden-deploy

sudo chmod +x /usr/local/bin/certwarden-deploy
```

... fill out the config file...
```shell
vi /etc/certwarden-deploy/config.yaml
```
```yaml
# Base URL of the CertWarden instance
# required
base_url: "https://certwarden.example.com"

# Set this to true if your CertWarden instance does not have a publicly trusted 
# TLS certificate (e.g. it has a self signed one)
# default is false
disable_certificate_validation: false

# define all managed certificates here
certificates:

    # name is a unique identifier that must start and end with an alphanumeric character, 
    # and can contain the following characters: a-zA-Z0-9._-
    # required
  - name: test-certificate.example.com

    # Contains the API-Key to fetch the certificate from the server
    # required
    cert_secret: examplekey_notvalid_hrzjGDDw8z

    # path where to save the certificate
    # required
    cert_path: "/path/to/test-certificate.example.com-cert.pem"

    # Contains the API-Key to fetch the private key from the server
    # required
    key_secret: examplekey_notvalid_hrzbbDDw8z

    # path where to save the private key
    # required
    key_path: "/path/to/test-certificate.example.com-key.pem"

    # action to run when certificate was updated or --force is on
    action: "/usr/bin/systemd reload caddy"
```

... and run it!
```shell
certwarden-deploy -v
```
## Contributing

I use my own [Forgejo](https://forgejo.org/) Instance [code.lila.network](https://code.lila.network) to manage issues, pull requests and CI/CD.

* If you have a trivial fix or improvement, go ahead and send a diff to the maintainer(s) of this repository (see
  [MAINTAINERS.md](https://code.lila.network/adoralaura/certwarden-deploy/src/branch/main/MAINTAINERS.md)).

* If you plan to do something more involved, first please [send me a mail]( mailto:dev@lauka.net?subject=%5Bcertwarden-deploy%5D)mso I can create an account for you.

### Non-development Contibutions

The best way to help without speaking a lot of Go would be to share your
configuration, setup, and tips. If you have something
that works and is not in the repository, please pay it forward and
share what works.

## Changelog
You can find the Changelog here: [Changelog](https://code.lila.network/adoralaura/certwarden-deploy/src/branch/main/CHANGELOG.md)

## License
`certwarden-deploy` is available under the MIT license. See the [LICENSE](https://code.lila.network/adoralaura/certwarden-deploy/src/branch/main/LICENSE) file for more info.

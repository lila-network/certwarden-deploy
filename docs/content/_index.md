---
title: Introduction
type: docs
---

## CertWarden

[CertWarden](https://www.certwarden.com/) is a self-hosted Centralized ACME Certificate Management platform. With it you can manage and aquire Let's Encrypt certificates.

However, to deploy them to your hosts, for now there only was a docker client, and that was too bloated for me.

So I built `certwarden-deploy`, a dependency-less binary that can run via crontab/systemd timers and that can fetch new certificates and run actions after new certificates got rolled out.

## Quick Start

Installation of the required CertWarden instance is out of scope of this documentation. For detailed instructions regarding CertWarden, please visit [it's documentation](https://www.certwarden.com/docs/introduction/)


To quickly get started with `certwarden-deploy`, just download the binary...

```shell
# this downloads certwarden-deploy version 0.1.1 
# to /usr/local/bin/certwarden-deploy
sudo wget https://code.lila.network/adoralaura/certwarden-deploy/releases/download/0.1.1/certwarden-deploy-0.1.1-linux-amd64 -O /usr/local/bin/certwarden-deploy

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

    api_key: examplekey_notvalid_hrzjGDDw8z

    # action to run when certificate was updated or --force is on
    action: "/usr/bin/systemd reload caddy"

    # path where to save the certificate
    # required
    file_path: "/path/to/test-certificate.example.com-cert.pem"
```

... and run it!
```shell
certwarden-deploy -v
```
## Contributing

I use my own [Forgejo Instance](https://code.lila.network) to manage issues and pull requests.

* If you have a trivial fix or improvement, go ahead and create a pull request,
  addressing (with `@...`) the maintainer of this repository (see
  [MAINTAINERS.md](MAINTAINERS.md)) in the description of the pull request.

* If you plan to do something more involved, first please [send me a mail]( mailto:dev@lauka.net?subject=%5Bcertwarden-deploy%5D).

### What to contribute

The best way to help without speaking a lot of Go would be to share your
configuration, alerts, dashboards, and recording rules. If you have something
that works and is not in the repository, please pay it forward and
share what works.

## Changelog
You can find the Changelog here: [Changelog](https://code.lila.network/adoralaura/certwarden-deploy/src/branch/main/CHANGELOG.md)

## License
`certwarden-deploy` is available under the MIT license. See the [LICENSE](https://code.lila.network/adoralaura/certwarden-deploy/src/branch/main/LICENSE) file for more info.

# certwarden-deploy

[![Please don't upload to GitHub](https://nogithub.codeberg.page/badge.svg)](https://nogithub.codeberg.page)

This is a simple binary to deploy certificates from a [CertWarden](https://www.certwarden.com/) instance.

## Quick Start

Installation of the required CertWarden instance is out of scope of this documentation. For detailed instructions regarding CertWarden, please visit [it's documentation](https://www.certwarden.com/docs/introduction/)

Before building the project, ensure you have the following installed:

- make: A build automation tool
- Go: Version 1.22 or later

To build the project, first clone the projects git repository, then navigate to the project's root directory and run the following command:

```shell
make build
```

This command will generate the `certwarden-deploy` binary in the `bin/` folder.

Then fill out the config file...

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

The source code for `certwarden-deploy` is hosted on my own GitLab Instance [gitlab.lila.network](https://gitlab.lila.network) to manage issues, pull requests and CI/CD.

- If you have a trivial fix or improvement, go ahead and send a diff to the maintainer(s) of this repository (see
  [MAINTAINERS.md](https://gitlab.lila.network/lila-network/certwarden-deploy/-/blob/main/MAINTAINERS.md)).

- If you plan to do something more involved, first please [send me a mail](mailto:adora@lila.network?subject=%5Bcertwarden-deploy%5D) so I can help you there.

### Non-development Contibutions

The best way to help without speaking a lot of Go would be to share your
configuration, setup, and tips. If you have something
that works and is not in the repository, please pay it forward and
share what works.

## Changelog

You can find the Changelog here: [Changelog](https://gitlab.lila.network/lila-network/certwarden-deploy/-/blob/main/CHANGELOG.md)

## License

`certwarden-deploy` is available under the MIT license. See the [LICENSE](https://gitlab.lila.network/lila-network/certwarden-deploy/-/blob/main/LICENSE) file for more info.

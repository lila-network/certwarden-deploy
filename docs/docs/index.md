# Quickstart

[CertWarden](https://www.certwarden.com/) is a self-hosted ACME certificate management platform. `certwarden-deploy` is a small companion binary that pulls certificates from a CertWarden instance and writes them to local disk without requiring Docker.

It is designed for scheduled execution through `systemd` timers or cron:

- fetch certificate, private key, and optional CA chain data from CertWarden
- compare the downloaded content with the files already on disk
- only replace files when the content changed, or when `--force` is used
- run an optional follow-up command after a rollout

`certwarden-deploy` writes changed files atomically, creates missing parent directories, and preserves the existing file mode when updating a file in place.

## Quick Start

Installation of the CertWarden server itself is out of scope here. If you still need that piece, start with the [official CertWarden documentation](https://www.certwarden.com/docs/introduction/).

1. Install the `certwarden-deploy` binary as described on the [Installation](installation.md) page.
2. Create `/etc/certwarden-deploy/config.yaml`.
3. Run a dry run first to verify paths, API keys, and connectivity.
4. Run it normally or wire it into the bundled `systemd` timer examples.

Example configuration:

```yaml
base_url: "https://certwarden.example.com"
disable_certificate_validation: false

certificates:
  - name: "example.com"
    cert_secret: "cw_cert_api_key"
    cert_path: "/etc/certs/{name}/fullchain.pem"
    key_secret: "cw_key_api_key"
    key_path: "/etc/certs/{name}/privkey.pem"
    ca_path: "/etc/certs/{name}/chain.pem"
    action: "/usr/bin/systemctl reload caddy"
```

Test it without writing files:

```shell
certwarden-deploy --dry-run --config /etc/certwarden-deploy/config.yaml
```

Then run the actual rollout:

```shell
certwarden-deploy --config /etc/certwarden-deploy/config.yaml
```

The [Configuration](configuration.md) page documents every field, placeholder, and CLI flag in more detail.

## Contributing

I use my own Forgejo Instance [code.lila.network](https://github.com/lila-network/certwarden-deploy) to manage issues, pull requests and CI/CD.

- If you have a trivial fix or improvement, go ahead and send a diff to the maintainer(s) of this repository (see
  [MAINTAINERS.md](https://github.com/lila-network/certwarden-deploy/src/branch/main/MAINTAINERS.md)).

- If you plan to do something more involved, first please [send me a mail](mailto:me@adora.codes?subject=%5Bcertwarden-deploy%5D) so I can create an account for you.

### Non-development Contibutions

The best way to help without speaking a lot of Go would be to share your
configuration, setup, and tips. If you have something
that works and is not in the repository, please pay it forward and
share what works.

## Changelog

You can find the Changelog here: [Changelog](https://github.com/lila-network/certwarden-deploy/src/branch/main/CHANGELOG.md)

## License

`certwarden-deploy` is available under the MIT license. See the [License page](license.md) for more info.

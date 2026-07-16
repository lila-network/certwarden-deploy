# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Unit and E2E tests
- Config file is searched in `./certwarden-deploy.yaml`, `$XDG_CONFIG_HOME/certwarden-deploy/config.yaml` and `/etc/certwarden-deploy/config.yaml` when `--config` is not set
- Server response body is now surfaced on non-success status codes
- `action` accepts a list of arguments, which is executed directly without a shell (#29)
- per-certificate `run_on` selects when the action runs: `new`, `changed`, `new_or_changed` (default) or `all` (#31)
- `actions.enabled` and `--no-actions` deploy the files but skip every post-rollout action. Actions stay on by default (#46)
- every run now ends with a summary record counting new, changed, unchanged, failed, action_failed and action_skipped certificates (#30)
- Support for the `privatecerts` and `privatecertchains` download endpoints via the optional `privatecert_path` and `privatecertchain_path` keys (#4)

### Changed

- Migrated repository to GitHub
- file write procedure got more resilient
- a string `action` is now run through `/bin/sh -c`, so pipes, redirects, `&&` and quoting work (#29)

    Previously the string was split on whitespace and exec'd directly, so `action: "cp a b && systemctl reload nginx"`
    silently ran `cp` with `&&` as an argument. Single commands keep working unchanged. A command that does not exist
    now fails with the shell's exit code 127 instead of a "file not found" error.

- an `action` key that is present but blank is now a configuration error instead of a silent no-op (#29)
- a rollout now tells a first deployment apart from an update, so certificates are counted as new instead of changed (#31)

### Fixed

- Certificate rollout failures now exit 2, post-rollout action failures exit 3 (#25)

    This is a behaviour change: a deployment that silently half-failed exited 0 before
    and exits non-zero now, so a previously green timer may start alerting.

- post-rollout action output is no longer discarded, stdout/stderr and the exit code are now logged (#26)
- A certificate and its key are now rolled out as a unit: if any artefact fails, none of them are written, so a new certificate can no longer end up next to the old key (#28)

## [0.2.4] - 2025-07-09

### Changed

- updated go to 1.24

### Fixed

- Upstream-Error from certwarden resulted in malformed certificates (#6)

## [0.2.3] - 2025-03-26

### Changed

- CA Certificates can now be rolled out too (thanks to Arslan 'ArsNotFound' Sakhapov)

### Added

- Documentation how string substitutions work within the config file.

## [0.2.2] - 2024-07-30

### Changed

- changed the way the version string is handled internally
- CI pipeline changed
- documentation is now more sophisticated and has a new theme

### Added

- Makefile

## [0.2.1] - 2024-07-12

### Fixed

- Configuration validation did not work as intended

### Changed

- updated example config file

## [0.2.0] - 2024-07-11

### ⚠️ Breaking Changes

- Config file syntax was changed to accomodate both private and public key deployment for certificates.

    This change is __NOT__ backwards compatible!
    The following yaml keys were changed/added:
  - `api_key`: changed to `cert_secret`
  - `file_path`: changed to `cert_path`
  - added keys: `key_secret`, `key_path`

### Changed

- config file syntax to enable deployment of private keys too
- refactor code

## [0.1.1] - 2024-07-03

### Fixed

- Fixed handling of the post certificate action

## [0.1.0] - 2024-07-03

### Added

- Minimal viable application
- some documentation

[unreleased]: https://github.com/lila-network/certwarden-deploy/compare/0.2.4...HEAD
[0.2.4]: https://github.com/lila-network/certwarden-deploy/compare/0.2.3..0.2.4
[0.2.3]: https://github.com/lila-network/certwarden-deploy/compare/0.2.2..0.2.3
[0.2.2]: https://github.com/lila-network/certwarden-deploy/compare/0.2.1..0.2.2
[0.2.1]: https://github.com/lila-network/certwarden-deploy/compare/0.2.0..0.2.1
[0.2.0]: https://github.com/lila-network/certwarden-deploy/compare/0.1.1..0.2.0
[0.1.1]: https://github.com/lila-network/certwarden-deploy/compare/0.1.0..0.1.1
[0.1.0]: https://github.com/lila-network/certwarden-deploy/tree/0.1.0

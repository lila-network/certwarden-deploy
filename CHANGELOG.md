# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.2.0] - 2024-07-11
### ⚠️ Breaking Changes
- Config file syntax was changed to accomodate both private and public key for certificates. 

    This change is __NOT__ backwards compatible!
    The following yaml keys were changed/added:
    - `api_key`: changed to `cert_secret`
    - `file_path`: changed to `cert_path`
    - added keys: `key_secret`, `key_path`

### Changed
- config file syntax to accomodate private keys too
- refactor code

## [0.1.1] - 2024-07-03

### Fixed
- Fixed handling of the post certificate action

## [0.1.0] - 2024-07-03

### Added
- Minimal viable application
- some documentation


[unreleased]: https://code.lila.network/adoralaura/certwarden-deploy/compare/0.2.0...HEAD
[0.2.0]: https://code.lila.network/adoralaura/certwarden-deploy/compare/0.1.1...0.2.0
[0.1.1]: https://code.lila.network/adoralaura/certwarden-deploy/compare/0.1.0...0.1.1
[0.1.0]: https://code.lila.network/adoralaura/certwarden-deploy/releases/tag/0.1.0

---
title: Installation
weight: 10
---

## Pre-built Binaries

Pre-built binaries are published at the [download page](https://static-cdn.lila.network/releases/certwarden-deploy/).

Pick the archive or binary that matches your operating system and CPU architecture. On Linux, `uname -m` is usually enough to confirm the architecture name of the current host.

Install the binary somewhere on your `PATH`, for example:

```shell
sudo install -m 0755 certwarden-deploy /usr/local/bin/certwarden-deploy
```

Then verify that it starts:

```shell
certwarden-deploy --version
certwarden-deploy --help
```

## Build from Source

### Prerequisites

- make: A build automation tool
- Go: Version 1.24 or later

### Compiling

Clone the repository, change into the project root, and build the binary:

```shell
make build
```

This creates `bin/certwarden-deploy`.

## First Run

By default, `certwarden-deploy` reads its configuration from `/etc/certwarden-deploy/config.yaml`.

Create that file, or point the binary at a different path with `--config`:

```shell
certwarden-deploy --dry-run --config /path/to/config.yaml
```

Running a dry run first is a good way to confirm:

- the CertWarden URL is reachable
- the API keys are valid
- the file paths resolve to the locations you expect
- any placeholder substitutions expand the way you intended

## Automatic Renewals with systemd

The repository ships example unit files in [`examples/`](https://github.com/lila-network/certwarden-deploy/src/branch/main/examples):

- `examples/certwarden-deploy.service`
- `examples/certwarden-deploy.timer`

Customize them for your environment before installing them:

- adjust `ExecStart` to the real binary path
- set `User=` and `Group=` if you do not want to run as `root`
- update the timer schedule if the default cadence does not fit your setup

Once adjusted, place them in `/etc/systemd/system/` and enable the timer:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now certwarden-deploy.timer
```

The bundled timer runs every Saturday at `04:00:00` with a randomized delay of up to two hours. `Persistent=true` means a missed run will be started after the machine comes back online.

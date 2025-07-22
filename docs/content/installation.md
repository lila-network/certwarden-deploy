---
title: Installation
weight: 10
---

## Getting pre-built Binaries
You can also get pre-built binaries from the [download page](https://static-cdn.lila.network/releases/certwarden-deploy/). Make sure you get the binaries fitting your architecture!

## Building the Project from Source
### Prerequisites

Before building the project, ensure you have the following installed:

- make: A build automation tool
- Go: Version 1.24 or later

### Compiling

To build the project, first clone the projects git repository, then navigate to the project's root directory and run the following command:

```shell
make build
```

This command will generate the `certwarden-deploy` binary in the `bin/` folder.

## Setting up automatic Certificate Renewals

Although not required for `certwarden-deploy` to work, it's highly recommended to set up automatic renewals for `certwarden-deploy`, so that you don't need to worry about rolling out your certificates every time they get renewed by CertWarden.

To do that, there are example `systemd` Service and Timer files included in the `examples/` directory of the `certwarden-deploy` repository.

Please make sure to customize them to your requirements (path to `certwarden-deploy` binary, user and group, execution interval...) and then drop them into the `/etc/systemd/system/` directory, then enable the timer with `systemctl enable --now certwarden-deploy.timer`

If you kept the example schedule, `certwarden-deploy` will run every saturday at ~4am.

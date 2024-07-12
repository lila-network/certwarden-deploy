---
title: Introduction
type: docs
---

# Introduction

## CertWarden

[CertWarden](https://www.certwarden.com/) is a self-hosted Centralized ACME Certificate Management platform. With it you can manage and aquire Let's Encrypt certificates.

However, to deploy them to your hosts, for now there only was a docker client, and that was too bloated for me.

So I built `certwarden-deploy`, a dependency-less binary that can run via crontab/systemd timers and that can fetch new certificates and run actions after new certificates got rolled out.

## Quick Start

Installation of the required CertWarden instance is out of scope of this documentation. For detailed instructions regarding CertWarden, please visit [it's documentation](https://www.certwarden.com/docs/introduction/)


To quickly get started with `certwarden-deploy`, just download the binary and run it.

```shell
# this downloads certwarden-deploy version 0.1.1 
# to /usr/local/bin/certwarden-deploy
sudo wget https://code.lila.network/adoralaura/certwarden-deploy/releases/download/0.1.1/certwarden-deploy-0.1.1-linux-amd64 -O /usr/local/bin/certwarden-deploy

sudo chmod +x /usr/local/bin/certwarden-deploy
```

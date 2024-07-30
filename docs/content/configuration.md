---
title: Configuration
weight: 20
---


This document describes how to configure `certwarden-deploy` and which certificates should be managed by it. The configuration file uses the [YAML format](https://yaml.org/) for a human-readable and easy-to-maintain structure.

## certwarden-deploy CLI Options
```plaintext
$ ./certwarden-deploy --help
certwarden-deploy is a CLI utility to deploy certificates managed by CertWarden.
Configuration is handled by a single YAML file, so you can get started quickly.

For more information on how to configure this tool, visit the docs at https://certwarden-deploy.adora.codes

Usage:
  certwarden-deploy [flags]

Flags:
  -c, --config string   Path to config file (default is /etc/certwarden-deploy/config.yaml) (default "/etc/certwarden-deploy/config.yaml")
  -d, --dry-run         Just show the would-be changes without changing the file system (turns on verbose logging)
  -f, --force           Force overwriting and execution action to occur, regardless if certificate already exists
  -h, --help            help for certwarden-deploy
  -q, --quiet           Disable any logging (if both -q and -v are set, quiet wins)
  -v, --verbose         Enable verbose logging
      --version         version for certwarden-deploy
```

## Configuration File Options

`base_url` (required):  
This string specifies the base URL of your CertWarden instance.

`disable_certificate_validation` (optional, default: false):  
    This boolean flag indicates whether to disable certificate validation for the CertWarden instance. Set this to true only if your CertWarden instance uses a self-signed certificate and you trust it explicitly. **Disabling validation weakens security, so use it with caution.**

`certificates:` (required):
    This is a list that defines each certificate to be managed.
    Each certificate definition is a nested YAML block with the following properties:

Each certificate configuration consists of:

`name` (required):
This string is a unique identifier for the certificate and must be the same as in you CertWarden instance.
It must start and end with an alphanumeric character and can contain letters (a-zA-Z), numbers (0-9), underscore (_), hyphen (-), and period (.).

`cert_secret` (required):  
This string holds the API key used to fetch the certificate data from the CertWarden server.

`cert_path` (required):  
This string defines the file path where the downloaded certificate will be saved.

`key_secret` (required):  
This string holds the API key used to fetch the private key data from the CertWarden server.

`key_path` (required):  
This string defines the file path where the downloaded private key will be saved.

`action` (optional):  
This string specifies a command to run after a certificate is updated or when the --force flag is used during execution.  
The example uses a systemd reload command for the popular reverse proxy named "caddy".

Example Configuration:
```yaml
# Base URL of the CertWarden instance
base_url: "https://certwarden.example.com"

# Disable certificate validation (not recommended for production)
disable_certificate_validation: false

# Define all managed certificates here
certificates:
  - name: test-certificate.example.com
    cert_secret: examplekey_notvalid_hrzjGDDw8z  # Replace with your actual key
    cert_path: "/path/to/test-certificate.example.com-cert.pem"
    key_secret: examplekey_notvalid_hrzbbDDw8z  # Replace with your actual key
    key_path: "/path/to/test-certificate.example.com-key.pem"
    action: "/usr/bin/systemctl reload caddy"
```
Use code with caution.

## Notes
- This documentation assumes you have a basic understanding of YAML syntax. Resources for learning YAML are readily available online.
- Replace placeholder values like `examplekey_notvalid_hrzjGDDw8z` with your actual API keys.

---
title: Configuration
weight: 20
---

`certwarden-deploy` reads a single YAML file that describes which certificates to fetch from CertWarden and where to write them on disk.

## CLI Flags

The binary accepts the following flags:

- `-c, --config`: path to the YAML config file. If not set, the first existing of these locations is used:
    1. `./certwarden-deploy.yaml`
    2. `$XDG_CONFIG_HOME/certwarden-deploy/config.yaml`, or `~/.config/certwarden-deploy/config.yaml` if `XDG_CONFIG_HOME` is unset
    3. `/etc/certwarden-deploy/config.yaml`

    If none of them exists, the tool exits with an error listing every path it searched. Setting `--config` explicitly disables the search: that file is used as-is and it is an error if it does not exist.
- `-d, --dry-run`: show what would change without writing files. This also enables debug logging
- `-f, --force`: write files and run actions even if the content on disk is unchanged
- `-q, --quiet`: only print errors
- `-v, --verbose`: enable debug logging
- `--version`: print the version and exit

If both `--quiet` and `--verbose` are set, `--quiet` wins.

## Example Configuration

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

## Top-level Keys

`base_url`

Required. Base URL of your CertWarden instance, for example `https://certwarden.example.com`.

The download endpoints are appended to this value internally, so the safest form is the plain site URL without an extra path suffix.

`disable_certificate_validation`

Optional. Default: `false`.

Set this to `true` only if your CertWarden instance uses a certificate that is not publicly trusted and you explicitly trust that endpoint. Disabling TLS validation weakens transport security.

`certificates`

Optional but normally expected. A list of certificate definitions. An empty list is valid, but nothing will be deployed.

## Certificate Keys

Each item in `certificates` describes one managed certificate.

`name`

Required. Certificate identifier as known by CertWarden.

The current validation accepts letters, numbers, dots, underscores, and hyphens: `a-z`, `A-Z`, `0-9`, `.`, `_`, `-`.

`cert_secret`

Required. API key used to download the certificate itself. This same secret is also used for `ca_path`.

`cert_path`

Required. Destination path for the certificate PEM file.

`key_secret`

Required when `key_path` is set. API key used to download the private key.

`key_path`

Optional in practice. Destination path for the private key PEM file.

If this value is left empty, private key rollout is skipped for that certificate.

`ca_path`

Optional. Destination path for the CA chain PEM file.

If this value is left empty, CA chain rollout is skipped for that certificate.

`action`

Optional. Command to run after a rollout changed any managed file for that certificate, or when `--force` is used.

It accepts two forms, see [Action Command Semantics](#action-command-semantics):

```yaml
# string form: run through /bin/sh
action: "cp {cert_path} /etc/ssl/ && systemctl reload nginx"

# list form: executed directly, no shell
action:
  - /usr/bin/systemctl
  - reload
  - nginx
```

If the key is present it must not be blank: an `action` that is an empty string, a whitespace-only string, or an empty list is rejected at startup. Leave the key out entirely if no command should run.

## Placeholders

`certwarden-deploy` supports placeholder substitution to reduce repetition in the config file.

Available placeholders:

- `{name}`: available in `cert_path`, `key_path`, `ca_path`, and `action`
- `{cert_path}`: available in `action`
- `{key_path}`: available in `action`
- `{ca_path}`: available in `action`

In the list form of `action`, placeholders are substituted in every item individually, so an item may be a placeholder on its own.

Example:

```yaml
certificates:
  - name: "example.com"
    cert_secret: "cw_cert_api_key"
    cert_path: "/etc/certs/{name}/fullchain.pem"
    key_secret: "cw_key_api_key"
    key_path: "/etc/certs/{name}/privkey.pem"
    ca_path: "/etc/certs/{name}/chain.pem"
    action: "/usr/local/bin/reload-cert {cert_path} {key_path}"
```

After substitution, the action above becomes:

```text
/usr/local/bin/reload-cert /etc/certs/example.com/fullchain.pem /etc/certs/example.com/privkey.pem
```

## Action Command Semantics

`action` accepts two forms, and the form decides how the command is executed.

### String form

A scalar is passed to `/bin/sh -c` as a whole:

```yaml
action: "cp {cert_path} /etc/ssl/ && systemctl reload nginx"
```

The full shell syntax is therefore available: pipes, redirects, `&&` and `||` chains, globbing, environment-variable expansion, and quoting.

```yaml
action: "/usr/local/bin/deploy --note 'cert renewed'"
```

Because a shell parses the string, shell metacharacters in it are syntax rather than data. If an argument may contain spaces, quotes, or `$`, either quote it correctly or use the list form.

### List form

A sequence is executed directly. No shell is involved, `argv[0]` is the binary and every other item is passed through untouched:

```yaml
action:
  - /usr/local/bin/deploy
  - --note
  - "cert renewed"
```

Here `cert renewed` stays a single argument, and nothing expands, globs, or chains. This is the form to prefer when you do not need shell features.

### Trusted configuration

Running the string form through a shell does not widen the tool's trust boundary. The config file is trusted input: by convention it is owned by `root` and mode `600`, and it already contains the command that is executed as the service user. Anyone who can write that file can already run arbitrary code as that user, with or without a shell.

Keep the config file's ownership and permissions tight, and treat it as the security-relevant file it is.

## Deployment Behavior

For each configured certificate, the binary:

1. downloads the current certificate, private key, and optional CA chain from CertWarden
2. compares the downloaded bytes with the existing files on disk
3. writes changed files atomically through a temporary file and rename
4. creates missing parent directories automatically
5. preserves the existing file mode when replacing a file; newly created files default to mode `0644`
6. runs the configured `action` if any managed file changed, or if `--force` was used

## Validation Notes

Current startup validation checks these conditions before deployment begins:

- `base_url` must be set
- every configured certificate must have a non-empty `name`
- every configured certificate must have a non-empty `cert_secret`
- every configured certificate must have a non-empty `cert_path`
- `name` may only contain letters, numbers, dots, underscores, and hyphens
- `action`, if the key is present, must not be blank

If validation fails, the process exits before contacting CertWarden.

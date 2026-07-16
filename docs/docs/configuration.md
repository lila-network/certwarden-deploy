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
- `--base-url`: override `base_url` from the config file. Validated as an absolute URL at startup
- `--api-key`: override `cert_secret` and `key_secret` for **all** certificates. See [--api-key](#api-key) below
- `-d, --dry-run`: show what would change without writing files. This also enables debug logging
- `-f, --force`: write files and run actions even if the content on disk is unchanged
- `--no-actions`: deploy the files but skip every post-rollout action. Overrides `actions.enabled` in the config file. Unlike `--dry-run`, files are still written
- `-q, --quiet`: only print errors. A successful run prints nothing at all, a failing one still prints the run summary and every failure
- `-v, --verbose`: enable debug logging
- `--version`: print the version and exit

If both `--quiet` and `--verbose` are set, `--quiet` wins.

For any setting that can come from more than one place, the precedence is:

```text
CLI flag  >  environment variable  >  config file
```

### --api-key

`--api-key` is blunt on purpose: it replaces both `cert_secret` and `key_secret` on *every* certificate, ignoring whatever the config file and the environment say.

That makes it a debugging tool, not a deployment mechanism. It is for answering "is this key the problem?" in a single run:

```console
$ certwarden-deploy --dry-run --verbose --api-key "$SOME_KEY" --base-url https://staging.example.com
```

For a real deployment where one key covers many certificates, use [`default_cert_secret` / `default_key_secret`](#default-secrets) or `CERTWARDEN_API_KEY` instead.

Because the flag is meant for exactly the situation where the config's `${VAR}` or `file:` references do not resolve on the machine you are debugging on, it short-circuits secret resolution entirely: an unset variable that `--api-key` is about to override is not reported as an error.

Neither flag leaks a secret into the log: `--base-url` is not a secret and is logged with its value, the `--api-key` value is never logged at any level. Only the flag name is recorded.

## Example Configuration

```yaml
base_url: "https://certwarden.example.com"
disable_certificate_validation: false

actions:
  enabled: true

certificates:
  - name: "example.com"
    cert_secret: "cw_cert_api_key"
    cert_path: "/etc/certs/{name}/fullchain.pem"
    key_secret: "cw_key_api_key"
    key_path: "/etc/certs/{name}/privkey.pem"
    ca_path: "/etc/certs/{name}/chain.pem"
    action: "/usr/bin/systemctl reload caddy"
    run_on: "new_or_changed"
```

## Download Endpoints

Each path key maps onto one CertWarden download endpoint:

| Config key | Endpoint | Contents |
| --- | --- | --- |
| `cert_path` | `/certwarden/api/v1/download/certificates/` | certificate |
| `key_path` | `/certwarden/api/v1/download/privatekeys/` | private key |
| `ca_path` | `/certwarden/api/v1/download/certrootchains/` | CA chain |
| `privatecert_path` | `/certwarden/api/v1/download/privatecerts/` | certificate + private key |
| `privatecertchain_path` | `/certwarden/api/v1/download/privatecertchains/` | certificate + private key + CA chain |

## Top-level Keys

`base_url`

Required. Base URL of your CertWarden instance, for example `https://certwarden.example.com`.

The download endpoints are appended to this value internally, so the safest form is the plain site URL without an extra path suffix.

`disable_certificate_validation`

Optional. Default: `false`.

Set this to `true` only if your CertWarden instance uses a certificate that is not publicly trusted and you explicitly trust that endpoint. Disabling TLS validation weakens transport security.

`actions`

Optional. Run-wide switches for post-rollout actions.

`actions.enabled`

Optional. Default: `true`.

Set to `false` to deploy the certificate files but skip every configured `action`. `--no-actions` does the same on the command line and takes precedence over this key.

Skipping an action is not a failure: the run still exits `0` if everything else worked, and each suppressed command is logged, so it is visible what did not run.

This differs from `--dry-run`, which simulates the whole run and writes nothing at all.

```yaml
actions:
  enabled: true
```

`default_cert_secret`

Optional. Default `cert_secret` for every certificate that does not set its own. See [Default secrets](#default-secrets).

`default_key_secret`

Optional. Default `key_secret` for every certificate that does not set its own.

`http`

Optional. Tunes how requests are made. See [The http block](#the-http-block).

`certificates`

Optional but normally expected. A list of certificate definitions. An empty list is valid, but nothing will be deployed.

## Certificate Keys

Each item in `certificates` describes one managed certificate.

`name`

Required. Certificate identifier as known by CertWarden.

The current validation accepts letters, numbers, dots, underscores, and hyphens: `a-z`, `A-Z`, `0-9`, `.`, `_`, `-`.

`cert_secret`

Required, unless a fallback applies. API key used to download the certificate itself. This same secret is also used for `ca_path`.

May be a literal key, a `${VAR}` environment reference, or a `file:/path` reference. See [Secrets](#secrets).

`cert_path`

Required. Destination path for the certificate PEM file.

`key_secret`

Required when `key_path` is set, unless a fallback applies. API key used to download the private key.

Supports the same `${VAR}` and `file:` references as `cert_secret`.

`key_path`

Optional in practice. Destination path for the private key PEM file.

If this value is left empty, private key rollout is skipped for that certificate.

`ca_path`

Optional. Destination path for the CA chain PEM file.

If this value is left empty, CA chain rollout is skipped for that certificate.

`privatecert_path`

Optional. Destination path for the combined certificate and private key, as served by the `privatecerts` endpoint. Useful for servers such as HAProxy that expect both in one file.

If this value is left empty, that download is skipped for the certificate.

Requires `key_secret`: this endpoint authenticates with `cert_secret` and `key_secret` joined by a dot, so the combined secret cannot be built without it.

```yaml
privatecert_path: "/etc/haproxy/certs/app.pem"
```

`privatecert_format`

Optional. Default: `pem`. One of `pem`, `pkcs12`, or `jks`.

Selects the container the `privatecerts` endpoint returns. Anything other than `pem` is requested from the server with a `?format=` query parameter, and the response is written to disk unchanged, so binary containers land byte for byte.

```yaml
privatecert_path: "/opt/app/keystore.p12"
privatecert_format: "pkcs12"
```

!!! warning "Change detection for `pkcs12` and `jks` is unverified"

    `certwarden-deploy` decides whether to write a file, and whether to run the `action`, by hashing the bytes the server returned. That assumes the server returns the same bytes for an unchanged certificate.

    Whether CertWarden rebuilds the PKCS#12/JKS container per request, with a fresh salt and IV, has not been verified. If it does, every run sees different bytes, every run counts as changed, and the `action` fires on every timer tick. If you use these formats, check the behaviour on your instance before relying on the `action`.

`privatecertchain_path`

Optional. Destination path for the combined certificate, private key, and CA chain, as served by the `privatecertchains` endpoint.

If this value is left empty, that download is skipped for the certificate.

Requires `key_secret`, for the same reason as `privatecert_path`.

```yaml
privatecertchain_path: "/etc/haproxy/certs/app-fullchain.pem"
```

`privatecertchain_format`

Optional. Default: `pem`. One of `pem`, `pkcs12`, or `jks`.

Same as `privatecert_format`, for the `privatecertchains` endpoint. The same unverified change-detection caveat applies.

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

If the key is present but blank -- an empty string, a whitespace-only string, or an empty list -- nothing runs and a warning is logged when the action would have fired. It is not a startup error: one blank action line must not stop every other certificate in the config from being deployed. Leave the key out entirely if no command should run.

`run_on`

Optional. Default: `new_or_changed`. Decides when `action` is executed, see [Action Trigger Policies](#action-trigger-policies).

An unknown value is rejected at startup.

## Secrets

`cert_secret` and `key_secret` accept a literal API key, but a literal key means the key lives in the config file. To keep it out of there, a secret value may instead reference where the real value lives.

```yaml
certificates:
  - name: "example.com"
    cert_secret: "${CERTWARDEN_APP_CERT_SECRET}"
    key_secret: "file:/run/credentials/certwarden.service/app-key"
```

The following forms are recognised, for `cert_secret`, `key_secret`, and the top-level defaults below:

- `${VAR}`: the value of the environment variable `VAR`
- `file:/path`: the contents of `/path`, with surrounding whitespace trimmed
- anything else: the literal value, exactly as before

An unset variable or an unreadable file is a configuration error. The run stops with exit code 1 before any request is made, rather than sending an empty key and reporting a puzzling `401`.

A reference must make up the whole value: `${VAR}-suffix` is rejected instead of being passed through. If you need a literal value that starts with `${`, escape it by doubling the dollar sign:

```yaml
cert_secret: "$${this-is-not-a-reference}"   # resolves to ${this-is-not-a-reference}
```

### Default secrets

When one CertWarden API key covers many certificates, repeating it on every entry is noise. Two optional top-level keys provide a default for every certificate that does not set its own:

```yaml
default_cert_secret: "${CERTWARDEN_CERT_SECRET}"
default_key_secret: "${CERTWARDEN_KEY_SECRET}"

certificates:
  - name: "example.com"          # uses both defaults
    cert_path: "/etc/certs/{name}/fullchain.pem"
    key_path: "/etc/certs/{name}/privkey.pem"

  - name: "other.example.com"    # overrides the certificate default only
    cert_secret: "${CERTWARDEN_OTHER_CERT_SECRET}"
    cert_path: "/etc/certs/{name}/fullchain.pem"
```

They take the same `${VAR}` and `file:` references as the per-certificate fields.

The precedence for each secret, most specific first:

1. `cert_secret` / `key_secret` on the certificate
2. `default_cert_secret` / `default_key_secret`
3. the `CERTWARDEN_API_KEY` environment variable
4. otherwise: a validation error naming all of the above

These are two keys rather than one `api_key` on purpose. The reference Python tool uses a single `api_key`, but this tool has kept the certificate and key secrets apart since 0.2.0, and a single key cannot express that split.

### CERTWARDEN_API_KEY

If a certificate has no `cert_secret` or `key_secret` and no default applies, the `CERTWARDEN_API_KEY` environment variable is used for it. It is the last fallback in the chain.

### Secrets and logs

Resolved secret values are never written to the log, at any log level, including `--verbose` and `--dry-run`. Debug output reports only *where* a secret came from, never what it is, and a resolution error names the offending variable or path but not its value.

### systemd credentials

`file:` exists mainly for systemd's `LoadCredential=`, which places a secret in a private file below `$CREDENTIALS_DIRECTORY` that only the service user can read:

```ini
[Service]
LoadCredential=cert-secret:/etc/certwarden-deploy/cert-secret
LoadCredential=key-secret:/etc/certwarden-deploy/key-secret
ExecStart=/usr/local/bin/certwarden-deploy
```

```yaml
certificates:
  - name: "example.com"
    cert_secret: "file:/run/credentials/certwarden-deploy.service/cert-secret"
    key_secret: "file:/run/credentials/certwarden-deploy.service/key-secret"
```

The same shape works for anything that can drop a secret into a file or the environment, such as Vault Agent, SOPS, or a `systemd-creds`-encrypted credential, without templating the whole config file.

## The http block

The optional top-level `http` block tunes how requests to CertWarden are made, rather than what is requested.

```yaml
http:
  headers:
    CF-Access-Client-Id: "${CF_ACCESS_CLIENT_ID}"
    CF-Access-Client-Secret: "${CF_ACCESS_CLIENT_SECRET}"
```

### http.headers

Optional. A map of header names to values, sent with every request.

This exists for deployments that put CertWarden behind an authenticating proxy such as Cloudflare Access, Authelia, or oauth2-proxy: without the headers those gateways require, the request never reaches CertWarden at all.

Header values support the same `${VAR}` and `file:` references as the secrets, because a header a gateway checks is usually a secret itself. See [Secrets](#secrets).

Two headers are owned by the tool and cannot be overridden from this block:

- `X-API-Key`: carries the certificate secret
- `User-Agent`

Configured headers are applied first and these two are set afterwards, so a typo in the block cannot clobber the API key and turn every request into a `401`.

Header **values** are never logged. Debug output lists header names only.

## Placeholders

`certwarden-deploy` supports placeholder substitution to reduce repetition in the config file.

In this section, "path keys" means `cert_path`, `key_path`, `ca_path`, `privatecert_path`, and `privatecertchain_path`.

Available placeholders:

| Placeholder | Expands to | Available in |
| --- | --- | --- |
| `{name}` | the certificate `name` | path keys, `action` |
| `{common_name}` | the certificate `name` | path keys, `action` |
| `{cert_id}` | the certificate `name` | path keys, `action` |
| `{date}` | the run date as `YYYYMMDD` | path keys, `action` |
| `{base_url}` | the top-level `base_url` | path keys, `action` |
| `{cert_path}` | the expanded `cert_path` | `action` |
| `{key_path}` | the expanded `key_path` | `action` |
| `{ca_path}` | the expanded `ca_path` | `action` |
| `{privatecert_path}` | the expanded `privatecert_path` | `action` |
| `{privatecertchain_path}` | the expanded `privatecertchain_path` | `action` |

`{common_name}` and `{cert_id}` are aliases of `{name}`, provided to ease migration from other CertWarden deployment tools. CertWarden addresses a certificate by a single identifier, so all three expand to the same value.

`{date}` is resolved once per run, not once per field, so a run that crosses midnight cannot write two different dates into two paths.

Path keys are expanded first, then `action` is expanded from the results. That means `{cert_path}` in an `action` always resolves to the final on-disk location. Substitution is a single pass: a value that is substituted in is never scanned for placeholders again, so the outcome never depends on replacement order.

Placeholders that no substitution recognises are left untouched and reported with a warning naming the placeholder, the certificate, and the field. A misspelled `{cert-path}` therefore shows up in the log instead of silently becoming part of a file path.

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

`{date}` is handy for keeping dated copies of a rollout:

```yaml
certificates:
  - name: "example.com"
    cert_secret: "cw_cert_api_key"
    cert_path: "/etc/certs/{name}/{date}/fullchain.pem"
    key_secret: "cw_key_api_key"
    key_path: "/etc/certs/{name}/{date}/privkey.pem"
    action: "/usr/local/bin/reload-cert {cert_path}"
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

## Action Trigger Policies

Every rollout classifies each of a certificate's files as one of:

- **created**: the file did not exist on disk before this run
- **modified**: the file existed and its content differed
- **unchanged**: the file on disk already matched CertWarden

The certificate as a whole is then **new** if any of its files was created, **changed** if none was created but at least one was modified, and **unchanged** otherwise.

`run_on` selects which of those outcomes runs the `action`:

| `run_on`         | new | changed | unchanged | Use case                                                        |
| ---------------- | --- | ------- | --------- | --------------------------------------------------------------- |
| `new`            | yes | no      | no        | one-off setup work that only makes sense on a first deployment   |
| `changed`        | no  | yes     | no        | reload on renewal only, ignoring the initial rollout             |
| `new_or_changed` | yes | yes     | no        | default: reload whenever something was written                   |
| `all`            | yes | yes     | yes       | an action that is cheap and idempotent, or that checks for itself |

Notes:

- `run_on` only gates the `action`. Which files get written is never affected by it.
- `--force` runs the action regardless of `run_on`, including `run_on: new`, because `--force` forces both the write and the action.
- `--force` also rewrites files whose content is identical and reports them as changed, so a forced run counts as changed rather than unchanged.
- omitting `run_on` behaves exactly like `new_or_changed`, which is what the tool did before this option existed.

```yaml
certificates:
  - name: "example.com"
    cert_secret: "cw_cert_api_key"
    cert_path: "/etc/certs/{name}/fullchain.pem"
    action: "/usr/bin/systemctl reload caddy"
    run_on: "new_or_changed"
```

## Deployment Behavior

For each configured certificate, the binary:

1. downloads the current certificate, private key, and the optional CA chain, combined certificate, and combined certificate chain from CertWarden
2. compares the downloaded bytes with the existing files on disk
3. writes changed files atomically through a temporary file and rename
4. creates missing parent directories automatically
5. preserves the existing file mode when replacing a file; newly created files default to mode `0644`
6. runs the configured `action` if the certificate's outcome matches `run_on`, or if `--force` was used, unless actions are disabled for the run

## Run Summary and Exit Codes

Every run ends with a single summary record, followed by one record per failure:

```text
INFO  run summary  new=2 changed=0 unchanged=5 failed=1 action_failed=0 action_skipped=0 total=8
ERROR certificate failed  name=api.example.com file-type=key error="API-Key invalid"
```

The fields are:

| Field            | Meaning                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| `new`            | certificates where at least one file did not exist before this run          |
| `changed`        | certificates where nothing was created but at least one file was rewritten  |
| `unchanged`      | certificates that were already up to date                                   |
| `failed`         | certificates that could not be rolled out                                   |
| `action_failed`  | actions that exited non-zero                                                |
| `action_skipped` | actions that were suppressed because actions are disabled for the run       |
| `total`          | certificates attempted: `new` + `changed` + `unchanged` + `failed`          |

Every count is always present, including zeroes, so the record has a stable shape and can be parsed or alerted on. `action_failed` and `action_skipped` are not part of `total`: those certificates were still deployed and are already counted above.

Under `--dry-run` the summary is prefixed with `DRY-RUN:` and reports what the run would have done.

The process exit code is:

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | every certificate was processed and every triggered action succeeded    |
| `1`  | configuration or setup error, nothing was deployed                      |
| `2`  | one or more certificates failed to roll out                             |
| `3`  | every certificate rolled out, but one or more actions failed            |

A certificate failure outranks an action failure: if both happened, the run exits `2`. A skipped action never affects the exit code.

## Validation Notes

Current startup validation checks these conditions before deployment begins:

- `base_url` must be set
- every configured certificate must have a non-empty `name`
- every configured certificate must end up with a non-empty `cert_secret`, from the certificate itself, from `default_cert_secret`, or from `CERTWARDEN_API_KEY`
- every configured certificate must have a non-empty `cert_path`
- `name` may only contain letters, numbers, dots, underscores, and hyphens
- `run_on`, if set, must be one of `new`, `changed`, `new_or_changed`, `all`
- `key_secret` must be set when `privatecert_path` or `privatecertchain_path` is set
- `privatecert_format` and `privatecertchain_format` must be `pem`, `pkcs12`, or `jks` when set

If validation fails, the process exits before contacting CertWarden.

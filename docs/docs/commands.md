---
title: Commands
weight: 30
---

`certwarden-deploy` without a subcommand is the deployment: it reads the config file, fetches every certificate in it, writes the ones that changed and runs their actions. That is the mode the [systemd timer](installation.md) runs, and it is unchanged.

The subcommands are for everything around that.

```shell
certwarden-deploy                       # roll out everything in the config file
certwarden-deploy fetch certificate ... # download one artefact, ad hoc
certwarden-deploy config validate       # lint the config file, no network
```

Every global flag from the [Configuration](configuration.md#cli-flags) page also applies to the subcommands, so `-c/--config`, `--base-url`, `--api-key`, `-v/--verbose` and `-q/--quiet` work everywhere.

## fetch

`fetch` downloads a single artefact of a single certificate and prints it or saves it. It is the command to reach for when you want to see what the server actually returns, check whether an API key works, or grab one certificate for a one-off job.

```shell
certwarden-deploy fetch certificate <name>       [--output FILE|-]
certwarden-deploy fetch key <name>               [--output FILE|-]
certwarden-deploy fetch ca <name>                [--output FILE|-]
certwarden-deploy fetch privatecert <name>       [--format pem|pkcs12|jks] [--output FILE|-]
certwarden-deploy fetch privatecertchain <name>  [--format pem|pkcs12|jks] [--output FILE|-]
```

The five subcommands map onto the five [download endpoints](configuration.md#download-endpoints).

### Output

`--output` defaults to `-`, which is stdout, so the material can be piped:

```shell
certwarden-deploy fetch certificate example.com | openssl x509 -noout -text
certwarden-deploy fetch privatecert example.com --format pkcs12 | keytool -list -v -keystore /dev/stdin
```

Log records go to **stderr**, never to stdout, so nothing ever lands in the middle of that pipe. The fetched material is only ever written, never logged, at any level, including `--verbose`.

Passing a path instead writes the file through the same atomic path a rollout uses: a temporary file next to the target, fsynced, then renamed into place. A failed fetch writes nothing and leaves an existing file alone.

```shell
certwarden-deploy fetch certificate example.com --output /tmp/example.com.pem
```

### Secrets and the server

The secret is resolved the same way a deployment resolves it, most specific first:

```text
--api-key  >  the certificate entry in the config file (matched by name)  >  CERTWARDEN_API_KEY
```

A name the config file does not mention is not an error: the chain simply falls through to the flag or the environment variable. Together with `--base-url` that means `fetch` works with no config file at all, which is the situation it is most useful in:

```shell
certwarden-deploy fetch certificate example.com \
  --base-url https://certwarden.example.com \
  --api-key cw_cert_api_key
```

`privatecert` and `privatecertchain` authenticate with both secrets joined by a dot, exactly as in a rollout, so both `cert_secret` and `key_secret` have to be resolvable for them.

Only the entry that is actually being fetched is resolved. A broken `${VAR}` on some other certificate in the config file does not stop a `fetch`: this is the command you use when the config is already misbehaving.

### What fetch does not do

`fetch` is deliberately dumb: it fetches, it writes or prints, it exits.

- **No filename templates.** `--output` is the literal path. Placeholders like `{name}` are a config file feature.
- **No change detection.** Fetching the same certificate twice writes the file twice, even when the bytes are identical. A debugging command that answers "unchanged, wrote nothing" is a debugging command that answers the wrong question.
- **No actions.** Nothing is reloaded, nothing is executed.

A failed fetch exits non-zero.

## config

`config` works on the config file itself. None of its subcommands contacts the CertWarden server.

```shell
certwarden-deploy config init [--path FILE]   # write a commented starter config
certwarden-deploy config validate             # parse and validate, exit 0 or 1
certwarden-deploy config show                 # print the effective config, secrets redacted
```

### config init

Writes a commented starter config, by default to `./certwarden-deploy.yaml`, which is the first location the [config file search](configuration.md#cli-flags) looks at, so a bare `certwarden-deploy` in the same directory picks it up.

```shell
certwarden-deploy config init
certwarden-deploy config init --path /etc/certwarden-deploy/config.yaml
```

Missing parent directories are created. The file is written with mode `0600`, because it is where the API keys are about to go.

It **refuses to overwrite an existing file** unless `--force` is given: the file it would replace is the one holding the keys of a working deployment.

### config validate

Parses and validates the config file, prints every problem it finds, and exits `0` if the config is usable or `1` if it is not.

```shell
certwarden-deploy config validate -c /etc/certwarden-deploy/config.yaml
```

**It makes no network requests at all.** That is the point of it: it is the command for a CI job, a pre-commit hook, or a config-management pipeline that wants to lint the file it just rendered, on a machine that has never been able to reach the CertWarden instance the file names. `--dry-run` is not a substitute — it still fetches every certificate from the API.

It runs exactly what a real run runs before its first request, in the same order and on the same code path: placeholder substitution, the CLI overrides, secret resolution, then validation. A green `config validate` and a run that then rejects the config would make the command worse than useless, so the two cannot drift apart.

That does mean validation sees the machine it runs on: a `cert_secret: "${CERTWARDEN_KEY}"` is reported as unresolvable if that variable is not set in the environment doing the validating.

### config show

Prints the config the tool will actually act on: placeholders expanded, `--base-url` and the other overrides folded in, secrets resolved, and the defaults a run would apply filled in.

```shell
certwarden-deploy config show -c /etc/certwarden-deploy/config.yaml
```

This is what to attach to a bug report, and what to look at when a config file and a run disagree about what should happen.

#### Secrets are always redacted

Every resolved secret and every `http.headers` value is printed as `<redacted>`:

```yaml
certificates:
- name: example.com
  cert_secret: <redacted>
  cert_path: /etc/ssl/example.com/fullchain.pem
```

There is **no flag to reveal them**, and there will not be one. The output of this command is meant to end up in terminal scrollbacks, CI logs and pasted bug reports, which is exactly the set of places an API key should never reach. If you need to know a secret, read it from where it is configured.

An empty field stays empty. `<redacted>` means "there is a value here", which is what makes the output able to answer whether a `default_cert_secret` or the `CERTWARDEN_API_KEY` fallback actually kicked in. Header *names* are printed as-is, for the same reason: whether `CF-Access-Client-Id` is being sent at all is a question worth answering, and it can be answered without the value.

#### Groups are desugared

A `groups` key is sugar: every member is folded into the flat `certificates` list before a run does anything else. `config show` prints the result of that folding rather than the sugar, because the flat list is what the tool actually acts on:

```yaml
# in the config file
groups:
  nginx:
    cert_secret: "${NGINX_SECRET}"
    cert_path: "/etc/nginx/ssl/{name}.crt"
    action: "systemctl reload nginx"
    certificates:
      - name: a.example.com
      - name: b.example.com
```

```yaml
# what `config show` prints
certificates:
- name: a.example.com
  cert_secret: <redacted>
  cert_path: /etc/nginx/ssl/a.example.com.crt
  action: systemctl reload nginx
  run_on: new_or_changed
- name: b.example.com
  cert_secret: <redacted>
  cert_path: /etc/nginx/ssl/b.example.com.crt
  action: systemctl reload nginx
  run_on: new_or_changed
```

There is no `groups` key in the output. This is the command to reach for when a group and its members disagree about which value wins: it shows the answer per certificate, with `{name}` already resolved.

`config validate` desugars the same way, so a problem a group introduces — a name that is not unique once expanded, a `privatecert_format` the group sets to something that does not exist — is reported by the linter rather than by the run. Those messages name the group they came from.

`config show` needs a valid config: an invalid one has no meaningful effective form, so it is reported the way `config validate` reports it.

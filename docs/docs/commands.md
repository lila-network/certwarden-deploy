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

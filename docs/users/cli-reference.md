# CLI Reference

Complete reference for the `hardline` CLI. For common workflows, start with [Getting Started](getting-started.md). For failure handling, see [Failure And Recovery](failure-and-recovery.md).

Hardline also ships a second binary, `profiletool`, for key generation and profile signing. See [Signing And Verification](signing-and-verification.md) and [Overrides And Signing](../profiles/overrides-and-signing.md).

## Synopsis

```text
hardline [-h|--help]
hardline [-v|-V|--version]
hardline <command> <profile> [flags]
```

Commands:

| Command | Purpose |
| --- | --- |
| `plan` | Inspect the target host and print what would change. Does not mutate. |
| `apply` | Verify, plan, then apply the profile. Writes a rollback journal. |
| `rollback` | Reverse the last successful apply for the profile on this host. |
| `verify-profile` | Validate the profile locally: signature, schema, templates, plugins. |
| `verify` | Alias for `verify-profile`. |
| `vp` | Alias for `verify-profile`. |
| `version` | Print version info. |

Every command that targets a remote host (`plan`, `apply`, `rollback`) takes the profile directory as a **positional argument**, not as a `--profile-dir` flag. Hardline does not accept inline `--override key=value` flags — runtime overrides are loaded from a JSON file via `--overrides-file` or auto-discovered as `profile.overrides.json` inside the profile directory.

## Global

| Flag | Shorthand | Description |
| --- | --- | --- |
| `--help` | `-h`, `-help` | Show usage. Works on the root command and on every subcommand. |
| `--version` | `-v`, `-V`, `-version` | Print version info and exit. |

`hardline <command> --help` prints subcommand-specific usage.

## `hardline plan <profile>`

Inspects the target host and prints what Hardline expects to change. Does not mutate the remote system.

```text
hardline plan <profile> [--host HOST| -H HOST] [--port PORT| -p PORT]
                        [--user USER| -u USER] [--keypath PATH| -k PATH]
                        [--overrides-file PATH] [--allow-local-key]
                        [--log-file PATH] [--report-file PATH]
                        [--report-format json|yaml|md] [--debug| -d]
```

| Flag | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--host` | `-H` | — | Remote host. Required. |
| `--port` | `-p` | `22` | SSH port. |
| `--user` | `-u` | — | Remote user. Required unless connecting as root is handled out-of-band. |
| `--keypath` | `-k` | — | Path to the SSH private key. Required. |
| `--overrides-file` | — | — | Load runtime overrides from a JSON object file. When omitted, Hardline auto-loads `profile.overrides.json` from the profile directory if present. |
| `--allow-local-key` | — | `false` | Verify the profile using a local signing key from `/etc/hardline/profile_signing_pub.pem` instead of the binary's embedded key. |
| `--log-file` | — | — | Write plain-text logs to this file. |
| `--report-file` | — | — | Write the plan report to this file. |
| `--report-format` | — | — | Report format: `json`, `yaml`, or `md`. If omitted, Hardline infers from the `--report-file` extension. |
| `--debug` | `-d` | `false` | Enable debug output. |

Example:

```bash
hardline plan starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --overrides-file ./runtime/dev-overrides.json \
  --report-file ./reports/dev-plan.yaml
```

## `hardline apply <profile>`

Verifies the profile, re-runs the planner, and applies each step in order. Records a rollback journal for the run.

```text
hardline apply <profile> [--host HOST| -H HOST] [--port PORT| -p PORT]
                         [--user USER| -u USER] [--keypath PATH| -k PATH]
                         [--overrides-file PATH] [--allow-local-key]
                         [--log-file PATH] [--report-file PATH]
                         [--report-format json|yaml|md]
                         [--keep-local-rollback] [--debug| -d]
```

All flags from `plan` apply, plus:

| Flag | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--keep-local-rollback` | — | `false` | Keep the runner-side rollback journal after a successful apply. Without this, Hardline deletes the local copy once the remote journal is confirmed. |

Only one `apply` can run against the same host at a time — Hardline takes a remote lock for the duration of the run.

Example:

```bash
hardline apply prod \
  -H example.com \
  -u deploy \
  -k ~/.ssh/id_rsa \
  --overrides-file ./runtime/prod-overrides.json \
  --keep-local-rollback \
  -d
```

## `hardline rollback <profile>`

Reverses the last successful apply for the profile on this host, using the remote rollback journal.

```text
hardline rollback <profile> [--host HOST| -H HOST] [--port PORT| -p PORT]
                            [--user USER| -u USER] [--keypath PATH| -k PATH]
                            [--allow-local-key] [--log-file PATH]
                            [--force-rollback] [--debug| -d]
```

| Flag | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--host` | `-H` | — | Remote host. Required. |
| `--port` | `-p` | `22` | SSH port. |
| `--user` | `-u` | — | Remote user. Required. |
| `--keypath` | `-k` | — | SSH private key path. Required. |
| `--allow-local-key` | — | `false` | Verify the profile using `/etc/hardline/profile_signing_pub.pem`. |
| `--log-file` | — | — | Write plain-text logs to this file. |
| `--force-rollback` | — | `false` | Proceed even when a managed file, package, or service was modified after the original apply. Use only when you understand the conflict. |
| `--debug` | `-d` | `false` | Enable debug output. |

`rollback` does not take `--overrides-file` or report flags — it replays the journal captured during the original apply, it does not re-plan.

Example:

```bash
hardline rollback starter-secure-ubuntu-24.04-lts \
  -H example.com \
  -u deploy \
  -k ~/.ssh/id_rsa
```

## `hardline verify-profile <profile>`

Aliases: `verify`, `vp`.

Runs the full local verification pipeline: manifest hashes, signature, profile and action schemas, declared templates on disk, plugin availability, and override keys. Does not touch the remote host.

```text
hardline verify-profile <profile> [--overrides-file PATH] [--allow-local-key]
                                  [--log-file PATH] [--debug| -d]
```

| Flag | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--overrides-file` | — | — | Validate override key names against `allowed_overrides`. Auto-loads `profile.overrides.json` if present when omitted. |
| `--allow-local-key` | — | `false` | Verify using `/etc/hardline/profile_signing_pub.pem`. |
| `--log-file` | — | — | Write plain-text logs to this file. |
| `--debug` | `-d` | `false` | Enable debug output. |

Example:

```bash
hardline verify staging --debug
```

## `hardline version`

Prints version information. Equivalent to `hardline --version`, `-v`, `-V`, or `-version`.

```bash
hardline version
```

## Environment Variables

| Variable | Used by | Description |
| --- | --- | --- |
| `HARDLINE_KNOWN_HOSTS` | `plan`, `apply`, `rollback` | Path to the SSH `known_hosts` file Hardline checks before connecting. When unset, Hardline uses `~/.ssh/known_hosts`. Hardline refuses to connect to a host whose key is not already present; it does not perform TOFU. |
| `HARDLINE_STATE_DIR` | `apply`, `rollback` | Root directory for the runner-side rollback journal. When unset, Hardline uses `/tmp/hardline/runs`. Override this if you want to persist local journals outside `/tmp`, or if you're running on a host that clears `/tmp` on reboot. |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success, or help/version printed and exited normally. |
| `1` | Missing or unrecognized command, or a required positional argument is missing. |
| `2` | Invalid or unknown flags. |
| `130` | Interrupted by SIGINT (Ctrl-C). Hardline catches SIGINT during remote work, attempts a graceful stop of the current step, and exits `130`. |

Any other non-zero exit means the operation itself failed — profile verification, remote connection, a step that returned an error, or a rollback conflict. Hardline prints the failure reason on stderr before exiting. For recovery guidance, see [Failure And Recovery](failure-and-recovery.md).

## Report Formats

`--report-format` supports three values:

- `json` — machine-readable, one object per run.
- `yaml` — the same object rendered as YAML for human review.
- `md` — a Markdown summary suitable for PR comments, release notes, or compliance evidence.

When `--report-file` is set and `--report-format` is omitted, Hardline infers the format from the file extension: `.json` → json, `.yaml` / `.yml` → yaml, `.md` → md. Any other extension is an error.

## Profile Argument

Every command except `version` takes a profile directory as its **first positional argument**. The argument is a path to the directory, not the profile ID. Relative and absolute paths both work:

```bash
hardline verify-profile ./profiles/staging
hardline verify-profile /etc/hardline/profiles/prod
hardline verify-profile starter-secure-ubuntu-24.04-lts
```

The directory must contain `profile.json`, `manifest.json`, and `manifest.sig`. See [Profile Structure](../profiles/structure.md).

# Architecture

This document reflects the current structure of the codebase.

## Top-level layout

- `cmd/hardline`
  - CLI entrypoint
- `cmd/profiletool`
  - profile signing key generation and manifest signing
- `cmd/genschema`
  - JSON schema generation
- `internals/cli`
  - argument parsing and usage text
- `internals/connection`
  - SSH setup, known-hosts lookup, sudo preflight
- `internals/runtime`
  - `pluginapi.Host` implementation on top of SSH and SFTP
- `internals/plan`
  - plan execution and report generation
- `internals/apply`
  - apply execution and rollback-journal capture
- `internals/rollback`
  - journal persistence and rollback execution
- `internals/verify`
  - profile signature verification
- `internals/registry`
  - built-in plugin registration
- `internals/plugins`
  - built-in plugin implementations
- `pluginprojects/firewalltemplate`
  - external shared-object plugin
- `pkg/profile`
  - profile loading and schema validation
- `pkg/pluginapi`
  - plugin contract, registry, rollback snapshot helpers

## Command flow

### `plan`

`cmd/hardline` parses the command, loads `.so` plugins from the binary directory, and calls `internals/plan.Plan`.

`plan` then:

1. validates report output flags
2. loads `profile.json` and action files
3. checks Hardline version against `profile.min_hardline`
4. checks `profile_schema` against the compiled-in supported version
5. validates the profile and action files against generated JSON schema
6. ensures every referenced plugin is registered
7. opens an SSH connection
8. runs plugin `Plan` for every step
9. renders terminal output and optional JSON/YAML/Markdown artifacts

### `apply`

`cmd/hardline` explicitly runs the planning path before apply:

1. `plan.Plan`
2. `apply.Apply`

The apply path then:

1. opens SSH
2. verifies passwordless sudo
3. reloads and validates the profile
4. creates a local rollback journal
5. captures pre-step state through plugin `Capture`
6. executes plugin `Apply`
7. captures post-step state
8. writes the remote rollback journal on success
9. deletes the local journal unless `--keep-local-rollback` is set

If a step fails after capture has started, Hardline automatically rolls back the captured steps in reverse order.

### `rollback`

`rollback` currently supports only one target:

- `last`

It:

1. opens SSH
2. verifies passwordless sudo
3. loads `/var/lib/hardline/runs/last.json`
4. refuses to run unless the remote journal status is `success`
5. replays rollback objects in reverse order

Service rollback is intentionally deferred until after file and package rollback so services restart against restored on-disk state.

### `verify-profile`

`verify-profile` is separate from `plan` and `apply`.

It:

1. verifies `manifest.json` and `manifest.sig` with the embedded Ed25519 public key
2. loads the profile
3. checks that every referenced plugin is registered

It does not contact a remote host.

## Trust and validation model

There are two distinct validation layers:

### Schema and plugin validation

Used by `plan` and `apply`.

- JSON schema validation comes from `pkg/profile.Profile.Affirm`
- plugin presence comes from `registry.EnsureProfilePlugins`

### Signature and manifest validation

Used only by `verify-profile`.

- manifest version must be `1`
- algorithm must be `sha256`
- every non-metadata file in the profile directory must match the manifest hash
- manifest signature must verify against the embedded Ed25519 public key

## Plugin architecture

The plugin contract lives in `pkg/pluginapi`.

Each plugin provides:

- `Name`
- `InternalValidation`
- `Apply`
- `Plan`
- `Capture`

Built-ins are registered at startup through `internals/registry`:

- `packages`
- `template`
- `service`
- `firewall`

Dynamic plugins are loaded from `plugins/*.so` next to the executable. The repo currently builds one:

- `firewall_template`

## Remote execution model

SSH setup is handled by `internals/connection`.

Notable behavior:

- port defaults to `22`
- host keys are checked through `known_hosts`
- `HARDLINE_KNOWN_HOSTS` can override the default path
- non-interactive sudo is required

Plugins operate on the remote host through the `pluginapi.Host` interface implemented by `internals/runtime.SSHRuntime`.

That interface exposes:

- root command execution
- root command execution with output
- file stat
- read root-owned files
- write root-owned files

## Rollback data model

Rollback journals store:

- host
- profile ID
- profile path
- status
- per-step rollback records

Per-step records contain:

- rollback mode
- `before` object snapshots
- `after` object snapshots
- notes

Rollback object kinds are:

- file
- service
- package
- validate

Local journals default to `${TMPDIR:-/tmp}/hardline/runs/<host>/last.json` and can be redirected with `HARDLINE_STATE_DIR`.

## Reporting model

Plan output is rendered in two layers:

- human-readable terminal output
- optional artifact output in `json`, `yaml`, or `md`

Artifacts include:

- profile metadata
- target metadata
- run summary
- change list
- attention list
- per-step details
- suggested apply and rollback commands

# Hardline

Hardline is a Go CLI that reads a profile directory from disk, connects to a remote host over SSH, plans changes, applies them, and records rollback state.

## Commands

`hardline` currently exposes five commands:

- `plan <profile>`
- `apply <profile>`
- `rollback last`
- `verify-profile <profile>` and `vp <profile>`
- `version` and `-v`

`apply` always runs the planning path first, then executes the profile.

## What Hardline manages

The built-in registry currently includes these plugins:

- `packages`
- `template`
- `service`
- `firewall`

At runtime, Hardline also loads any `.so` plugins found in `plugins/` next to the binary. This repo builds one external plugin there:

- `firewall_template`

## Requirements from the code

- Go `1.25.4`
- SSH access to the target host
- A trusted `known_hosts` entry, or `HARDLINE_KNOWN_HOSTS` pointing at a known-hosts file
- Non-interactive `sudo` on the remote host

## Build and Test

Common make targets:

- `make test`
  - runs `go test ./...`
  - enforces repo-wide and per-package coverage floors through `MIN_COVERAGE` (default `90`)
- `make build`
  - runs `tidy`
  - ensures the embedded profile signing public key exists
  - regenerates JSON schemas
  - builds the `firewall_template` plugin
  - builds `tmp/hardline`
- `make profiletool`
- `make genschema`
- `make sign-profiles`

## CLI examples

Plan:

```bash
tmp/hardline plan base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user deploy \
  --keypath /home/me/.ssh/id_ed25519
```

Apply with a saved report:

```bash
tmp/hardline apply base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user deploy \
  --keypath /home/me/.ssh/id_ed25519 \
  --report-file tmp/plan.json \
  --report-format json
```

Keep the local rollback journal after a successful apply:

```bash
tmp/hardline apply base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user deploy \
  --keypath /home/me/.ssh/id_ed25519 \
  --keep-local-rollback
```

Rollback the last successful remote run:

```bash
tmp/hardline rollback last \
  --host example.com \
  --user deploy \
  --keypath /home/me/.ssh/id_ed25519
```

Verify a signed profile:

```bash
tmp/hardline verify-profile base-secure-ubuntu-24.04-lts
```

## Profile verification and trust

`verify-profile` does two things:

- verifies `manifest.json` and `manifest.sig` with the embedded Ed25519 public key
- checks that every plugin referenced by the profile is registered

`plan` and `apply` do not call the signature-verification path. They load the profile, validate it against the JSON schema, and check that required plugins are registered.

## Rollback state

During `apply`, Hardline captures per-step rollback state before execution.

- local journal:
  - default root: `${TMPDIR:-/tmp}/hardline/runs`
  - override: `HARDLINE_STATE_DIR`
- remote journal:
  - `/var/lib/hardline/runs/last.json`

On success, the remote journal is written. The local journal is removed unless `--keep-local-rollback` is set.

`rollback` only supports the target `last`, and it reads the remote journal.

## Integration tests

The integration runner provisions a GCP VM with Terraform and then runs the live scenarios over SSH.

Targets:

- `make itest`
- `make itest-scenario ITEST_SCENARIO=<name>`
- `make itest-scenarios`
- `make itest-gcp-up`
- `make itest-gcp-down`

Terraform input defaults live under `integration-tests/terraform/terraform.tfvars.example`.

## Repository map

- `cmd/hardline`: CLI entrypoint
- `cmd/profiletool`: key generation and profile signing
- `cmd/genschema`: JSON schema generation
- `internals/apply`: apply workflow
- `internals/plan`: planning and report generation
- `internals/rollback`: rollback journals and rollback execution
- `internals/verify`: profile signature verification
- `internals/plugins`: built-in plugin implementations
- `pluginprojects/firewalltemplate`: external plugin project
- `pkg/profile`: profile loading and schema validation
- `schema/`: generated JSON schemas
- `integration-tests/`: live integration runner, test profiles, Terraform

For more detail:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/plugins.md`](docs/plugins.md)
- [`docs/profiles.md`](docs/profiles.md)
- [`docs/plan-design.md`](docs/plan-design.md)
- [`docs/codebase-gaps.md`](docs/codebase-gaps.md)

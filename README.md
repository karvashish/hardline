# hardline

`hardline` applies declarative host-hardening profiles over SSH.

This repository now documents four separate things on purpose:

- the current code-backed behavior in this file
- the repo and runtime structure in [`docs/architecture.md`](/home/kartikeya_vashishtha/hardline-try2/docs/architecture.md)
- the on-disk profile and plugin model in [`docs/profiles.md`](/home/kartikeya_vashishtha/hardline-try2/docs/profiles.md) and [`docs/plugins.md`](/home/kartikeya_vashishtha/hardline-try2/docs/plugins.md)
- the intended direction and status against that direction in [`docs/plan-design.md`](/home/kartikeya_vashishtha/hardline-try2/docs/plan-design.md) and [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md)

If a reader wants to know whether something is implemented, missing, or currently wrong, start with [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md). If they want to know where to read the code next, start with [`docs/architecture.md`](/home/kartikeya_vashishtha/hardline-try2/docs/architecture.md).

The current implementation is centered on:

- JSON profiles and JSON action files
- built-in step plugins for packages, templates, services, and firewall rules
- a shipped external `firewall_template` plugin project that builds to a loadable `.so`
- signed profile integrity verification
- automatic rollback capture during `apply`

## Commands

`hardline` exposes these commands:

- `plan <profile> --host HOST --user USER --keypath PATH`
- `apply <profile> --host HOST --user USER --keypath PATH`
- `rollback last --host HOST --user USER --keypath PATH`
- `verify-profile <profile>`
- `vp <profile>`
- `version`

Important current behavior:

- `apply` always runs `plan` first from [`cmd/hardline/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/hardline/main.go).
- `rollback` only supports the target `last`.
- `verify-profile` verifies `manifest.json` and `manifest.sig`; it does not run schema validation or step planning.
- SSH connections require a private key, a populated `known_hosts`, and non-interactive `sudo`.

## Doc Map

- [`README.md`](/home/kartikeya_vashishtha/hardline-try2/README.md)
  Current implementation overview.
- [`docs/architecture.md`](/home/kartikeya_vashishtha/hardline-try2/docs/architecture.md)
  Repository map and main execution paths with code entry points.
- [`docs/profiles.md`](/home/kartikeya_vashishtha/hardline-try2/docs/profiles.md)
  Actual on-disk profile format and plugin-owned config structure.
- [`docs/plugins.md`](/home/kartikeya_vashishtha/hardline-try2/docs/plugins.md)
  Plugin contract, built-in plugin set, and rollback ownership boundaries.
- [`docs/plan-design.md`](/home/kartikeya_vashishtha/hardline-try2/docs/plan-design.md)
  Intended operator-facing direction for planning, apply, rollback, and verification.
- [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md)
  Status page: implemented, partial, wrong, and missing relative to the vision.

## Start Here

For a new engineer, the fastest reading order is:

1. [`README.md`](/home/kartikeya_vashishtha/hardline-try2/README.md)
2. [`docs/architecture.md`](/home/kartikeya_vashishtha/hardline-try2/docs/architecture.md)
3. [`docs/profiles.md`](/home/kartikeya_vashishtha/hardline-try2/docs/profiles.md)
4. [`docs/plugins.md`](/home/kartikeya_vashishtha/hardline-try2/docs/plugins.md)
5. [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md)

## Relevant Files

- CLI entry point: [`cmd/hardline/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/hardline/main.go)
- CLI parsing and versioning: [`internals/cli/cli.go`](/home/kartikeya_vashishtha/hardline-try2/internals/cli/cli.go), [`internals/cli/version.go`](/home/kartikeya_vashishtha/hardline-try2/internals/cli/version.go)
- Profile loading and validation: [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go), [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go)
- Planning: [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go), [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go)
- Apply: [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go), [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go)
- Rollback: [`internals/rollback/journal.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go), [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go)
- Plugin contract: [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)
- Shared plugin registry owner: [`internals/registry/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/registry/registry.go)
- Built-in plugin registration: [`internals/plugins/builtin/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go)
- Bundled external plugin project: [`pluginprojects/firewalltemplate/bundle.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/bundle.go)
- External plugin loading: [`internals/plugins/loader.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/loader.go)
- SSH and remote execution: [`internals/connection/connection.go`](/home/kartikeya_vashishtha/hardline-try2/internals/connection/connection.go), [`internals/remote/exec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/remote/exec.go), [`internals/remote/fs.go`](/home/kartikeya_vashishtha/hardline-try2/internals/remote/fs.go)
- Verification and signing: [`internals/verify/integrity.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/integrity.go), [`cmd/profiletool/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main.go)

## Profile Layout

A profile is a directory that contains:

- `profile.json`
- `actions/*.json`
- `templates/*.tmpl`
- `manifest.json`
- `manifest.sig`

The bundled example is [`base-secure-ubuntu-24.04-lts/profile.json`](/home/kartikeya_vashishtha/hardline-try2/base-secure-ubuntu-24.04-lts/profile.json).

`profile.json` declares:

- profile identity and OS metadata
- the supported profile schema version
- the minimum hardline version
- ordered action file paths
- declared template paths

Each action file contains ordered `steps`. Each step has core metadata:

- `id`
- `plugin`
- `severity`
- `risk_class`
- `control_tags`
- `config`
- optional `allow_unvalidated`

Plugin-specific fields live under `config`.

## Built-in Plugins

The built-in registry is assembled in [`internals/plugins/builtin/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go).

Supported built-in plugins:

- `packages`
- `template`
- `service`
- `firewall`

Bundled external plugin:

- `firewall_template`
  Built from [`pluginprojects/firewalltemplate`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate) into `tmp/plugins/firewall_template.so` by `make build`.
  Building and loading the shared object requires a C compiler in `PATH` because Go plugins use cgo-enabled linking.

Before `plan` and `apply`, the binary attempts to load external Go plugins from a `plugins/` directory next to the compiled binary. Shared objects must export `HardlinePluginV1`.

## Execution Model

`plan`:

1. Loads the profile directory.
2. Checks hardline version compatibility.
3. Validates `profile.json` and each action file against the generated JSON schemas.
4. Connects to the target host over SSH.
5. Runs each step's plugin planner and prints a human-readable report.

`apply`:

1. Runs `plan` first.
2. Reconnects to the target host.
3. Re-checks version compatibility and schema validation.
4. Captures rollback state for each step.
5. Executes each step in action-file order.
6. Automatically rolls back recorded steps if a later step fails.
7. Saves the last successful rollback journal.

`rollback last`:

1. Loads the last successful journal for the target host.
2. Reconnects over SSH.
3. Replays rollback objects in reverse order.

## Signing And Verification

Profile signing is handled by [`cmd/profiletool/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main.go).

Useful targets:

- `make keygen`
- `make sign-profile PROFILE_DIR=<profile-dir>`
- `make test`
- `make build`

`verify-profile` checks:

- the Ed25519 signature on `manifest.json`
- the declared manifest version and hash algorithm
- the SHA-256 hash of every regular file in the profile directory except `manifest.json` and `manifest.sig`

## Testing

Repository tests run through `make test`, which enforces repo-wide coverage with a default minimum of `90%`.

# Hardline

Hardline is a signed-profile runner for applying opinionated system configuration to remote Linux hosts over SSH. It verifies profile contents locally, checks the target host before changes, produces a plan, applies steps with non-interactive `sudo`, and stores rollback journals so the last successful run can be reverted.

The repo ships with:

- the `hardline` CLI in [`cmd/hardline/main.go`](cmd/hardline/main.go)
- the `profiletool` helper in [`cmd/profiletool/main.go`](cmd/profiletool/main.go)
- built-in plugins for packages, templates, services, and nftables
- an example Ubuntu 24.04 hardening profile in [`base-secure-ubuntu-24.04-lts/profile.json`](base-secure-ubuntu-24.04-lts/profile.json)
- an example external plugin project in [`pluginprojects/firewalltemplate/handlers.go`](pluginprojects/firewalltemplate/handlers.go)

## Quick Start

Build the project:

```bash
make build
```

Verify, plan, and apply the included example profile:

```bash
tmp/hardline verify-profile base-secure-ubuntu-24.04-lts
tmp/hardline plan base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
tmp/hardline apply base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

Roll back the last successful apply for that profile:

```bash
tmp/hardline rollback base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

Notes:

- The remote user must be able to run `sudo -n`.
- The target host must already exist in your `known_hosts` file.
- `apply` automatically re-runs verification and planning before it makes changes.

## For Users

If you want to run Hardline without digging through internals, start here:

- [User Guide](docs/user-guide.md) for the user-facing docs hub
- [Getting Started](docs/users/getting-started.md) for prerequisites, build outputs, and the basic `verify-profile` / `plan` / `apply` / `rollback` flow
- [Troubleshooting](docs/users/troubleshooting.md) for common failures
- [Signing And Verification](docs/users/signing-and-verification.md) for profile trust and key handling

## For Profile Authors

If you are writing or editing profiles, start here:

- [Profile Authoring Guide](docs/profile-authoring.md) for the authoring docs hub
- [Profile Structure](docs/profiles/structure.md) for `profile.json` and directory layout
- [Action Files](docs/profiles/action-files.md) for step structure and execution ordering
- [Built-In Plugins](docs/profiles/builtin-plugins.md) for plugin config reference
- [Overrides And Signing](docs/profiles/overrides-and-signing.md) for runtime inputs and profile signing
- [Example Profile](base-secure-ubuntu-24.04-lts/profile.json) for a concrete Ubuntu 24.04 hardening profile

## Internals

If you want to understand how the repo is wired together, extend it, or review the architecture:

- [Internals Guide](docs/internals.md) for the internals docs hub
- [Architecture](docs/internals/architecture.md) for package layout and module boundaries
- [Data Models](docs/internals/data-models.md) for profiles, manifests, reports, and journals
- [Execution Flow](docs/internals/execution-flow.md) for `verify`, `plan`, `apply`, and `rollback`
- [Planning And Reports](docs/internals/planning-and-reports.md) for planner output and report generation
- [Plugin System](docs/internals/plugin-system.md) for the plugin contract and loading model
- [Rollback](docs/internals/rollback.md) for journal lifecycle and conflict handling
- [Safety And Trust](docs/internals/safety-and-trust.md) for signing, overrides, managed paths, and external plugin trust
- [Contributing Notes](Contributing.md) for project-specific style constraints
- [Profile Schema](schema/profile.schema.json) and [Action Schema](schema/action-file.schema.json) for the generated JSON schemas used during validation

## Main Commands

```text
hardline plan <profile> [--host HOST] [--user USER] [--keypath PATH] ...
hardline apply <profile> [--host HOST] [--user USER] [--keypath PATH] ...
hardline rollback <profile> [--host HOST] [--user USER] [--keypath PATH] ...
hardline verify-profile <profile> [--overrides-file PATH] ...
hardline verify <profile>   # alias for verify-profile
hardline vp <profile>       # alias for verify-profile
hardline version
```

Useful flags:

- `--report-file` and `--report-format json|yaml|md` to save plan/apply output
- `--log-file` to write plain-text logs
- `--overrides-file` or `profile.overrides.json` for runtime overrides
- `--allow-local-key` to verify profiles with `/etc/hardline/profile_signing_pub.pem`
- `--keep-local-rollback` to keep the runner-side journal after a successful apply
- `--force-rollback` to roll back even if a managed object changed after apply

## Build Outputs

`make build` produces:

- `tmp/hardline`
- `tmp/profiletool`
- `tmp/plugins/firewall_template.so`

External plugins are loaded from a `plugins/` directory adjacent to the `hardline` binary, so if you move the binary, move the plugin directory with it.

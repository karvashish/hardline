# Hardline - Signed-Profile Linux Hardening

[![Unit Tests](https://github.com/karvashish/hardline/actions/workflows/unit-tests.yml/badge.svg?branch=main&event=push)](https://github.com/karvashish/hardline/actions/workflows/unit-tests.yml)
[![Build](https://github.com/karvashish/hardline/actions/workflows/build.yml/badge.svg?branch=main&event=push)](https://github.com/karvashish/hardline/actions/workflows/build.yml)

Hardline is a signed-profile runner for applying opinionated system configuration to remote Linux hosts over SSH. It verifies profile contents locally, checks the target host before changes, produces a plan, applies steps with non-interactive `sudo`, and stores rollback journals so the last successful run can be reverted.

## What's In The Trusted Execution Surface

A signed Hardline profile can only ask the runtime to do things the runtime knows how to do. The vocabulary is five typed plugin configs:

- `packages` - install / purge named packages
- `template` - render a file to a managed destination path with a fixed mode
- `service` - enable / disable / restart named systemd units
- `firewall` - declarative nftables rules
- `file_meta` - re-stamp mode / owner / group / immutable / append-only flags on existing paths

That is the entire surface a reviewer needs to read to know what a profile will do when applied. There is no `exec`, no `command`, no `script`, no templating language with side effects - signing the manifest is signing the full set of instructions, not a wrapper around them.

Hardline runs the hardening step, and only the hardening step. Provisioning stays where it is - Terraform, cloud-init, or Ansible brings the host up and creates the admin user. Hardline takes over once the host is ready.

Beyond the narrow vocabulary, three supporting properties worth knowing:

- **Runtime signature verification.** The runner verifies the profile's signature against a trusted key before any step executes - not at git-clone time, not at CI time, at the moment of apply.
- **Rollback journal with conflict detection.** Each step records before/after snapshots. Rollback restores the before state and refuses to proceed if the current remote state has drifted since apply (unless `--force-rollback` is passed).
- **Apply lock on the target.** Only one apply per host at a time; concurrent runs would corrupt the journal.

The repo ships with:

- the `hardline` CLI in [`cmd/hardline/main.go`](cmd/hardline/main.go)
- the `profiletool` helper in [`cmd/profiletool/main.go`](cmd/profiletool/main.go)
- repo-wide Go unit tests plus GitHub Actions badges for `main`
- a Terraform-backed integration test harness in [`integration-tests/`](integration-tests/) for real Ubuntu 24.04 validation across plan/apply/rollback, plugins, overrides, and failure paths
- built-in plugins for packages, templates, services, nftables, and file metadata
- an example Ubuntu 24.04 hardening profile in [`starter-secure-ubuntu-24.04-lts/profile.json`](starter-secure-ubuntu-24.04-lts/profile.json)
- an example external plugin project in [`pluginprojects/firewalltemplate/handlers.go`](pluginprojects/firewalltemplate/handlers.go)

## Install

Download a prebuilt release archive from [github.com/karvashish/hardline/releases](https://github.com/karvashish/hardline/releases). Every tag publishes Linux (amd64, arm64) and Windows (amd64, arm64) archives plus the example profile as a separate tarball. Each file has a companion `.sha256` for verification. See the [Install Guide](docs/users/install.md) for verify/extract/PATH steps, or [Build From Source](docs/users/getting-started.md#build-from-source) if you prefer to build from a checkout.

## Quick Start

Assuming `hardline` is on your `PATH` and you have a copy of the example profile directory (from the release archive or the repo checkout), verify, plan, apply, and roll back:

```bash
hardline verify-profile starter-secure-ubuntu-24.04-lts
hardline plan starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
hardline apply starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
hardline rollback starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

Notes:

- The remote user must be able to run `sudo -n`.
- The target host must already exist in your `known_hosts` file (or set `HARDLINE_KNOWN_HOSTS`).
- `apply` automatically re-runs verification and planning before it makes changes.

## Supported Targets

Hardline targets Linux hosts. Current support covers Debian-family systems with systemd and nftables: the `packages` plugin uses `apt-get`, the `service` plugin uses `systemctl`, and the `firewall` plugin renders an `nftables` include under `/etc/nftables.d/`. Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Debian 12 or later are supported, with the integration tests and the shipped starter profile currently targeting Ubuntu 24.04 LTS; coverage of the other releases is pending additional testing.

Support for RHEL-family distributions (Rocky, Alma, RHEL 9 or later) is planned. The `packages` plugin is the only distribution-specific component; the remaining functionality is distribution-independent. See issue [#20](https://github.com/karvashish/hardline/issues/20).

## For Users

If you want to run Hardline without digging through internals, start here:

- [User Guide](docs/user-guide.md) for the user-facing docs hub
- [Install Guide](docs/users/install.md) for downloading, verifying, and putting a release on your `PATH`
- [Getting Started](docs/users/getting-started.md) for prerequisites and the basic `verify-profile` / `plan` / `apply` / `rollback` flow
- [CLI Reference](docs/users/cli-reference.md) for every command, flag, environment variable, and exit code
- [Troubleshooting](docs/users/troubleshooting.md) for common failures
- [Failure And Recovery](docs/users/failure-and-recovery.md) for what happens when a run is interrupted or a host disappears mid-apply
- [Signing And Verification](docs/users/signing-and-verification.md) for profile trust and key handling

## For Profile Authors

If you are writing or editing profiles, start here:

- [Profile Authoring Guide](docs/profile-authoring.md) for the authoring docs hub
- [Profile Structure](docs/profiles/structure.md) for `profile.json` and directory layout
- [Action Files](docs/profiles/action-files.md) for step structure and execution ordering
- [Built-In Plugins](docs/profiles/builtin-plugins.md) for plugin config reference
- [Overrides And Signing](docs/profiles/overrides-and-signing.md) for runtime inputs and profile signing
- [Example Profile](starter-secure-ubuntu-24.04-lts/profile.json) for a concrete Ubuntu 24.04 hardening profile

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
- [Testing](docs/internals/testing.md) for unit coverage, CI workflows, and the Terraform-backed integration harness
- [Contributing Notes](Contributing.md) for project-specific style constraints
- [Releasing](docs/releasing.md) for how versions get cut, tagged, built, and published
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

For every flag, environment variable, and exit code, see the [CLI Reference](docs/users/cli-reference.md).

## Build Outputs

`make build` produces:

- `tmp/hardline`
- `tmp/profiletool`
- `tmp/plugins/firewall_template.so`

External plugins are loaded from a `plugins/` directory adjacent to the `hardline` binary, so if you move the binary, move the plugin directory with it.

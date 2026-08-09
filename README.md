# Hardline - Signed-Profile Linux Hardening

[![Unit Tests](https://github.com/karvashish/hardline/actions/workflows/unit-tests.yml/badge.svg?branch=main&event=push)](https://github.com/karvashish/hardline/actions/workflows/unit-tests.yml)
[![Build](https://github.com/karvashish/hardline/actions/workflows/build.yml/badge.svg?branch=main&event=push)](https://github.com/karvashish/hardline/actions/workflows/build.yml)

**Documentation: [karvashish.github.io/hardline](https://karvashish.github.io/hardline/)**

Hardline is a signed-profile runner for applying opinionated system configuration to remote Linux hosts over SSH. It verifies profile contents locally, checks the target host before changes, produces a plan, applies steps with non-interactive `sudo`, and stores rollback journals so the last successful run can be reverted.

![Hardline demo: verify, plan, apply, and roll back a signed profile on a fresh Ubuntu 24.04 host](docs/assets/demo.gif)

A real run of [`demo-profile/`](demo-profile/) against a throwaway Ubuntu 24.04 host, with plain `ssh` reading the host's own state before apply, after apply, and after rollback. Output is verbatim; timing and paths are not.

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
- a Terraform-backed integration test harness in [`integration-tests/`](integration-tests/) that provisions a real Ubuntu 24.04, Rocky 9, or Fedora host (`ITEST_OS`) and validates plan/apply/rollback, plugins, overrides, and failure paths against it
- built-in plugins for packages, templates, services, nftables, and file metadata
- example hardening profiles in [`starter-secure-ubuntu-24.04-lts/profile.json`](starter-secure-ubuntu-24.04-lts/profile.json) and [`starter-secure-rocky-9/profile.json`](starter-secure-rocky-9/profile.json)
- an example external plugin project in [`pluginprojects/firewalltemplate/handlers.go`](pluginprojects/firewalltemplate/handlers.go)

## Install

Download a prebuilt release archive from [github.com/karvashish/hardline/releases](https://github.com/karvashish/hardline/releases). Every tag publishes Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64, arm64) archives plus the example profile as a separate tarball. Each file has a companion `.sha256` for verification. See the [Install Guide](docs/users/install.md) for verify/extract/PATH steps, or [Build From Source](docs/users/getting-started.md#build-from-source) if you prefer to build from a checkout.

## Quick Start

Assuming `hardline` is on your `PATH` and you have a copy of the example profile directory (from its separate release archive or the repo checkout), verify, plan, apply, and roll back:

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

## Example Run

To see what Hardline produces without running it, [`docs/examples/`](docs/examples/) holds the verify, plan, apply, and rollback logs, the plan report in all three formats, and the rollback journal from a real run of the starter profile against a fresh Ubuntu 24.04 host (host and paths redacted).

## Supported Targets

Hardline targets Linux hosts running systemd and nftables. The engine itself carries no distribution knowledge: the profile picks its package manager by naming the plugin (`packages_apt`, `packages_dnf4` or `packages_dnf5`) and declares the nftables main config the host's service loads (`firewall.main_config`: `/etc/nftables.conf` or `/etc/sysconfig/nftables.conf`). Anything outside those sets is rejected at `verify-profile`, before a connection is made. Service units are named verbatim, so a profile says `ssh` or `sshd` depending on its target.

| Package plugin | nftables main config | Typical hosts |
| --- | --- | --- |
| `packages_apt` | `/etc/nftables.conf` | Debian, Ubuntu |
| `packages_dnf4` | `/etc/sysconfig/nftables.conf` | RHEL 9, Rocky 9, Alma 9 |
| `packages_dnf5` | `/etc/sysconfig/nftables.conf` | Fedora 41 or later, RHEL 10 |

A profile is not portable across those rows: it pins one target and the runner enforces it. `os.family` is matched case-insensitively against `/etc/os-release` `ID` **exactly**, and `os.version` against `VERSION_ID` component by component, so a profile declaring `rocky` is refused on a host reporting `almalinux` or `rhel`, however similar the two are.

The two shipped starter profiles therefore apply to exactly these hosts:

| Starter profile | Accepted host |
| --- | --- |
| `starter-secure-ubuntu-24.04-lts` | `ID=ubuntu`, `VERSION_ID` 24.04 or 24.04.x |
| `starter-secure-rocky-9` | `ID=rocky`, `VERSION_ID` 9 or 9.x |

To harden a host the starters do not cover, copy the nearest one, change `os.family`/`os.version` and the package plugin to match, and sign it with your own key. Ubuntu 24.04 LTS and Rocky 9 are the targets the integration suite runs against; Fedora is exercised as the `packages_dnf5` verification target and ships no starter profile.

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
- [Example Profiles](starter-secure-ubuntu-24.04-lts/profile.json) for a concrete Ubuntu 24.04 hardening profile, and [`starter-secure-rocky-9`](starter-secure-rocky-9/profile.json) for its RHEL-family counterpart

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

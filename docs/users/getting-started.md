# Getting Started

This page assumes `hardline` is already on your `PATH`. If it isn't, start with the [Install Guide](install.md).

## Prerequisites

Local machine:

- `hardline` and `profiletool` on `PATH` (or run them from the extracted release directory)
- an SSH private key that can reach the target host
- a populated `known_hosts` file, or `HARDLINE_KNOWN_HOSTS` pointing to one

Remote machine:

- SSH access for the user you pass to `--user`
- non-interactive `sudo` through `sudo -n`. This is required even when you connect as root: every privileged command is issued as `sudo -n sh -lc ...` with no root-user shortcut, so a target that has no `sudo` binary installed fails the connection preflight regardless of which user you connect as
- an OS that matches the profile declaration

For `starter-secure-ubuntu-24.04-lts`:

- the target should report `ID=ubuntu`
- the target should report `VERSION_ID=24.04`
- package management is expected to work through `apt-get`
- service management is expected to work through `systemctl`

For `starter-secure-rocky-9`:

- the target should report `ID=rocky`
- the target should report `VERSION_ID=9` or a `9.x` point release
- package management is expected to work through `dnf` (dnf4)
- service management is expected to work through `systemctl`

## Get The Example Profile

Each starter profile is published as its own tarball on every release: `starter-secure-ubuntu-24.04-lts` and its RHEL-family counterpart `starter-secure-rocky-9`. Extracting one gives you the directory the commands below name. You can also `git clone` the repo and use `profiles/<name>` in place. See [Install Guide → Download The Example Profile](install.md#download-the-example-profile) for the tarball route.

## First Command

Start by verifying the profile locally:

```bash
hardline verify-profile starter-secure-ubuntu-24.04-lts
```

`verify`, `vp`, and `verify-profile` all work for this command.

This checks:

- `manifest.json` and `manifest.sig`
- the profile and action file schemas
- required templates on disk
- plugin availability
- runtime override keys when overrides are provided

## Basic Workflow

### Generate A Plan

```bash
hardline plan starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

`plan` inspects remote state and prints what Hardline expects to change. It does not mutate the target.

### Apply A Profile

```bash
hardline apply starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

Important behavior:

- `apply` runs verification first
- `apply` runs the planner before mutation
- Hardline keeps a remote rollback journal for the last successful run
- only one apply can run on the same host at a time

Keep the local rollback journal too:

```bash
hardline apply starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --keep-local-rollback
```

### Roll Back The Last Successful Apply

```bash
hardline rollback starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

If a managed file, package, or service changed after the original apply, rollback stops rather than overwriting the newer state.

Override that protection carefully:

```bash
hardline rollback starter-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --force-rollback
```

## Useful Flags

- `--log-file PATH`
- `--report-file PATH`
- `--report-format json|yaml|md`
- `--overrides-file PATH`
- `--allow-local-key`

The [CLI Reference](cli-reference.md) has the full list with descriptions, shorthands, and environment variables.

## Build From Source

If you prefer building from a checkout instead of downloading a release, clone the repo and run `make build`. This requires **Go 1.26.1 or newer**. The build produces:

- `tmp/hardline`
- `tmp/profiletool`
- `tmp/plugins/firewall_template.so`

Either add `./tmp` to your `PATH` for the rest of the session, or run commands with the explicit `tmp/` prefix (`tmp/hardline verify-profile ...`). If you relocate the binary after building, keep external plugins in a sibling `plugins/` directory next to it — see the note in the [Install Guide](install.md#put-hardline-on-your-path).

There is also a Terraform-backed integration harness under `integration-tests/` for live-host validation. See [Internals → Testing](../internals/testing.md).

Related:

- [Overrides](overrides.md)
- [Signing And Verification](signing-and-verification.md)
- [Failure And Recovery](failure-and-recovery.md)

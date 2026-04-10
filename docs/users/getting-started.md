# Getting Started

## Prerequisites

Local machine:

- Go `1.26.1` or newer if you are building from source
- an SSH private key that can reach the target host
- a populated `known_hosts` file, or `HARDLINE_KNOWN_HOSTS` pointing to one

Remote machine:

- SSH access for the user you pass to `--user`
- non-interactive `sudo` through `sudo -n`, unless you connect as root
- an OS that matches the profile declaration

For the included sample profile:

- the target should report `ID=ubuntu`
- the target should report `VERSION_ID=24.04`
- package management is expected to work through `apt-get`
- service management is expected to work through `systemctl`

## Build

From the repo root:

```bash
make build
```

That creates:

- `tmp/hardline`
- `tmp/profiletool`
- `tmp/plugins/firewall_template.so`

If you relocate the `hardline` binary, keep external plugins in a sibling `plugins/` directory next to it.

## First Command

Start by verifying the included profile locally:

```bash
tmp/hardline verify-profile base-secure-ubuntu-24.04-lts
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
tmp/hardline plan base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

`plan` inspects remote state and prints what Hardline expects to change. It does not mutate the target.

### Apply A Profile

```bash
tmp/hardline apply base-secure-ubuntu-24.04-lts \
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
tmp/hardline apply base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --keep-local-rollback
```

### Roll Back The Last Successful Apply

```bash
tmp/hardline rollback base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519
```

If a managed file, package, or service changed after the original apply, rollback stops rather than overwriting the newer state.

Override that protection carefully:

```bash
tmp/hardline rollback base-secure-ubuntu-24.04-lts \
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

Related:

- [Overrides](overrides.md)
- [Signing And Verification](signing-and-verification.md)

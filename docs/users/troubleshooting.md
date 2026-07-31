# Troubleshooting

Errors you're likely to hit on day one, and what to do about them. For interrupted runs, stuck locks, and partial applies, see [Failure And Recovery](failure-and-recovery.md). For signing-specific issues, see [Signing And Verification](signing-and-verification.md).

## SSH And Connection

### `ssh host is required` / `ssh user is required`

`plan`, `apply`, and `rollback` all require remote connection details. Pass `--host`, `--user`, and `--keypath` (or their shorthands `-H`, `-u`, `-k`).

An omitted `--keypath` has no dedicated message — Hardline tries to read the empty path and surfaces the OS error (`open : no such file or directory`).

### `known_hosts file ... does not exist`

Hardline does **not** perform trust-on-first-use for host keys. The target must already be in a `known_hosts` file before Hardline will connect.

```bash
ssh-keyscan example.com >> ~/.ssh/known_hosts
```

If your `known_hosts` is in a non-default location, point Hardline at it:

```bash
export HARDLINE_KNOWN_HOSTS=/path/to/known_hosts
```

### `ssh: handshake failed` or `host key mismatch`

Your `known_hosts` has a stale entry for this host — most commonly because the remote OS was reinstalled, a VM was recreated, or a cloud instance was rebuilt with the same DNS name. Fix by removing the old entry and re-adding:

```bash
ssh-keygen -R example.com
ssh-keyscan example.com >> ~/.ssh/known_hosts
```

Do **not** blindly accept new keys — confirm out-of-band that the replacement key is legitimate before re-adding.

### SSH connection hangs or times out

- Confirm the target is reachable at all: `ssh -v -i ~/.ssh/id_ed25519 ubuntu@example.com`
- Check DNS: `getent hosts example.com`
- Check firewall / security group rules on the target
- If the target is behind a jump host, Hardline does **not** read `~/.ssh/config` — connect to the final target directly or set up a local tunnel

### `Permission denied (publickey)`

The private key you passed to `--keypath` is not authorized for the target user. Verify manually:

```bash
ssh -i ~/.ssh/id_ed25519 ubuntu@example.com whoami
```

If `ssh` works directly but Hardline says the key is wrong, make sure you're passing the exact same path (no shell-expanded `~` inside quoted strings, for example).

## Sudo

### `non-interactive sudo is required`

The target user cannot satisfy `sudo -n` — meaning `sudo` wants a password or the user isn't in `sudoers`. Options:

- Add the user to a group with `NOPASSWD` in `/etc/sudoers.d/` (for example, `deploy ALL=(ALL) NOPASSWD: ALL`)
- Connect as a user who already has passwordless sudo
- Connect as `root` directly if that's acceptable in your environment

Hardline never prompts for passwords interactively and never caches them. `sudo -n` or bust.

### `sudo: a password is required` mid-run

The `sudo` timestamp cache expired between steps, or the `sudoers` policy has `tty_tickets` set and Hardline's session got a new tty. Confirm the user has genuine `NOPASSWD` privileges (not just a cached timestamp) before re-running.

## Profile Verification

### `manifest signature verification failed`

Hardline verified the profile against its trusted public key and the signature didn't match. Most common causes:

1. You downloaded a release binary but signed your own profile with a key Hardline doesn't know about. Fix by installing your public key at `/etc/hardline/profile_signing_pub.pem` and passing `--allow-local-key`, or by re-signing the profile with the key the binary trusts.
2. The profile files were edited after signing, so `manifest.json` hashes no longer match. Re-run `profiletool sign` after any edit.
3. `manifest.sig` is empty, corrupt, or was never written. Re-sign.

See [Signing And Verification](signing-and-verification.md) for the full key rotation story.

### `unexpected file not listed in manifest: ...`, `manifest references missing file: ...`, or `hash mismatch for ...`

A file in the profile directory was added, removed, or modified after the manifest was written. Re-sign the profile. `manifest.json`, `manifest.sig`, and `profile.overrides.json` are the only files exempt from the hash walk.

### `local signing key ... has insecure permissions`

Hardline refuses to use `/etc/hardline/profile_signing_pub.pem` unless its mode is `0644` or stricter with no group or world write bit. Fix:

```bash
sudo chmod 0644 /etc/hardline/profile_signing_pub.pem
```

### `OS family mismatch` or `OS version mismatch`

The target host does not match the `os` block declared in `profile.json`. Either connect to a host that matches, or use a profile whose `os` block matches your target. The included base profile targets `ubuntu/24.04/lts`.

## Overrides

### `profile does not allow overrides: <keys>`

Your overrides file contains one or more keys that are not listed in `allowed_overrides` in `profile.json`. The message names every offending key. Either:

- Remove the offending key from your overrides file
- Add the key to `allowed_overrides` and re-sign the profile (only the profile author can do this meaningfully — the override is scoped to what the profile's plugins will actually read)

Remember: plugins must explicitly read an override before it has any effect. Adding a key to `allowed_overrides` does not automatically wire it through.

### `profile.overrides.json` is ignored

Hardline auto-discovers `profile.overrides.json` only when `--overrides-file` is not passed. If you pass `--overrides-file PATH`, **only** that file is read — the auto-discovery file is skipped. Pick one path or the other, not both.

Also note: `profile.overrides.json` is deliberately excluded from the signed manifest. If you're bundling profiles into a signed archive and need the overrides to travel with them, use `--overrides-file` instead so the intent is explicit.

## Packages Plugin

### `apt/dpkg lock is held by another process (PIDs: ...)`

Some other `apt-get`, `dpkg`, `unattended-upgrades`, or the kernel's auto-updater is already running on the target. Hardline checks `/var/lib/dpkg/lock`, `/var/lib/apt/lists/lock`, and `/var/lib/dpkg/lock-frontend` with `fuser` and does not wait — it fails fast with the holding PIDs so you can investigate. Wait a minute and retry, or inspect:

```bash
sudo lsof /var/lib/dpkg/lock
```

If `unattended-upgrades` runs frequently on your target, consider scheduling Hardline runs outside the upgrade window.

### `invalid package name "..."`

The packages plugin validates every name against `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$`. Underscores, slashes, backslashes, spaces, and shell metacharacters are all rejected, and a name may not start with `.`, `+`, or `-`. If you need a package manager feature the built-in plugin won't express, write an external plugin.

## Firewall Plugin

### `nftables config check failed` / errors from `nft`

The firewall plugin shells out to `nft` on the target and has no separate presence check, so a missing `nftables` package surfaces as the underlying command failing — most visibly from `nft -c -f /etc/nftables.conf` during validation. Install the userspace tools in an earlier step via the `packages` plugin, or choose a profile that doesn't use the firewall plugin.

### `nftables.conf missing include for /etc/nftables.d/*.nft`

The plugin requires `/etc/nftables.conf` to contain `include "/etc/nftables.d/*.nft"` and appends the line when it is absent. This error means the check ran against a target where the append had not happened yet or was reverted.

### Rules apply but traffic still blocked

The firewall plugin writes a deterministic ruleset file to the `managed_dest` path declared in the step — `/etc/nftables.d/99-hardline-firewall.nft` in the shipped starter profile — and ensures `/etc/nftables.conf` sources `/etc/nftables.d/*.nft`. If your target has a pre-existing `nftables` ruleset that conflicts (for example, `ufw` or a cloud-init-managed ruleset), the two sets can race. Inspect the live table:

```bash
sudo nft list ruleset
```

## Reports And Output

### `unsupported report format`

Use `--report-format json`, `yaml`, or `md`. If you pass only `--report-file`, Hardline infers the format from the extension (`.json`, `.yaml`, `.yml`, `.md`). Any other extension is an error.

### `permission denied` or `is a directory` while writing a report

Hardline creates missing parent directories automatically and overwrites an existing report file if one is already there. These errors mean the destination path itself is not writable, or that you pointed `--report-file` at a directory instead of a filename.

## Rollback

### `rollback refuses to overwrite newer changes`

That is the conflict protection working as designed. A managed file, package, or service has been modified on the target *after* the original apply, and rolling back would overwrite the newer state.

Review the reported conflicts carefully. If you're confident the newer state is unwanted, re-run with `--force-rollback`. If the newer state came from another tool or a second Hardline profile, prefer fixing the conflict at its source.

### `no journal found for profile "..."`

No successful apply has been recorded for this profile on this host — `/var/lib/hardline/runs/<profileID>/` is empty or absent. Either it was never applied, or the journal was cleaned up (the remote journal is deleted after a successful rollback, and `--keep-local-rollback` controls the runner-side copy).

### `last run is not marked successful (status="failed")`

A journal exists but records a failed or interrupted apply. `rollback` only replays journals with `status: success`; a failed apply already attempted its own automatic rollback. See [Failure And Recovery](failure-and-recovery.md).

## Version And Install

### `hardline: command not found`

The `hardline` binary is not on your `PATH`. Either:

- Add the extracted release directory to `PATH` (see [Install Guide](install.md))
- Run commands with the full path: `/path/to/hardline verify-profile ...`
- If you built from source, the binary is at `tmp/hardline` relative to the repo root

### `hardline version` reports an unexpected version

Hardline reports the version embedded from `internals/cli/version.json`. Source builds no longer derive the CLI version string from `git describe`.

If the version looks wrong:

- Inspect `internals/cli/version.json`
- Rebuild the binaries after updating it
- If this is meant to be a release build, check the release workflow or release PR metadata rather than the git working tree state

## Getting More Detail

Almost every command accepts `--debug` (or `-d`) to print verbose internal state:

```bash
hardline plan starter-secure-ubuntu-24.04-lts -H example.com -u ubuntu -k ~/.ssh/id_ed25519 -d
```

Combine with `--log-file PATH` to capture the full trace for a bug report.

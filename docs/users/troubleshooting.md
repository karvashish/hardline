# Troubleshooting

Errors you're likely to hit on day one, and what to do about them. For interrupted runs, stuck locks, and partial applies, see [Failure And Recovery](failure-and-recovery.md). For signing-specific issues, see [Signing And Verification](signing-and-verification.md).

## SSH And Connection

### `ssh host is required` / `ssh user is required` / `ssh key path is required`

`plan`, `apply`, and `rollback` all require remote connection details. Pass `--host`, `--user`, and `--keypath` (or their shorthands `-H`, `-u`, `-k`).

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

### `manifest.sig: signature verification failed`

Hardline verified the profile against its trusted public key and the signature didn't match. Most common causes:

1. You downloaded a release binary but signed your own profile with a key Hardline doesn't know about. Fix by installing your public key at `/etc/hardline/profile_signing_pub.pem` and passing `--allow-local-key`, or by re-signing the profile with the key the binary trusts.
2. The profile files were edited after signing, so `manifest.json` hashes no longer match. Re-run `profiletool sign` after any edit.
3. `manifest.sig` is empty, corrupt, or was never written. Re-sign.

See [Signing And Verification](signing-and-verification.md) for the full key rotation story.

### `manifest.json: file ... not listed in manifest` or `hash mismatch for ...`

A file in the profile directory was added, removed, or modified after the manifest was written. Re-sign the profile.

### `local signing key is group-writable` or `world-writable`

Hardline refuses to use `/etc/hardline/profile_signing_pub.pem` unless its mode is `0644` or stricter with no group or world write bit. Fix:

```bash
sudo chmod 0644 /etc/hardline/profile_signing_pub.pem
```

### `OS family mismatch` or `OS version mismatch`

The target host does not match the `os` block declared in `profile.json`. Either connect to a host that matches, or use a profile whose `os` block matches your target. The included base profile targets `ubuntu/24.04/lts`.

## Overrides

### `profile does not allow overrides` or `override key not allowed: ...`

Your overrides file contains a key that is not listed in `allowed_overrides` in `profile.json`. Either:

- Remove the offending key from your overrides file
- Add the key to `allowed_overrides` and re-sign the profile (only the profile author can do this meaningfully — the override is scoped to what the profile's plugins will actually read)

Remember: plugins must explicitly read an override before it has any effect. Adding a key to `allowed_overrides` does not automatically wire it through.

### `profile.overrides.json` is ignored

Hardline auto-discovers `profile.overrides.json` only when `--overrides-file` is not passed. If you pass `--overrides-file PATH`, **only** that file is read — the auto-discovery file is skipped. Pick one path or the other, not both.

Also note: `profile.overrides.json` is deliberately excluded from the signed manifest. If you're bundling profiles into a signed archive and need the overrides to travel with them, use `--overrides-file` instead so the intent is explicit.

## Packages Plugin

### `apt lock held by another process`

Some other `apt-get`, `dpkg`, `unattended-upgrades`, or the kernel's auto-updater is already running on the target. Hardline does not wait for locks — it fails fast so you can investigate. Wait a minute and retry, or inspect:

```bash
sudo fuser /var/lib/dpkg/lock-frontend
```

If `unattended-upgrades` runs frequently on your target, consider scheduling Hardline runs outside the upgrade window.

### `package name invalid`

The packages plugin validates package names against a conservative regex. Backslashes, spaces, and shell metacharacters are rejected. If you need a package manager feature the built-in plugin won't express, write an external plugin.

## Firewall Plugin

### `nftables not installed` / `nft command not found`

The base profile's firewall plugin expects `nftables` userspace tools on the target. Install them explicitly in an earlier step via the `packages` plugin, or choose a profile that doesn't use the firewall plugin.

### Rules apply but traffic still blocked

Hardline writes a deterministic include file at `/etc/nftables.d/99-hardline-firewall.nft` and ensures `/etc/nftables.conf` sources `/etc/nftables.d/*.nft`. If your target has a pre-existing `nftables` ruleset that conflicts (for example, `ufw` or a cloud-init-managed ruleset), the two sets can race. Inspect the live table:

```bash
sudo nft list ruleset
```

## Reports And Output

### `unsupported report format`

Use `--report-format json`, `yaml`, or `md`. If you pass only `--report-file`, Hardline infers the format from the extension (`.json`, `.yaml`, `.yml`, `.md`). Any other extension is an error.

### `report file already exists`

Hardline does not overwrite existing report files. Delete the old one, pick a different path, or use a versioned filename.

## Rollback

### `rollback refuses to overwrite newer changes`

That is the conflict protection working as designed. A managed file, package, or service has been modified on the target *after* the original apply, and rolling back would overwrite the newer state.

Review the reported conflicts carefully. If you're confident the newer state is unwanted, re-run with `--force-rollback`. If the newer state came from another tool or a second Hardline profile, prefer fixing the conflict at its source.

### `no rollback journal found`

No successful apply has been recorded for this profile on this host. Either it was never applied, or the journal was cleaned up (the remote journal is deleted after a successful rollback, and `--keep-local-rollback` controls the runner-side copy).

## Version And Install

### `hardline: command not found`

The `hardline` binary is not on your `PATH`. Either:

- Add the extracted release directory to `PATH` (see [Install Guide](install.md))
- Run commands with the full path: `/path/to/hardline verify-profile ...`
- If you built from source, the binary is at `tmp/hardline` relative to the repo root

### `hardline version` reports `dev` or a commit hash instead of a tag

You're running a development build, not a tagged release. The `git describe` used at build time prints `dev` when there are no tags, or `<short-sha>-dirty` when there are uncommitted changes in the checkout. This is expected for source builds between releases.

## Getting More Detail

Almost every command accepts `--debug` (or `-d`) to print verbose internal state:

```bash
hardline plan base-secure-ubuntu-24.04-lts -H example.com -u ubuntu -k ~/.ssh/id_ed25519 -d
```

Combine with `--log-file PATH` to capture the full trace for a bug report.

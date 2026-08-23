# Safety And Trust

This page focuses on the trust boundaries and guardrails enforced across the codebase.

## Signed Profile Verification

Profiles are verified through:

- `manifest.json`
- `manifest.sig`
- an Ed25519 public key

By default, verification uses the public key embedded into the binary. With `--allow-local-key`, verification switches to:

```text
/etc/hardline/profile_signing_pub.pem
```

On Unix, that local key is opened with `O_NOFOLLOW` and every check runs against the resulting descriptor rather than the path, so there is no window between what was checked and what is read. It must be a regular file, owned by root, and not group-writable or world-writable (mode `0644` or stricter). A non-root owner is refused outright: that uid could otherwise swap the key hardline verifies against.

The Windows build cannot make either guarantee. `O_NOFOLLOW` has no equivalent there, so the key is opened with a plain `os.Open` that will follow a link, and there is no uid to compare, so the root-owner check is skipped rather than failed. The regular-file and permission-bit checks still run, but they mean much less against a Windows ACL. Treat `--allow-local-key` on Windows as a convenience for authoring, not as a trust anchor with the Unix guarantees; the embedded key is unaffected on every platform, because it is compiled into the binary and never read from disk.

Verification is two-way: every manifest entry must match a file on disk, and every regular file on disk must appear in the manifest. Only `manifest.json`, `manifest.sig`, and `profile.overrides.json` are exempt, and a non-regular file anywhere in the tree aborts the walk. On top of that, every path listed in `profile.json`'s `actions` and `templates` must be covered by the manifest, so a signed profile cannot point at unsigned content.

There is no second pass over the profile directory later in the run, and none is needed. Verification reads each file once, checks its bytes against the manifest digest, and keeps those verified bytes in memory as `VerifiedManifest.Files`. The `Profile` handed to plan and apply is built from that map, and every later read - action files at load time, template bodies at `LoadTemplate` time - resolves through it rather than through the filesystem. Editing the profile directory after `verify` has returned changes nothing about what gets applied: the run is working from the snapshot that was verified, not from the directory it came from.

## Input Whitelists On The Trusted Surface

A signed profile is trusted input, but its values still reach a root shell, so each one is narrowed to the smallest set that works rather than escaped and hoped for:

| Value | Accepted set |
| --- | --- |
| Managed destination (`template`, `firewall`, `audit`, `ssh`) | `[A-Za-z0-9._/-]`, under `/etc/`, normalized, `99-hardline*` or `00-hardline*` basename, `.conf`/`.nft`/`.rules` |
| `file_meta` path | `[A-Za-z0-9._/@-]`, absolute, normalized, not `/` |
| `file_meta` owner and group | `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$` |
| Package name | `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$` |
| Package version read back from `dpkg-query` | `^[A-Za-z0-9.+:~-]{1,128}$` |
| systemd unit name | `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$` |
| `ssh` service unit | `ssh` or `sshd`, in the profile and again when read back from the journal |
| `ssh` keyword and value | a closed keyword whitelist, each with its own enum or numeric range |
| `ssh` verify context fields | `^[A-Za-z0-9._:-]{1,255}$`, so none can carry the `,` or `=` that separate a connection spec |
| Host and profile ID in journal paths | `[A-Za-z0-9._-]`, everything else replaced with `_` |

The sets deliberately exclude `$`, backticks, parentheses, quotes, backslashes, glob characters, and whitespace, so an accepted value cannot alter a command even before quoting. The leading-alphanumeric requirement on package and unit names stops a value like `--force` from being read as an option rather than an operand.

## Override Trust Boundary

Runtime overrides are intentionally outside the signed manifest.

That design gives operators a place to supply environment-specific values without re-signing the whole profile, but it also means Hardline has to narrow what those values can affect.

Current controls are:

- only JSON objects are accepted
- explicit `--overrides-file` wins over auto-discovery
- override keys must be listed in `allowed_overrides`
- plugins must explicitly opt in to using override values

## Managed File Boundary

For plugins that use `pluginapi.EnforceManagedPath`, managed destinations are restricted to:

- normalized absolute paths under `/etc/`
- basenames starting with `99-hardline` or `00-hardline`
- extensions `.conf`, `.nft`, or `.rules`

That reduces accidental writes outside Hardline's expected configuration scope.

Both prefixes are accepted on every path. The check is a whitelist on the name, not a rule about ordering: `00-hardline` exists for a drop-in directory that keeps the first match rather than the last (`sshd_config.d`), but nothing requires it there or refuses it elsewhere. Which prefix sorts correctly for a given directory is the profile author's call, and [the ssh plugin](../profiles/ssh-plugin.md) is where that matters.

The nftables main config is the one root-written path outside it. Its name is fixed by the profile and the distribution, so it can never satisfy the `hardline` prefix rule; the firewall plugin restores it from its own snapshot instead, and the two-entry whitelist (`/etc/nftables.conf`, `/etc/sysconfig/nftables.conf`) is what a tampered journal has to get past.

## Remote Execution Guardrails

Hardline requires:

- SSH host key verification through `known_hosts`
- non-interactive `sudo`
- OS compatibility with the profile declaration

Apply and rollback both take a remote lock directory at:

```text
/var/lib/hardline/.apply-lock.d
```

It is created with `mkdir`, which is atomic, so it prevents overlapping mutating runs on the same target in either direction.

## External Plugin Trust Boundary

External plugins are a separate trust boundary from signed profiles.

Important facts:

- they are loaded from a `plugins/` directory next to the binary
- they are not signature-verified
- they execute with the same root-capable process context as Hardline
- Hardline refuses to load them from a directory or file that is writable by group or others, owned by a third party, or reached through a symlink
- the same ownership and writability checks run over the plugins directory's whole parent chain, and over what that chain resolves to after symlinks, so a tight directory under a parent someone else can rename is refused too

In practice, that means external plugins should be treated like trusted release artifacts, not like user-provided extensions in a multi-tenant environment.

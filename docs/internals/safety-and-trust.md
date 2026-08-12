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

That local key must not be group-writable or world-writable (mode `0644` or stricter).

Verification is two-way: every manifest entry must match a file on disk, and every regular file on disk must appear in the manifest. Only `manifest.json`, `manifest.sig`, and `profile.overrides.json` are exempt, and a non-regular file anywhere in the tree aborts the walk. On top of that, every path listed in `profile.json`'s `actions` and `templates` must be covered by the manifest, so a signed profile cannot point at unsigned content.

`apply` re-hashes `manifest.json` after connecting and before its first write, comparing it against the digest captured at verify time. An edit to the profile directory between verify and apply aborts the run rather than being applied unsigned.

## Input Whitelists On The Trusted Surface

A signed profile is trusted input, but its values still reach a root shell, so each one is narrowed to the smallest set that works rather than escaped and hoped for:

| Value | Accepted set |
| --- | --- |
| Managed destination (`template`, `firewall`) | `[A-Za-z0-9._/-]`, under `/etc/`, normalized, `99-hardline*` basename, `.conf`/`.nft`/`.rules` |
| `file_meta` path | `[A-Za-z0-9._/@-]`, absolute, normalized, not `/` |
| `file_meta` owner and group | `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$` |
| Package name | `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$` |
| Package version read back from `dpkg-query` | `^[A-Za-z0-9.+:~-]{1,128}$` |
| systemd unit name | `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$` |
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
- basenames starting with `99-hardline`
- extensions `.conf`, `.nft`, or `.rules`

That reduces accidental writes outside Hardline's expected configuration scope.

## Remote Execution Guardrails

Hardline requires:

- SSH host key verification through `known_hosts`
- non-interactive `sudo`
- OS compatibility with the profile declaration

Apply also uses a remote lock directory at:

```text
/var/lib/hardline/.apply-lock.d
```

That prevents overlapping apply runs on the same target.

## External Plugin Trust Boundary

External plugins are a separate trust boundary from signed profiles.

Important facts:

- they are loaded from a `plugins/` directory next to the binary
- they are not signature-verified
- they execute with the same root-capable process context as Hardline
- Hardline refuses to load them from a directory or file that is writable by group or others, owned by a third party, or reached through a symlink

In practice, that means external plugins should be treated like trusted release artifacts, not like user-provided extensions in a multi-tenant environment.

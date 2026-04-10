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

That local key must not be group-writable or world-writable.

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
- Hardline refuses to load them from a world-writable plugin directory

In practice, that means external plugins should be treated like trusted release artifacts, not like user-provided extensions in a multi-tenant environment.

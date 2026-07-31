# File Meta Plugin

Re-stamps ownership, mode, and a bounded set of `chattr` flags on a path that already exists on the target host.

Example:

```json
{
  "id": "sshd-config-perms",
  "plugin": "file_meta",
  "config": {
    "path": "/etc/ssh/sshd_config",
    "mode": "0600",
    "owner": "root",
    "group": "root"
  }
}
```

Config fields:

- `path`: absolute path to an existing file or directory on the target host
- `mode`: octal file mode string such as `0600` (compared against the host's `stat -c %a`, so `0640` and `640` are equal)
- `owner`: user name or numeric uid to `chown` to, matching `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`
- `group`: group name or numeric gid to `chown` to, same pattern as `owner`
- `immutable`: optional boolean — `true` sets the `i` (immutable) attr, `false` clears it, omitted leaves it untouched
- `append_only`: optional boolean — `true` sets the `a` (append-only) attr, `false` clears it, omitted leaves it untouched

At least one of `mode`, `owner`, `group`, `immutable`, or `append_only` must be set; an all-empty config is rejected at verify time.

## Semantics

- **Existing paths only.** The target must already exist. `file_meta` never creates files or directories — a missing target makes `plan` flag the step and `apply` hard-fail. This is why it is not scope-locked to `/etc/99-hardline*` the way `template` is.
- **Absolute path from a narrow character whitelist.** The path must match `^[A-Za-z0-9._/@-]+$` and be absolute and normalized. `@` is kept for systemd template unit paths; `$`, backticks, parentheses, quotes, glob characters, whitespace, control bytes, and all non-ASCII (homoglyph) characters are outside the set. Relative paths, `..` traversal, `//`, and the filesystem root `/` are also rejected, all at verify/plan time before any root command runs. A trailing slash is tolerated and stripped.
- **Directory targets stamp the directory itself.** Pointing `path` at a directory changes that directory's own metadata. There is no recursion and no glob expansion; contents are never touched. To stamp several paths, write several steps.
- **Bounded `chattr`.** Only the `i` (immutable) and `a` (append-only) attributes are managed. Every other ext-family attribute on the target is read but never modified.

## Idempotency

`plan` and `apply` first snapshot the current `mode`/`owner`/`group`/attrs, then compute the delta. Only the fields that differ are changed: an unchanged mode runs no `chmod`, unchanged owner/group runs no `chown`, unchanged attrs run no `chattr`. A second `apply` against an already-stamped target is a no-op and reports no change.

## Immutable lift → chmod → relock ordering

An immutable file rejects `chmod` and `chown`. When a step both manages attrs (`immutable`/`append_only` is set) and needs to change mode or owner/group on a target that currently carries managed attrs, `apply` clears the managed attrs first, applies the mode/owner change, then re-applies the desired attrs last. This lift → change → relock ordering is what lets a single step harden the mode of a file that is already immutable.

## Rollback and conflict detection

- **Deterministic rollback.** Capture records a `file_meta` snapshot of the pre-apply mode/owner/group/attrs. Rollback restores them exactly, clearing managed attrs first so an immutable target does not reject the restoring `chmod`/`chown`, then re-applying the captured attrs. A target that was absent at capture time restores to a no-op; a target that has since been deleted is an error (rollback never re-creates it).
- **Conflict detection.** Rollback compares the target's current mode/owner/group/attrs against the post-apply snapshot. If the metadata drifted, or the path is now absent, rollback refuses unless `--force-rollback` is passed. See [Rollback](../internals/rollback.md) for the journal lifecycle.

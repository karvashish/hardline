# Packages Plugin

Used for `apt-get` operations.

Example:

```json
{
  "id": "packages-base",
  "plugin": "packages",
  "config": {
    "update": "always",
    "upgrade": "once",
    "autoremove": "once",
    "install": ["nftables", "fail2ban"],
    "purge": ["telnet"]
  }
}
```

Config fields:

- `update`, `upgrade`, `autoremove`: `never`, `always`, `once`, `if_<N>[hdw]_since_last`, or omitted
- `install`: package names to install
- `purge`: package names to purge

## Operation Cadence

| Value | When the operation runs |
| --- | --- |
| omitted or `never` | never |
| `always` | on every apply |
| `once` | only when `install`/`purge` would actually change something on this host |
| `if_<N>[hdw]_since_last` | when at least `<N>` hours (`h`), days (`d`), or weeks (`w`) have passed since the last run, or when no run has been recorded |

`<N>` must be a positive integer and the unit must be one of `h`, `d`, `w`; anything else fails validation. The "last run" timestamps are per-operation marker files on the target: `/var/lib/hardline/last-update`, `last-upgrade`, and `last-autoremove`. Their mtime is what the comparison reads, so deleting one makes the next apply run that operation.

Rules:

- package names must match `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$`
- entries must not be empty, and a name cannot repeat within `install` or within `purge`
- the same package cannot appear in both `install` and `purge`
- package operations are guarded by apt/dpkg lock checks, which fail fast rather than wait
- `apt-get` commands run under a 30-minute per-command `timeout` on the target

## Rollback

Rollback of a purge reinstalls the package, preferring the exact version captured before the purge (`apt-get install -y <name>=<version>`) and falling back to an unpinned install if that fails. `update`, `upgrade`, and `autoremove` are not reversible; the journal records them with a best-effort note rather than undoing them.

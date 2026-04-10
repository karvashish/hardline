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

- `update`, `upgrade`, `autoremove`: `never`, `always`, `once`, or `if_<N>[hdw]_since_last`
- `install`: package names to install
- `purge`: package names to purge

Rules:

- package names are validated
- the same package cannot appear in both `install` and `purge`
- package operations are guarded by apt/dpkg lock checks

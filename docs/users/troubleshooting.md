# Troubleshooting

## `ssh host is required` or `ssh user is required`

`plan`, `apply`, and `rollback` require remote connection details. Pass `--host`, `--user`, and `--keypath`.

## `known_hosts file ... does not exist`

Create it first or point Hardline at another file:

```bash
ssh-keyscan example.com >> ~/.ssh/known_hosts
export HARDLINE_KNOWN_HOSTS=~/.ssh/known_hosts
```

## `non-interactive sudo is required`

The target user cannot satisfy `sudo -n`. Fix `sudoers` or connect as a user with passwordless sudo.

## `OS family mismatch` or `OS version mismatch`

The target host does not match the profile's `os` block. Use a matching host or a different profile.

## `profile does not allow overrides`

Your overrides file contains keys that are not listed in `allowed_overrides`.

## `unsupported report format`

Use `json`, `yaml`, or `md`, or pick a report file extension such as `.json`, `.yaml`, `.yml`, or `.md`.

## Rollback refuses to overwrite newer changes

That is the conflict protection working as designed. Review the reported conflicts, then decide whether `--force-rollback` is appropriate.

# Template Plugin

Writes a declared template file to a managed destination.

Example:

```json
{
  "id": "ssh-template-apply",
  "plugin": "template",
  "config": {
    "src": "templates/10-ssh-sshd-config.tmpl",
    "dest": "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
    "mode": "0600"
  }
}
```

Config fields:

- `src`: required. Template path declared in `profile.json` and covered by the signed manifest
- `dest`: required. Managed destination path on the target host
- `mode`: optional octal file mode string such as `0644`. Defaults to `0600` when omitted

Important detail:

- the built-in `template` plugin copies template bytes as-is
- it does not run Go templating or interpolate runtime overrides

Managed destination rules, enforced by `EnforceManagedPath` before any root command runs:

- characters limited to `[A-Za-z0-9._/-]`, which excludes `$`, backticks, parentheses, quotes, backslashes, globs, and whitespace
- must be under `/etc/`
- path must already be normalized (`path.Clean` must be a no-op)
- basename must start with `99-hardline`
- extension must be `.conf`, `.nft`, or `.rules`

The plugin compares size and mode, then content, before writing: a destination that already matches is left alone and the step reports no change.

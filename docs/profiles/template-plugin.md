# Template Plugin

Writes a declared template file to a managed destination.

Example:

```json
{
  "id": "journald-hardening",
  "plugin": "template",
  "config": {
    "src": "templates/50-journald-hardening.conf.tmpl",
    "dest": "/etc/systemd/journald.conf.d/99-hardline.conf",
    "mode": "0644"
  }
}
```

Config fields:

- `src`: required. Template path declared in `profile.json` and covered by the signed manifest
- `dest`: required. Managed destination path on the target host
- `mode`: optional octal file mode string such as `0644`. Defaults to `0600` when omitted

Do not use this plugin for `sshd_config.d`. Writing an sshd drop-in as opaque
bytes leaves nothing to check that it parses, that the daemon took it, or that a
`Match` block did not override it. The [SSH Plugin](ssh-plugin.md) owns that
file and verifies all three.

Important detail:

- the built-in `template` plugin copies template bytes as-is
- it does not run Go templating or interpolate runtime overrides

Managed destination rules, enforced by `EnforceManagedPath` before any root command runs:

- characters limited to `[A-Za-z0-9._/-]`, which excludes `$`, backticks, parentheses, quotes, backslashes, globs, and whitespace
- must be under `/etc/`
- path must already be normalized (`path.Clean` must be a no-op)
- basename must start with `99-hardline`, or with `00-hardline` where the
  drop-in directory keeps the **first** match rather than the last.
  `sshd_config.d` is the case that matters: sshd expands its includes
  lexically and keeps the first value obtained for most keywords, so a
  `99-` file there loses to any earlier vendor or cloud-init drop-in.
  Everywhere else (`sysctl.d`, `journald.conf.d`, `jail.d`, `nftables.d`)
  the last file wins and `99-hardline` is correct.
- extension must be `.conf`, `.nft`, or `.rules`

The plugin compares size and mode, then content, before writing: a destination that already matches is left alone and the step reports no change.

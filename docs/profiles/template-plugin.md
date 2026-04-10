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

- `src`: template path declared in `profile.json`
- `dest`: managed destination path on the target host
- `mode`: octal file mode string such as `0644`

Important detail:

- the built-in `template` plugin copies template bytes as-is
- it does not run Go templating or interpolate runtime overrides

Managed destination rules:

- must be under `/etc/`
- path must already be normalized
- basename must start with `99-hardline`
- extension must be `.conf`, `.nft`, or `.rules`

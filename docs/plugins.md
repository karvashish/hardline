# Plugins

This page documents the plugin surface that exists in code today.

## Plugin contract

The plugin interface is defined by `pkg/pluginapi.Plugin`.

Every plugin must provide:

- `Name`
- `InternalValidation`
- `Apply`
- `Plan`
- `Capture`

Hardline refuses to run a step if its plugin is missing.

Validation policy:

- if `InternalValidation` is `true`, the step is accepted normally
- if `InternalValidation` is `false`, the step must set `allow_unvalidated=true`

## Built-in plugins

The default registry registers four built-ins:

- `packages`
- `template`
- `service`
- `firewall`

## External plugin loading

At process start, Hardline scans `plugins/` next to the executable and loads every `.so` file it finds.

A dynamic plugin must export:

- `HardlinePluginV1`

This repo currently builds one external plugin:

- `firewall_template`

## Rollback modes

Plugins capture rollback data through `Capture`.

Current rollback modes in use:

- `template`: deterministic
- `service`: deterministic
- `firewall`: deterministic
- `firewall_template`: deterministic
- `packages`: best_effort

`packages` capture notes explicitly mark `apt update`, `apt upgrade`, and `apt autoremove` as not fully reversible or best-effort.

## Managed file restrictions

File-oriented rollback capture uses `pluginapi.EnforceManagedPath`.

A managed file destination must:

- live under `/etc/`
- have a basename starting with `99-hardline`
- use one of these extensions:
  - `.conf`
  - `.nft`
  - `.rules`

That restriction is enforced by the capture path used for:

- `template`
- `firewall`
- `firewall_template`

## `packages`

Spec:

```json
{
  "update": true,
  "upgrade": false,
  "autoremove": false,
  "install": ["tree"],
  "purge": ["telnet"]
}
```

Validation from code:

- install entries must be non-empty
- purge entries must be non-empty
- a package cannot appear twice in the same list
- a package cannot be both installed and purged in one step

## `template`

Spec:

```json
{
  "src": "templates/example.tmpl",
  "dest": "/etc/example.d/99-hardline-example.conf",
  "mode": "0644"
}
```

Validation from code:

- `src` is required
- `dest` is required
- `mode`, when set, must parse as octal

Behavior:

- loads the template through `profile.LoadTemplate`
- compares remote content and mode
- only rewrites when content or mode differ

## `service`

Spec:

```json
{
  "name": "nftables",
  "enabled": true,
  "state": "restarted"
}
```

Accepted states:

- empty
- `started`
- `start`
- `stopped`
- `stop`
- `restarted`
- `restart`
- `reloaded`
- `reload`
- `reload-or-restart`

Notes from code:

- `sshd` is normalized to `ssh`
- rollback restores both enablement and activity state

## `firewall`

Spec shape:

```json
{
  "backend": "nftables",
  "family": "inet",
  "table": "filter",
  "managed_dest": "/etc/nftables.d/99-hardline-firewall.nft",
  "policies": [
    {"chain": "input", "policy": "drop"}
  ],
  "rules": [
    {"chain": "input", "proto": "tcp", "port": 22, "action": "accept"}
  ]
}
```

Validation from code:

- only backend `nftables` is accepted
- `managed_dest` is required
- the spec is normalized before execution

Behavior:

- writes a deterministic nftables file
- ensures `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`
- validates the final nftables config in plan/apply support paths

## `firewall_template`

This plugin lives in `pluginprojects/firewalltemplate` and is built as a shared object.

Spec:

```json
{
  "backend": "nftables",
  "policy": "drop",
  "template_src": "templates/20-firewall-template.tmpl",
  "template_dest": "/etc/nftables.d/99-hardline-custom.nft",
  "allow": [
    {"port": 2222, "proto": "tcp"},
    {"port": 5353, "proto": "udp"}
  ]
}
```

Validation from code:

- only backend `nftables` is accepted
- `policy` is required
- each allow rule port must be `1..65535`
- protocol must be empty, `tcp`, or `udp`

Behavior:

- loads a profile template
- injects generated allow rules with a template function
- writes a managed nftables file
- plan output is explicitly marked best-effort and template-driven

## Example step

From `integration-tests/profiles/multi-plugin-success/actions/10-multi.json`:

```json
{
  "id": "itest-managed-template-apply",
  "plugin": "template",
  "severity": "low",
  "risk_class": "integrity",
  "control_tags": [],
  "config": {
    "src": "templates/10-managed.conf.tmpl",
    "dest": "/etc/hardline.d/99-hardline-itest-success.conf",
    "mode": "0644"
  }
}
```

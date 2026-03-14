# Hardline Profiles

This document describes the profile format that the current code loads from [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go).

## Relevant Files

- loader: [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go)
- schema validation: [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go)
- profile schema: [`schema/profile.schema.json`](/home/kartikeya_vashishtha/hardline-try2/schema/profile.schema.json)
- action schema: [`schema/action-file.schema.json`](/home/kartikeya_vashishtha/hardline-try2/schema/action-file.schema.json)
- example profile: [`base-secure-ubuntu-24.04-lts/profile.json`](/home/kartikeya_vashishtha/hardline-try2/base-secure-ubuntu-24.04-lts/profile.json)

## Directory Shape

A profile is a directory, not a single file. The expected layout is:

- `profile.json`
- `actions/*.json`
- `templates/*.tmpl`
- `manifest.json`
- `manifest.sig`

The manifest files are used by `verify-profile`. They are not loaded by `profile.Load`.

## `profile.json`

`profile.json` contains:

```json
{
  "id": "base-secure-ubuntu-24.04-lts",
  "display_name": "Base Secure Ubuntu 24.04 LTS",
  "version": "1.0.0",
  "os": {
    "family": "ubuntu",
    "version": "24.04",
    "variant": "lts"
  },
  "profile_schema": 1,
  "min_hardline": "0.0.1",
  "actions": [
    "actions/00-packages.json"
  ],
  "templates": [
    "templates/10-ssh-sshd-config.tmpl"
  ]
}
```

Semantics:

- `actions` is an ordered list. `plan` and `apply` walk action files in this order.
- `templates` is a declaration list used by `Profile.LoadTemplate`. Template-backed plugins can only load files declared here.
- `profile_schema` is compared against the compiled schema support in the current binary.
- `min_hardline` is checked during `plan` and `apply`.

## Action Files

Each action file has this top-level shape:

```json
{
  "steps": [
    {
      "id": "ssh-template-apply",
      "plugin": "template",
      "severity": "medium",
      "risk_class": "access",
      "control_tags": [],
      "config": {
        "src": "templates/10-ssh-sshd-config.tmpl",
        "dest": "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
        "mode": "0600"
      }
    }
  ]
}
```

Core step fields owned by the profile package:

- `id`
- `plugin`
- `severity`
- `risk_class`
- `control_tags`
- `config`
- `allow_unvalidated`

Plugin-specific data is always nested under `config`.

## Shipped Step Types

Built-in plugins and the bundled external firewall template plugin expose these `config` structs:

- [`internals/plugins/packages/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/spec.go)
- [`internals/plugins/template/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/spec.go)
- [`internals/plugins/service/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/spec.go)
- [`internals/plugins/firewall/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/spec.go)
- [`pluginprojects/firewalltemplate/spec.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/spec.go)

Built-ins:

- `packages`
  Uses `update`, `upgrade`, `autoremove`, `install`, and `purge`.
- `template`
  Uses `src`, `dest`, and `mode`.
- `service`
  Uses `name`, optional `enabled`, and optional `state`.
- `firewall`
  Manages nftables rules written to a managed destination.

Bundled external plugin:

- `firewall_template`
  Renders an nftables template with an allowlist.

## Validation Boundaries

Profile validation is split across two layers:

- [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go) validates `profile.json` and each action file against generated JSON schemas.
- Plugin validation is enforced through the plugin registry and `pluginapi.EnsureValidationPolicy(...)`.

If a plugin does not self-validate, the step must explicitly set `allow_unvalidated=true` or `plan` and `apply` will fail.

## Template Rules

Templates are loaded relative to the profile directory. `Profile.LoadTemplate(rel)` rejects any template path that is not declared in `profile.json`.

That means:

- listing a template in `profile.json` is required
- referencing a template from a step is not sufficient on its own

## Example

The canonical in-repo example profile is [`base-secure-ubuntu-24.04-lts/profile.json`](/home/kartikeya_vashishtha/hardline-try2/base-secure-ubuntu-24.04-lts/profile.json).

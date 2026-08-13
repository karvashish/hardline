# Action Files

Each action file is a JSON object with a `steps` array:

```json
{
  "steps": [
    {
      "id": "journald-hardening",
      "plugin": "template",
      "config": {
        "src": "templates/50-journald-hardening.conf.tmpl",
        "dest": "/etc/systemd/journald.conf.d/99-hardline.conf",
        "mode": "0644"
      }
    }
  ]
}
```

## Step Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable step identifier |
| `plugin` | yes | Registered plugin name |
| `config` | no | Plugin-specific configuration object |
| `allow_unvalidated` | no | Acknowledge a plugin that does not perform internal validation |

## Schema-Level Config Validation

`config` is not freeform. `schema/action-file.schema.json` carries an `if`/`then` branch per built-in plugin that constrains the fields most likely to reach a root shell:

| Plugin | Constrained field | Pattern |
| --- | --- | --- |
| `packages` | `install[]`, `purge[]` | `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$` |
| `template` | `src` | profile-relative path, no leading `/` |
| `template` | `dest` | `^[A-Za-z0-9._/-]+$` |
| `service` | `name` | `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$` |
| `firewall`, `firewall_template` | `managed_dest` | `^[A-Za-z0-9._/-]+$` |
| `file_meta` | `path` | `^[A-Za-z0-9._/@-]+$` |
| `file_meta` | `owner`, `group` | `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$` |

Plugins re-check these at run time; the schema branch fails the profile earlier, at `verify-profile`. Fields not listed above are unconstrained by the schema and validated only by the owning plugin.

## Notes

- step order is execution order
- `id` and `plugin` are the only required step fields; `additionalProperties` is `false`, so no other keys are accepted
- all built-in plugins in this repo, and the example external `firewall_template` plugin, set `InternalValidation=true`
- a step whose plugin leaves `InternalValidation` false **must** set `allow_unvalidated: true`, or planning fails with `plugin "..." does not internally validate; set allow_unvalidated=true to acknowledge it`; such steps also get a `validation is explicitly disabled` highlight in the plan report
- on a plugin that already validates, `allow_unvalidated` is accepted and ignored
- service steps with `restart_policy.type=on_change` can refer to earlier step IDs through `restart_policy.steps`

Next:

- [Built-In Plugins](builtin-plugins.md)
- [External Plugins](external-plugins.md)

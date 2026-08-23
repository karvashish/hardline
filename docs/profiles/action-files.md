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
| `plugin` | yes | Registered plugin name, matching `^[a-z][a-z0-9_]*$` |
| `config` | in practice yes | Plugin-specific configuration object. The `Step` definition itself requires only `id` and `plugin`, but every per-plugin branch below requires `config`, so a step naming a plugin the repo ships has to carry one - an empty `{}` where the plugin needs no field |

## Schema-Level Config Validation

`config` is not freeform. `schema/action-file.schema.json` carries an `if`/`then` branch keyed on `plugin` for every plugin the repo ships, and each branch describes that plugin's whole config object — every field by name and type, patterns on the values that reach a root shell, and `additionalProperties: false` so a typo or an unknown key fails rather than being ignored:

| Plugin | Required config fields | Other fields |
| --- | --- | --- |
| `packages_apt`, `packages_dnf4`, `packages_dnf5` | — | `update`, `upgrade`, `autoremove`, `install`, `purge`, `purge_also_removes` |
| `template` | `src`, `dest`, `mode` | — |
| `audit` | `src`, `dest`, `mode` | — |
| `ssh` | `path`, `mode`, `service`, `settings` | `verify_contexts` |
| `service` | `name` | `enabled`, `state`, `restart_policy` |
| `firewall` | `backend`, `main_config`, `managed_dest` | `family`, `table`, `policies`, `rules` |
| `firewall_template` | `backend`, `main_config`, `policy` | `allow`, `template_src`, `template_dest` |
| `file_meta` | `path` | `mode`, `owner`, `group`, `immutable`, `append_only` |

Every branch also requires `config` itself, including the three package branches, which require no field inside it. A step naming one of them still has to carry a `config` object. The schema accepts an empty one, but the plugin's own validator does not: a package step that configures no operation has nothing to do, so it is rejected a moment later at `verify-profile`.

Plugins re-check their config through the `Validate` func every plugin must implement. Both checks run during `verify-profile`, offline, and in that order: the schema branch first, then the plugin's own validator. They are deliberately redundant.

They are also maintained separately, and that is worth knowing when you author a plugin. `make genschema` reflects `profile.Profile` and `profile.ActionFile` from their Go types, but the per-plugin `config` branches are not reflected from the plugin `Spec` types - they are written by hand in `cmd/genschema/pluginconfig.go`, as a required-field list and a field-constraint map per plugin. Nothing mechanically ties them to what the plugin's `Validate` accepts, so the two *can* drift, and the schema is the looser of the two whenever they do: the branch has no way to express a cross-field rule, and a field it fails to mark required will simply be caught a moment later by the validator. `make check-schemas` guards that the committed schema matches what `make genschema` produces; it does not guard that either one matches the plugin. When you add or change a plugin config field, change both.

## Notes

- step order is execution order
- `id` and `plugin` are the only fields the `Step` definition requires on its own, and `config` is required by the branch for every plugin the repo ships; `additionalProperties` is `false`, so no keys beyond those three are accepted
- every plugin validates its own steps, and the registry refuses to load one that does not supply a `Validate` func. There is no way for a step to opt out of validation — the older `allow_unvalidated` field no longer exists and is rejected as an unknown key
- service steps with `restart_policy.type=on_change` can refer to earlier step IDs through `restart_policy.steps`

Next:

- [Built-In Plugins](builtin-plugins.md)
- [External Plugins](external-plugins.md)

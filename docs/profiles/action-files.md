# Action Files

Each action file is a JSON object with a `steps` array:

```json
{
  "steps": [
    {
      "id": "ssh-template-apply",
      "plugin": "template",
      "config": {
        "src": "templates/10-ssh-sshd-config.tmpl",
        "dest": "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
        "mode": "0600"
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

## Notes

- step order is execution order
- all built-in plugins in this repo set `InternalValidation=true`
- `allow_unvalidated` is mostly relevant for external plugins
- service steps with `restart_policy.type=on_change` can refer to earlier step IDs through `restart_policy.steps`

Next:

- [Built-In Plugins](builtin-plugins.md)
- [External Plugins](external-plugins.md)

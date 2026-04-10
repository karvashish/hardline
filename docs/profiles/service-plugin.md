# Service Plugin

Manages service enablement and state through `systemctl`.

Example:

```json
{
  "id": "ssh-service-reload",
  "plugin": "service",
  "config": {
    "name": "ssh",
    "enabled": true,
    "state": "reloaded",
    "restart_policy": {
      "type": "on_change",
      "steps": ["ssh-template-apply"]
    }
  }
}
```

Config fields:

- `name`: service name
- `enabled`: optional boolean
- `state`: `started`, `stopped`, `restarted`, `reloaded`, or `reload-or-restart`
- `restart_policy`: optional

Restart policy behavior:

- `always` means perform the requested restart or reload when the step runs
- `on_change` means only do it if an upstream step in `restart_policy.steps` changes

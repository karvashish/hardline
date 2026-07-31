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

- `name`: required service name, matching `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`. The name `sshd` is normalized to `ssh`
- `enabled`: optional boolean. Omitted means "leave enablement as-is"; it is not defaulted to `true`
- `state`: optional. `started`, `stopped`, `restarted`, `reloaded`, or `reload-or-restart`. The bare verbs `start`, `stop`, `restart`, and `reload` are accepted as equivalents. Omitted means no state change
- `restart_policy`: optional. `type` is `always` or `on_change`; `steps` lists upstream step IDs

`reloaded`, `reload`, and `reload-or-restart` all issue `systemctl reload-or-restart`; there is no reload-only path.

## Idempotency

`started` and `stopped` check `systemctl is-active` first and skip the command when the service is already in the requested state, so the step reports no change.

## Restart Policy Behavior

- `always` (or no `restart_policy`) means perform the requested restart or reload every time the step runs
- `on_change` suppresses the restart or reload only when **all** of the following hold: no step listed in `restart_policy.steps` reported a change this run, the service is currently active, and its enablement already matches `enabled` when that field is set. If any one fails, the restart proceeds

The change signal comes from the apply loop, which compares each step's before and after captures. Referencing a step ID that does not exist in the run is not an error — it simply never signals a change.

On rollback, an `on_change` step re-runs its restart only if one of its `restart_policy.steps` dependencies was actually reverted; `always` steps re-run unconditionally.

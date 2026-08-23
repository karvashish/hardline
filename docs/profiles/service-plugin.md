# Service Plugin

Manages service enablement and state through `systemctl`.

Example:

```json
{
  "id": "journald-service-restart",
  "plugin": "service",
  "config": {
    "name": "systemd-journald",
    "enabled": true,
    "state": "restarted",
    "restart_policy": {
      "type": "on_change",
      "steps": ["journald-hardening"]
    }
  }
}
```

Config fields:

- `name`: required service name, matching `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`. The name reaches `systemctl` verbatim: hardline does not alias unit names, so a profile targeting Debian says `ssh` and one targeting RHEL says `sshd`
- `enabled`: optional boolean. Omitted means "leave enablement as-is"; it is not defaulted to `true`
- `state`: optional. `started`, `stopped`, `restarted`, `reloaded`, or `reload-or-restart`. The bare verbs `start`, `stop`, `restart`, and `reload` are accepted as equivalents. Omitted means no state change
- `restart_policy`: optional. `type` is `always` or `on_change`; `steps` lists upstream step IDs

`reloaded`, `reload`, and `reload-or-restart` all issue `systemctl reload-or-restart`; there is no reload-only path.

## Idempotency

`started` and `stopped` check `systemctl is-active` first and skip the command when the service is already in the requested state, so the step reports no change.

## Restart Policy Behavior

- `always` (or no `restart_policy`) means perform the requested restart or reload every time the step runs
- `on_change` suppresses the restart or reload only when **all** of the following hold: no step listed in `restart_policy.steps` reported a change this run, the service is currently active, and its enablement already matches `enabled` when that field is set. If any one fails, the restart proceeds

The change signal comes from the apply loop, which compares each step's before and after captures.

`restart_policy.steps` is checked at `verify-profile`, offline, against the step IDs declared across every action file in the profile. Three things are rejected there: watching a step ID that no action file declares, watching the step's own ID, and watching a step that runs *after* the watching step. That last rule makes the change signal meaningful - a step that has not run yet cannot have reported a change, so a forward reference could only ever read as "no change" and silently suppress the restart.

On rollback, an `on_change` step re-runs its restart only if one of its `restart_policy.steps` dependencies was actually reverted; `always` steps re-run unconditionally.

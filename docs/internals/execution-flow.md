# Execution Flow

The execution path is split between `cmd/hardline/main.go` and the package for the selected command.

## Entry In `cmd/hardline`

For `plan`, `apply`, `rollback`, and `verify-profile`, the CLI does the following first:

1. parse flags into `cli.Command`
2. set debug and log-file behavior
3. load external plugins from the binary-adjacent `plugins/` directory

Then the commands diverge:

- `plan` runs `verify.Verify`, then `plan.Plan`
- `apply` runs `verify.Verify`, then `plan.Plan`, then `apply.Apply`
- `rollback` runs `verify.Verify`, then `rollback.Rollback`
- `verify-profile` runs only `verify.Verify`
- `version` does not load plugins or touch profiles

The process also installs a signal handler. The first `SIGINT` or `SIGTERM` cancels the apply context for graceful shutdown. A second signal exits immediately with code `130`.

## `verify-profile`

`verify.Verify`:

1. verifies `manifest.json` against `manifest.sig`
2. chooses the embedded public key or `/etc/hardline/profile_signing_pub.pem`
3. loads `profile.json`
4. validates `profile.json` and every action file against the generated schemas
5. validates `allowed_overrides`
6. resolves runtime overrides and rejects unknown keys
7. ensures each referenced plugin exists
8. ensures declared templates exist on disk

This stage is deliberately local. No SSH connection is required.

## `plan`

Then `plan.Plan`:

1. validates plan output flags
2. loads the profile
3. checks `min_hardline` and `profile_schema`
4. validates the profile and plugin availability
5. resolves runtime overrides and stores them on the profile
6. connects to the remote host over SSH
7. checks the remote OS
8. runs each step's `Plugin.Plan`
9. prints a compact or detailed plan
10. optionally writes a JSON, YAML, or Markdown report

Two details matter here:

- `cli.ResolveOverrides` prefers `--overrides-file`; otherwise it auto-loads `<profile>/profile.overrides.json`
- `plan` records predicted step changes in a `map[string]bool`, and downstream service steps consult that map for `restart_policy.type=on_change`

## `apply`

`apply` is intentionally split across two layers.

First, `cmd/hardline/main.go` runs:

1. `verify.Verify`
2. `plan.Plan`
3. `apply.Apply`

Then `apply.Apply` itself:

1. connects to the remote host
2. checks non-interactive sudo
3. acquires `/var/lib/hardline/.apply-lock.d`
4. reloads and validates the profile
5. resolves overrides again
6. creates a local rollback journal
7. captures pre-step state, applies a step, captures post-step state
8. updates step-change tracking for downstream `service` steps
9. auto-rolls back on failure after prior mutation
10. persists the successful journal remotely

Within each step, the apply package does:

1. `Capture` before state
2. append a `StepRecord` to the local journal
3. run plugin `Apply`
4. `Capture` after state
5. compare before and after captures to compute actual `StepChanges`

If a step fails after prior mutations, apply triggers rollback using the recorded journal entries. If the context is canceled during apply, the same rollback path is used for already-completed steps.

## `rollback`

Then `rollback.Rollback`:

1. loads the profile ID from `profile.json`
2. connects to the remote host
3. checks non-interactive sudo
4. loads the newest remote journal for that profile
5. refuses rollback unless that journal is marked `success`
6. walks recorded steps in reverse order
7. checks for conflicts unless `--force-rollback` is set
8. removes the consumed remote journal on success

Rollback has one subtle rule: service objects are deferred until after non-service objects. That keeps file and package state restoration ahead of service toggles and restarts.

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

`verify.Verify`, in order:

1. resolves the signing public key — the embedded one by default, `/etc/hardline/profile_signing_pub.pem` under `--allow-local-key`
2. verifies `manifest.json` against `manifest.sig`, then re-hashes every regular file in the directory and requires an exact two-way match with the manifest entries
3. loads `profile.json`
4. `Affirm` validates `profile.json` and every action file against the embedded schemas, and validates the `allowed_overrides` list itself
5. resolves runtime overrides and rejects keys not in `allowed_overrides`
6. ensures each referenced plugin exists in the registry
7. asserts every path in `actions` and `templates` is covered by the signed manifest
8. stats each declared template to confirm it exists on disk

Step 7 runs before step 8 on purpose: coverage rejects any reference pointing outside the signed tree, so the stat never touches a path the signature did not cover.

`Verify` returns a `VerifiedBundle` holding the profile directory, the digest of the exact manifest bytes whose signature was checked, and the loaded `*profile.Profile`. `plan`, `apply`, and `rollback` take that bundle rather than a directory path, so they operate on the profile whose signature was checked instead of re-reading a directory that may have changed since.

This stage is deliberately local. No SSH connection is required.

## `plan`

Then `plan.Plan`:

1. validates plan output flags, before any network work
2. takes the profile from the `VerifiedBundle` rather than reloading it
3. checks `min_hardline` and `profile_schema` against the binary
4. validates plugin availability
5. resolves runtime overrides, validates them, and stores them on the profile
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
3. acquires `/var/lib/hardline/.apply-lock.d` via `mkdir`, which is atomic, and releases it on the way out
4. checks the remote OS
5. re-checks `min_hardline` and `profile_schema`, and plugin availability
6. resolves overrides again and stores them on the profile
7. re-hashes `manifest.json` and compares it to the digest recorded at verify time, aborting if the profile directory changed in between
8. creates a local rollback journal
9. captures pre-step state, applies a step, captures post-step state
10. updates step-change tracking for downstream `service` steps
11. auto-rolls back on failure after prior mutation
12. persists the successful journal remotely, then deletes the local copy unless `--keep-local-rollback` was passed

Step 7 is the window-closing check: verification happens before the SSH connection is even opened, so without it an edit made to the profile directory during the connect-and-preflight phase would be applied unsigned.

Within each step, the apply package does:

1. `Capture` before state
2. append a `StepRecord` to the local journal
3. run plugin `Apply`
4. `Capture` after state
5. compare before and after captures to compute actual `StepChanges`

If a step fails after prior mutations, apply triggers rollback using the recorded journal entries. If the context is canceled during apply, the same rollback path is used for already-completed steps.

## `rollback`

Then `rollback.Rollback`:

1. takes the profile ID from the verified bundle
2. connects to the remote host
3. checks non-interactive sudo
4. loads the newest remote journal for that profile
5. refuses rollback unless that journal is marked `success`
6. walks recorded steps in reverse order
7. checks for conflicts unless `--force-rollback` is set
8. removes the consumed remote journal on success

Rollback has one subtle rule: service objects are deferred until after non-service objects. That keeps file and package state restoration ahead of service toggles and restarts.

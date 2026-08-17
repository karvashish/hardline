# Plugin System

The plugin surface lives in `pkg/pluginapi`.

Each plugin registers as:

```go
type Plugin struct {
    Name               string
    InternalValidation bool
    Apply              func(Context, profile.Step) error
    Plan               func(Context, profile.Step) (PlanResult, error)
    Capture            func(Context, profile.Step) (CaptureResult, error)
    Rollback           func(Host, ObjectRecord) error
    DetectConflict     func(Host, ObjectRecord) []string
}
```

## Runtime Contract

Every plugin must provide:

- `Apply`
- `Plan`
- `Capture`
- `Rollback`
- `DetectConflict`

Missing any of those is a registry error.

`Rollback` restores one captured `ObjectRecord`, and `DetectConflict` compares one post-apply `ObjectRecord` against live remote state. The rollback orchestrator in `internals/rollback` no longer switches on object kind itself - it looks up the step's plugin and delegates to these two funcs, so each plugin owns the restore and conflict logic for the object kinds it emits. The one exception is `runtime_policy`, which the orchestrator drops before dispatching because no plugin restores it (see below).

Plugin names are normalized to lowercase when registered and when looked up from step definitions.

## Important Context Fields

- `Context.Host` is the remote execution surface
- `Context.Profile` gives access to profile metadata and declared templates
- `Context.Overrides` carries runtime overrides
- `Context.StepChanges` lets downstream steps react to upstream changes

`allow_unvalidated=true` only matters when `InternalValidation` is `false`. `pluginapi.EnsureValidationPolicy` enforces that handshake before a step runs.

## Plan And Capture Shapes

Planning is richer than a single yes or no:

- `Summary` is the main terminal and report summary
- `Details` holds explanatory lines
- `Diff` holds final-state diff lines
- `WillChange` predicts whether the step will mutate state
- `OperatorSummary` is the condensed description used in reports
- `Highlights` carries warnings or special notes

Rollback capture is object-based instead of plugin-specific string output. A `CaptureResult` carries a `RollbackMode`, a list of `ObjectRecord`s, optional `Notes`, and an optional `Reload`. The object kinds it can record are:

- `file` objects
- `file_meta` objects
- `service` objects
- `package` objects
- `config_line` objects
- `runtime_policy` objects
- `validate` no-op records

`runtime_policy` is the one kind a plugin records but never restores. It holds what a daemon reported it was holding — `auditctl -l`, `nft list ruleset` — so that a run which only reloads the daemon still shows a delta between the before and after captures and rollback does not skip it as unchanged. Putting the daemon back is the job of the file object the daemon reads, so the orchestrator skips this kind before dispatching and a plugin does not need a case for it.

The rollback modes exposed in `pkg/pluginapi` are:

- `deterministic`
- `best_effort`
- `irreversible`
- `noop`

`CaptureResult.Reload` is step-level service intent rather than observed state — the action, the restart policy, and the dependency step IDs. Rollback reads it to decide whether to re-run a restart after reverting the step's dependencies.

## Built-In Plugins

Registered in `internals/registry/registry.go`, in this order:

- `packages_apt`, `packages_dnf4`, `packages_dnf5`
- `template`
- `service`
- `firewall`
- `file_meta`
- `audit`
- `ssh`

The shared registry is built once at package init; a built-in that fails to register panics rather than degrading silently.

Notable behavior:

- `packages` uses `apt-get`, per-operation marker files under `/var/lib/hardline`, and a 30-minute per-command timeout
- `template` treats declared template files as static bytes
- `service` uses `StepChanges` to suppress restarts and reloads when `restart_policy.type=on_change`
- `firewall` normalizes nftables policy into a deterministic include file
- `file_meta` re-stamps mode, owner, group, and the `i`/`a` chattr flags on paths that already exist
- `audit` writes the rules file and runs `augenrules --load`, then reads the loaded policy back with `auditctl`
- `ssh` renders the sshd drop-in, parses it with `sshd -t`, guards management access, reloads, and verifies the result with `sshd -T`

## External Plugin Loading

External plugins are loaded by `internals/plugins.LoadFromBinaryDir`.

That loader:

1. finds the directory adjacent to the `hardline` binary
2. requires the directory to be a real directory, not a symlink, not writable by group or others, and owned by root or by the user running hardline
3. scans for `.so` files
4. applies the same checks to each `.so` before opening it, so a file planted before the directory was tightened is refused rather than loaded
5. opens each plugin with Go's `plugin` package
6. looks up the `HardlinePluginV1` symbol
7. requires that symbol to be a `*pluginapi.Plugin`
8. registers the plugin into the shared registry

If one or more external plugins are found, Hardline emits an explicit warning that they are not signature-verified and will run as root.

## External Plugin Example

The example external plugin in `pluginprojects/firewalltemplate` shows the expected shared-object export:

- exported symbol: `HardlinePluginV1`
- type: `*pluginapi.Plugin`

## Build And Platform Constraints

External plugins are native Go shared objects (`-buildmode=plugin`). They must be rebuilt against every `hardline` release - the Go toolchain and dependency versions have to match the host binary byte-for-byte, or `plugin.Open` rejects the `.so`. They are unsupported on Windows: the Windows builds are statically linked with `CGO_ENABLED=0`, and Go's plugin system is only available on Linux, FreeBSD, and macOS. The built-in plugins are compiled into the binary and ship on every platform.

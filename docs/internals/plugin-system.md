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

`Rollback` restores one captured `ObjectRecord`, and `DetectConflict` compares one post-apply `ObjectRecord` against live remote state. The rollback orchestrator in `internals/rollback` no longer switches on object kind itself - it looks up the step's plugin and delegates to these two funcs, so each plugin owns the restore and conflict logic for the object kinds it emits.

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

Rollback capture is object-based instead of plugin-specific string output. A `CaptureResult` can record:

- file objects
- service objects
- package objects
- validation or no-op records

The rollback modes exposed in `pkg/pluginapi` are:

- `deterministic`
- `best_effort`
- `noop`

## Built-In Plugins

Registered in `internals/registry/registry.go`:

- `packages`
- `template`
- `service`
- `firewall`

Notable behavior:

- `packages` uses `apt-get`, state files under `/var/lib/hardline`, and longer timeouts
- `template` treats declared template files as static bytes
- `service` uses `StepChanges` to suppress restarts and reloads when `restart_policy.type=on_change`
- `firewall` normalizes nftables policy into a deterministic include file

## External Plugin Loading

External plugins are loaded by `internals/plugins.LoadFromBinaryDir`.

That loader:

1. finds the directory adjacent to the `hardline` binary
2. requires the directory not to be world-writable
3. scans for `.so` files
4. opens each plugin with Go's `plugin` package
5. looks up the `HardlinePluginV1` symbol
6. requires that symbol to be a `*pluginapi.Plugin`
7. registers the plugin into the shared registry

If one or more external plugins are found, Hardline emits an explicit warning that they are not signature-verified and will run as root.

## External Plugin Example

The example external plugin in `pluginprojects/firewalltemplate` shows the expected shared-object export:

- exported symbol: `HardlinePluginV1`
- type: `*pluginapi.Plugin`

## Build And Platform Constraints

External plugins are native Go shared objects (`-buildmode=plugin`). They must be rebuilt against every `hardline` release - the Go toolchain and dependency versions have to match the host binary byte-for-byte, or `plugin.Open` rejects the `.so`. They are unsupported on Windows: the Windows builds are statically linked with `CGO_ENABLED=0`, and Go's plugin system is only available on Linux, FreeBSD, and macOS. The five built-in plugins are compiled into the binary and ship on every platform.

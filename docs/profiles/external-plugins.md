# External Plugins

Hardline can load additional plugins from a `plugins/` directory next to the binary, resolved from `os.Executable()` (so a symlink on `PATH` resolves to the real install directory first).

Loading rules:

- a missing `plugins/` directory is not an error; it is skipped silently
- only files whose extension is `.so`, case-insensitively, are considered; subdirectories are ignored
- files load in sorted filename order, and any one failure aborts the whole load
- registering two plugins under the same name fails with `plugin already registered for name`
- when at least one plugin is present, Hardline prints a warning that they run as root and are not signature-verified

The external plugin contract is:

- build as a Go shared object with `-buildmode=plugin`
- export a symbol named `HardlinePluginV1`
- the symbol type must be `*pluginapi.Plugin`
- the value must set a `Name` and all six handler funcs: `Validate`, `Apply`, `Plan`, `Capture`, `Rollback`, and `DetectConflict`

See [../internals/plugin-system.md](../internals/plugin-system.md) for the full `pluginapi.Plugin` shape and the runtime contract.

## Migration: validation, rollback, and conflict detection are now plugin-owned

`Validate`, `Rollback`, and `DetectConflict` are required. The registry rejects any plugin that leaves one nil, and a single rejected plugin aborts loading for the whole directory:

```text
plugin "<name>" is missing Validate func
plugin "<name>" is missing Rollback func
plugin "<name>" is missing DetectConflict func
```

Plugins built against an older `pluginapi.Plugin` — before these fields existed — fail to load until all three are implemented.

- `Validate(step, overrides)` checks the step's config before anything runs, at `verify-profile`, offline. It receives its own deep copy of the resolved overrides, so a plugin that merges an override into its config validates the merged result and cannot mutate what `Plan` and `Apply` read next. It replaces the old `InternalValidation bool` field and the `allow_unvalidated` step key, both of which are gone: there is no longer an unvalidated path.
- `Rollback` restores one captured `ObjectRecord`.
- `DetectConflict` compares one post-apply `ObjectRecord` against live remote state.

See `pluginprojects/firewalltemplate/handlers.go` for a worked example.

The repo contains an example external plugin project in:

```text
pluginprojects/firewalltemplate/
```

That example is built by `make build` into:

```text
tmp/plugins/firewall_template.so
```

Trust model:

- external plugins are not signature-verified
- they execute with root privileges through Hardline
- Hardline refuses to load them from a directory or file that is writable by group or others, owned by a third party, or reached through a symlink
- the same checks run over the plugins directory's parent chain, so a correctly-permissioned directory under a parent someone else can rewrite is refused too

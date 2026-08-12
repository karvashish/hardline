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
- the value must set a `Name` and all five handler funcs: `Apply`, `Plan`, `Capture`, `Rollback`, and `DetectConflict`

See [../internals/plugin-system.md](../internals/plugin-system.md) for the full `pluginapi.Plugin` shape and the runtime contract.

## Migration: rollback and conflict detection are now plugin-owned

`Rollback` and `DetectConflict` are required. The registry rejects any plugin that leaves either nil, and a single rejected plugin aborts loading for the whole directory:

```text
plugin "<name>" is missing Rollback func
plugin "<name>" is missing DetectConflict func
```

Plugins built against an older `pluginapi.Plugin` — before these fields existed — fail to load until both are implemented. `Rollback` restores one captured `ObjectRecord`; `DetectConflict` compares one post-apply `ObjectRecord` against live remote state. See `pluginprojects/firewalltemplate/handlers.go` for a worked example.

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

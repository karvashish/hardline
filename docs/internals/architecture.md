# Architecture

Hardline is a profile-driven remote execution engine built around signed profile directories, ordered steps, and plugin-owned state transitions.

At the top level, the system has three safety layers:

1. local profile verification before remote work starts
2. step planning before mutation
3. rollback journals captured around each applied step

A run is driven by this object chain:

1. a profile directory on disk
2. `profile.json`, which declares action files and templates
3. ordered step definitions loaded from action files
4. a plugin chosen by each step's `plugin` field
5. a remote host surface passed in through `pluginapi.Context`
6. a rollback journal capturing before and after state

Each step is implemented by a plugin that can:

- validate input
- plan desired changes
- apply changes
- capture state for rollback

## Main Binaries

- `cmd/hardline` owns CLI orchestration
- `cmd/profiletool` owns signing key generation plus manifest and signature generation
- `cmd/genschema` regenerates the JSON schema files in `schema/`

`cmd/hardline/main.go` intentionally stays thin. It wires together CLI parsing, plugin loading, verification, planning, apply, rollback, version reporting, and signal handling.

## Module Boundaries

CLI and input resolution:

- `internals/cli` parses flags, resolves overrides, and exposes version helpers

Verification and schema checks:

- `internals/verify`
- `pkg/profile`
- `schema/`

Execution path:

- `internals/plan`
- `internals/apply`
- `internals/rollback`
- `internals/connection`
- `internals/remote`

Plugin system:

- `internals/registry`
- `internals/plugins`
- `pluginprojects/firewalltemplate`

Reusable packages:

- `pkg/profile`
- `pkg/pluginapi`
- `pkg/logger`

## Design Shape

Some important architectural choices show up repeatedly in the code:

- verification is local and happens before remote mutation
- plugins own the operational details of planning, applying, and capturing state
- the remote host is abstracted behind a narrow `pluginapi.Host` interface
- apply and rollback are journal-based rather than "diff from desired state" only
- external plugins are supported, but treated as a separate trust boundary

The built-in registry is assembled once in `internals/registry`, while external `.so` plugins are loaded from a sibling `plugins/` directory next to the compiled binary.

Next:

- [Data Models](data-models.md)
- [Execution Flow](execution-flow.md)
- [Plugin System](plugin-system.md)

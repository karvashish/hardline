# Data Models

This page covers the main on-disk and in-memory structures that move through Hardline.

## Profile Model

`pkg/profile.Profile` is the core loaded object. It combines:

- user-facing fields from `profile.json`
- `profilePath`, which anchors relative paths
- decoded `ActionFiles`
- runtime overrides loaded at execution time

Important behavior in `pkg/profile`:

- action file paths are resolved relative to the profile directory
- templates must be declared in `profile.json` before plugins can load them
- runtime overrides are cloned on set and on read
- override keys are validated against `allowed_overrides`

## Action Files And Steps

The action-file schema requires steps with:

- `id`
- `plugin`
- optional `config`
- optional `allow_unvalidated`

The `profile.Step` runtime struct stores `id`, `plugin`, `config`, and `allow_unvalidated`.

## Profile Manifest

The profile integrity manifest is:

- versioned
- algorithm-tagged
- path-and-hash based

Current rules from `internals/verify/integrity.go`:

- manifest version must be `1`
- algorithm must be `sha256`
- each entry contains a relative normalized path and a hex SHA-256 digest
- duplicate entries are rejected
- path traversal and metadata-file references are rejected

These files are excluded from the signed manifest:

- `manifest.json`
- `manifest.sig`
- `profile.overrides.json`

## Plan Report Model

Structured plan reports contain:

- profile metadata
- target host and OS info
- summary counts
- top-level planned changes
- top-level attention items
- per-step status, details, diffs, and highlights
- next-step commands for apply and rollback

The report `kind` is currently `hardline_plan`.

## Rollback Journal Model

The rollback journal stores:

- run metadata
- host and profile identity
- status
- ordered step records
- checksum

Each `StepRecord` stores:

- step ID
- plugin type
- rollback mode
- before objects
- after objects
- notes

Object records are typed by `Kind` (`pkg/pluginapi`). The kinds are:

- `file` — a `FileSnapshot` (path, existence, mode, base64 contents); used by `template` and `firewall`.
- `file_meta` — a `FileMetaSnapshot` (path, existence, mode, owner, group, and the managed chattr letters `i`/`a` in `attrs`); used by the `file_meta` plugin to re-stamp metadata on an existing path without recording its contents.
- `service` — a `ServiceState` (unit, enabled, active, known).
- `package` — a `PackageState` (name, installed, version, requested install/purge).
- `validate` — a no-op marker for validation-only steps.

Which kinds a step records depends on the plugin's capture logic.

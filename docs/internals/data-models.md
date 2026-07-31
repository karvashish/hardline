# Data Models

This page covers the main on-disk and in-memory structures that move through Hardline.

## Profile Model

`pkg/profile.Profile` is the core loaded object. It combines:

- user-facing fields from `profile.json`
- `profilePath`, which anchors relative paths
- decoded `ActionFiles`
- runtime overrides loaded at execution time

Important behavior in `pkg/profile`:

- action file and template paths are resolved relative to the profile directory by `Profile.resolve`, which rejects an empty reference, a backslash, an absolute path, and any `..` segment, then resolves symlinks on the parent directory and rejects anything landing outside the profile root. This is what keeps a signed pointer from reaching unsigned content
- templates must be declared in `profile.json` before plugins can load them
- runtime overrides are cloned on set and on read (`maps.Clone`), so a plugin cannot mutate the profile's copy
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

`rollback.Journal` is currently `version: 2` and stores:

| Field | Meaning |
| --- | --- |
| `version` | Journal format version, `2` |
| `run_id` | `20060102T150405.000000000Z` timestamp; also the remote journal filename, so lexical order is time order |
| `created_at` | RFC 3339 nano timestamp of the run start |
| `host` | Target host as passed on the command line |
| `profile_id` | Profile `id` from `profile.json` |
| `profile_path` | Profile directory as passed on the command line |
| `status` | `in_progress`, `success`, `failed`, or `interrupted` |
| `steps` | Ordered step records |
| `checksum` | Integrity hash computed over the journal with `checksum` blanked |

Each `StepRecord` stores:

- `id` — step ID
- `type` — plugin name
- `rollback_mode`
- `before` / `after` — object records
- `notes`
- `reload` — optional `ServiceReload` carrying the step's service intent (`action`, `restart_policy`, `restart_deps`), which rollback consults to decide whether to re-run a restart

Object records are typed by `kind` (`pkg/pluginapi`). The kinds are:

- `file` — a `FileSnapshot` (`path`, `existed`, `mode`, `content_b64`); used by `template` and `firewall`.
- `file_meta` — a `FileMetaSnapshot` (`path`, `existed`, `mode`, `owner`, `group`, and the managed chattr letters `i`/`a` in `attrs`); used by the `file_meta` plugin to re-stamp metadata on an existing path without recording its contents.
- `service` — a `ServiceState` (`unit`, `enabled`, `active`, `known`).
- `package` — a `PackageState` (`name`, `was_installed`, `version`, `requested_install`, `requested_purge`).
- `validate` — a no-op marker for validation-only steps, carrying only a `message`.

Which kinds a step records depends on the plugin's capture logic.

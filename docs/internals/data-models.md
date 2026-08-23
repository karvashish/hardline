# Data Models

This page covers the main on-disk and in-memory structures that move through Hardline.

## Profile Model

`pkg/profile.Profile` is the core loaded object. It combines:

- user-facing fields from `profile.json`
- `profilePath`, which anchors relative paths
- decoded `ActionFiles`
- runtime overrides loaded at execution time

Important behavior in `pkg/profile`:

- action file and template references are normalized by `Profile.resolve`, which rejects an empty reference, a backslash, an absolute path, and any `..` segment, then returns the cleaned slash-separated key. It touches no filesystem: the key is looked up in the verified file map built at verify time, and `signedBytes` fails a reference the manifest does not cover. That map lookup, not a path traversal check, is what keeps a signed pointer from reaching unsigned content - there is no symlink to resolve because nothing is opened by path after verification
- templates must be declared in `profile.json` before plugins can load them
- runtime overrides are cloned on set and on read (`maps.Clone`), so a plugin cannot add, drop, or repoint an entry in the profile's map. The clone is shallow: values are `json.RawMessage`, and a plugin that writes into the bytes of one writes into the profile's copy. Plugins decode overrides and do not mutate them, so this has no effect today, but the guarantee is over the map, not over the values
- override keys are validated against `allowed_overrides`

## Action Files And Steps

The action-file schema requires steps with:

- `id`
- `plugin`
- `config`

`additionalProperties` is `false`, so those three are the whole step vocabulary, and the `profile.Step` runtime struct stores exactly them. `config` is not freeform: the schema carries an `if`/`then` branch per built-in plugin that constrains that plugin's config object by name, type, and pattern, and closes it with `additionalProperties: false`. That branch also requires `config`, so while the `Step` definition lists only `id` and `plugin` as required, a step naming a plugin the repo ships is rejected without a config object. See [Action Files](../profiles/action-files.md#schema-level-config-validation).

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

`rollback.Journal` is currently `version: 3` and stores:

| Field | Meaning |
| --- | --- |
| `version` | Journal format version, `3`. Loading rejects anything else outright; a journal written by an older hardline has to be rolled back with the binary that wrote it |
| `run_id` | `20060102T150405.000000000Z` timestamp; also the remote journal filename, so lexical order is time order |
| `created_at` | RFC 3339 nano timestamp of the run start |
| `host` | Target host as passed on the command line |
| `profile_id` | Profile `id` from `profile.json` |
| `profile_path` | Profile directory as passed on the command line |
| `status` | `in_progress`, `success`, `failed`, `interrupted`, or `rolling_back` once a rollback has claimed the journal |
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

- `file` — a `FileSnapshot` (`path`, `existed`, `mode`, `owner`, `group`, `content_b64`); used by `template`, `firewall`, `audit`, and `ssh`.
- `file_meta` — a `FileMetaSnapshot` (`path`, `existed`, `mode`, `owner`, `group`, and the managed chattr letters `i`/`a` in `attrs`); used by the `file_meta` plugin to re-stamp metadata on an existing path without recording its contents.
- `service` — a `ServiceState` (`unit`, `enabled`, `active`, `enabled_state`, `active_state`, `known`).
- `package` — a `PackageState` (`name`, `was_installed`, `version`, `pin_spec`, `requested_install`, `requested_purge`). `pin_spec` holds the version in the capturing plugin's own reinstall syntax — `name=version` for apt, a full NEVRA for rpm.
- `runtime_policy` — a `RuntimePolicy` (`name`, `state`): what a daemon reported it was holding, such as `auditctl -l` or `nft list ruleset`. It exists so a run that only reloads a daemon still shows a delta between the before and after captures, and it is the one kind rollback never restores — the orchestrator drops it before dispatching to a plugin.

An `ObjectRecord` also carries an optional free-text `Message`. Which kinds a step records depends on the plugin's capture logic.

# Rollback

## Rollback Model

Rollback fidelity comes from plugin `Capture` results. A capture records objects such as:

- files
- services
- packages

Each step stores:

- `Before` snapshot
- `After` snapshot
- `RollbackMode`
- optional notes

## Journal Locations

Local runner journal:

- `${HARDLINE_STATE_DIR:-/tmp/hardline/runs}/<host>/<profileID>.json`

Remote success journals:

- `/var/lib/hardline/runs/<profileID>/<runID>.json`

The local path uses sanitized host and profile ID components. The remote path uses one file per successful apply run, so rollback can pop the newest run and leave older successful runs underneath it.

## Journal Lifecycle

- `apply` creates a local journal before step execution starts
- before each step, it captures state and appends a `StepRecord`
- after each successful step, it captures post-state and updates the same record
- on success, it saves the final journal remotely
- unless `--keep-local-rollback` is set, it removes the local journal after remote persistence succeeds

`Journal.RunID` is a UTC timestamp string, which is why lexicographic sort order matches run order for remote journal lookup.

## Integrity And Format

Journals currently use version `2`.

When serialized:

- the checksum field is cleared
- the journal is marshaled with indentation
- a SHA-256 checksum of that canonical JSON is computed
- the checksum is written back into the final JSON

When loaded, rollback verifies that checksum before trusting the journal contents.

## Rollback Execution Rules

Rollback walks step records in reverse order.

Two important behaviors are easy to miss:

- steps whose before and after snapshots are identical are skipped
- service objects are deferred until after non-service objects, so file and package restoration happens first

## Conflict Detection

Before overwriting state, rollback compares the journal's recorded post-apply state against current remote state.

That check currently covers:

- file contents
- service enabled and active state
- package installed state

If a mismatch is detected, rollback stops and reports that the object changed after apply. `--force-rollback` bypasses that protection.

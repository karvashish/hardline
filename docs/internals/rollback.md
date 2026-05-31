# Rollback

Rollback is one of Hardline's core design features. The product changes SSH, systemd units, packages, and firewall state on remote hosts; without a strong rollback model, every failed or interrupted apply would become a manual recovery exercise.

Hardline's rollback story is built on captured remote state, not on guessed "inverse commands." Before a step mutates anything, Hardline asks the plugin to capture the current state. After the step succeeds, it captures the state again. The journal stores both snapshots and uses them later to decide:

- what changed
- whether the change is safe to undo
- how to restore the recorded pre-apply state

## Rollback Model

Rollback fidelity comes from plugin `Capture` results. A capture records typed objects such as:

- files
- file metadata (mode/owner/group/attrs on an existing path)
- services
- packages

Each step stores:

- `Before` snapshot
- `After` snapshot
- `RollbackMode`
- optional notes

In journal terms, the unit of rollback is a `StepRecord`:

```text
StepRecord
  id
  type
  rollback_mode
  before[]
  after[]
  notes[]
```

That matters because rollback is based on what the remote host actually looked like, not on what the step config said it "should" have done.

## Journal Locations

Local runner journal:

- `${HARDLINE_STATE_DIR:-/tmp/hardline/runs}/<host>/<profileID>.json`

Remote success journals:

- `/var/lib/hardline/runs/<profileID>/<runID>.json`

The local path uses sanitized host and profile ID components. The remote path uses one file per successful apply run, so rollback can pop the newest run and leave older successful runs underneath it.

Two practical consequences are easy to miss:

- the local journal is the working journal during `apply`
- the remote journal is only the last successful state history for later manual `rollback`

If an apply fails halfway through, the local journal is the only authoritative record of what had already been captured.

## Journal Lifecycle

The lifecycle is intentionally conservative:

1. `apply` creates a local journal before step execution starts.
2. Before each step runs, Hardline captures state and appends a new `StepRecord`.
3. Hardline persists the local journal immediately after writing that pre-step record.
4. The step runs.
5. If the step succeeds, Hardline captures post-step state and updates the same `StepRecord` with `After`.
6. Hardline persists the local journal again.
7. After the whole apply succeeds, Hardline marks the journal `success` and writes a timestamped copy to the target host.
8. Unless `--keep-local-rollback` is set, it removes the runner-side journal after remote persistence succeeds.

Status transitions are meaningful:

- `in_progress` while apply is running
- `interrupted` if the apply context is cancelled
- `failed` if apply exits unsuccessfully
- `success` only after the full apply completes and the journal is ready to be used for later rollback

That `success` status is important because manual `rollback` refuses to operate on a journal that does not represent a fully successful apply.

## Local Journal vs Remote Journal

The two journal locations serve different jobs:

- the local journal is for in-flight safety during `apply`
- the remote journal is for post-success rollback on later invocations

This is why a failed apply behaves differently from a later explicit `rollback` command:

- on step failure or interrupt, Hardline replays rollback from the local journal it just built
- on a later `hardline rollback ...`, Hardline loads the newest successful remote journal for that profile

Failed applies do not create remote success journals. A later manual rollback cannot "undo the failed apply" unless there was already an older successful journal on the target.

## Remote Journal Stack

Each successful apply gets its own timestamped file under:

```text
/var/lib/hardline/runs/<profileID>/<runID>.json
```

`RunID` is a UTC timestamp string, so lexicographic order is also chronological order. Rollback loads the lexicographically last file, meaning "most recent successful apply."

After a successful manual rollback:

- Hardline deletes the journal file it just used
- the previous successful apply, if any, becomes the new rollback target

So remote journals behave like a stack of successful applies for a profile on a host.

## Integrity And Format

Journals currently use version `2`.

When serialized:

- the checksum field is cleared
- the journal is marshaled with indentation
- a SHA-256 checksum of that canonical JSON is computed
- the checksum is written back into the final JSON

When loaded, rollback verifies that checksum before trusting the journal contents.

That checksum does not make the journal tamper-proof against a privileged attacker, but it does protect against corruption and accidental damage. If the file on disk does not match the recorded checksum, rollback refuses to trust it.

## Rollback Modes

Plugins declare a `RollbackMode` in their capture result. Today the important modes are:

- `deterministic`
- `best_effort`
- `noop`

`deterministic` means the plugin captured enough information to restore the prior state exactly enough for Hardline's model. The built-in plugins that manage files and services use this:

- `template`
- `firewall`
- `service`
- `file_meta`

`best_effort` means the step can be meaningfully reversed, but not with strong transactional guarantees. The built-in `packages` plugin uses this mode because package-manager operations like `apt update`, `upgrade`, and `autoremove` are not losslessly reversible.

`noop` means there is nothing to revert for rollback purposes.

In practice:

- file rollback restores the previous file contents and mode, or removes the file if it did not exist before
- file-metadata rollback restores the previous mode/owner/group and managed `i`/`a` attrs on the existing path; it clears managed attrs first so an immutable target does not reject the restoring `chmod`/`chown`, and it never re-creates a path that has since been deleted
- service rollback restores enabled/active state
- package rollback removes packages that this run installed when they were absent before, reinstalls packages that this run purged when they were present before, prefers the recorded pre-apply version when available, and skips no-op runs whose before/after package state is identical

The package plugin also records notes when rollback is inherently lossy, such as:

- `apt update is not directly reversible`
- `apt upgrade rollback is best-effort`
- `apt autoremove rollback is best-effort`

## What A Step Snapshot Actually Contains

The object snapshots are typed, not raw shell output:

- file snapshots record path, existence, mode, and base64-encoded contents
- file-metadata snapshots record path, existence, mode, owner, group, and the managed `i`/`a` chattr letters — and deliberately no file contents
- service snapshots record unit name plus enabled/active/known state
- package snapshots record package name, whether it was installed, the version when known, and whether the step requested install or purge

That is why rollback can reason differently about different object kinds instead of replaying opaque commands.

## Automatic Rollback During Apply

Rollback is not only a separate command. It is also used internally during `apply`.

If a step fails after earlier steps already succeeded:

- Hardline reports the failed step
- replays rollback over the already-recorded steps
- walks those steps in reverse
- returns an error that distinguishes between:
  - apply failed and automatic rollback completed
  - apply failed and automatic rollback also failed

The same local-journal path is used when the apply context is cancelled by `SIGINT` or `SIGTERM`.

## Rollback Execution Rules

Rollback walks step records in reverse order.

Within each step, it restores the recorded `Before` objects in reverse object order.

Two important behaviors are easy to miss:

- steps whose `Before` and `After` snapshots are identical are skipped
- service-bearing steps are deferred until after non-service steps, so file and package restoration happens first

That service deferral is operationally important. Restoring files and packages before restoring service state reduces the chance of restarting a unit against half-restored configuration.

The no-delta rule also explains why repeated desired-state runs are often self-cancelling for packages and services. If profile **A** installs `htop` when it is absent and profile **B** later asks for `htop` when it is already installed, B records `Before.WasInstalled = true` and `After.WasInstalled = true`, so B's rollback step is skipped and does **not** uninstall the package. Only A's earlier state-changing run would have a journal entry capable of removing it on rollback. Services behave similarly because rollback records coarse enabled/active state, not every restart as a distinct durable change. Files are different: if two profiles write different bytes to the same managed file, that is a real delta, not a no-op, which is why file overlap remains the dangerous case.

## Why Conflict Detection Compares Against `After`

Before overwriting state, rollback compares the journal's recorded post-apply state against the current remote state.

This check uses `After`, not `Before`.

That is the right comparison because the question rollback is asking is:

"Is the host still in the state this profile last wrote?"

If the answer is no, then something changed after apply, and rollback should not blindly restore old state on top of newer intent.

## Conflict Detection By Object Type

That check currently covers:

- file contents
- file metadata (mode/owner/group/attrs)
- service enabled state
- service active state
- package installed state
- installed package version, when available

More specifically:

- for files, rollback reads the current remote file and compares it to the journal's recorded post-apply contents
- for file metadata, rollback re-reads the target's current mode/owner/group/attrs and compares them to the recorded post-apply snapshot; a path that is now absent (or whose metadata cannot be read) also counts as a conflict
- for services, rollback compares current `systemctl is-enabled` and `systemctl is-active` results to the recorded post-apply service state
- for packages, rollback compares whether the package is installed now to whether it was installed after apply, and when the package is still installed and the journal has a version, it also compares versions

If a mismatch is detected, rollback stops and reports that the object changed after apply.

`--force-rollback` bypasses that protection.

## What `--force-rollback` Actually Means

`--force-rollback` does not make rollback smarter. It makes it less conservative.

With `--force-rollback`, Hardline still uses the same journal, same reverse order, and same restore logic. The difference is that when current remote state no longer matches the recorded `After` snapshot, Hardline logs a warning and proceeds anyway.

That is sometimes necessary, but it is intentionally not the default because it means:

- overwriting changes made after apply
- potentially destroying another profile's state
- acting on stale assumptions about what is currently on the host

The docs in [Failure And Recovery](../users/failure-and-recovery.md) go deeper on overlapping-profile hazards, especially when two profiles touch the same managed file.

## Current Limits

Rollback is strong, and it is transactional to the practical limit of an agentless SSH-based system, but it is not a full transaction system.

Hardline journals captured state before and after each step, persists that journal as it goes, and can roll back completed work. What it does not have is a resident remote agent, a shared commit protocol across file/service/package operations, or a target-side snapshot mechanism.

Important limits:

- it is not atomic across a whole apply
- it only knows about objects the plugin captured
- package rollback is best-effort, not lossless
- a failed apply leaves no remote success journal
- if the target is unreachable during automatic rollback, the local journal becomes the only structured recovery record

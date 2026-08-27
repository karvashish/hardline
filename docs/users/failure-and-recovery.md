# Failure And Recovery

What happens when things go wrong during a Hardline run, and how to recover. This page is grounded in the actual execution flow — for the code-level detail see [Execution Flow](../internals/execution-flow.md) and [Rollback](../internals/rollback.md) in the internals docs.

## What Hardline Guarantees

Before describing failures, it's worth being explicit about what Hardline actually promises:

- **`verify` and `plan` never mutate the target.** A failure during these phases leaves the remote host untouched, full stop.
- **`apply` captures `Before` state and writes a journal entry before running any plugin that mutates state.** Each step's `Before` snapshot is on disk (local journal) before the plugin runs.
- **If a step fails after earlier steps succeeded, `apply` auto-rolls back those earlier steps using the journal it just wrote.** You do not have to run `rollback` manually after a mid-run failure — Hardline attempts it automatically on the way out.
- **A successful `apply` persists its journal remotely.** Subsequent `rollback` invocations read that remote journal.
- **Rollback walks steps in reverse order, compares current remote state to the recorded post-apply state, and refuses to overwrite anything that has changed since.** `--force-rollback` bypasses that check; the default does not. Steps that touch service objects are held back and reverted last, after the reverse pass, so a service is not restarted before the config it depends on has been restored.
- **A rollback that dies partway is resumable.** It claims the journal by marking it `rolling_back` before it starts, and leaves it in place if it does not finish. The next `hardline rollback` picks that journal up and continues rather than refusing a half-reverted host; steps the failed attempt already reverted are recognized as reverted, not reported as third-party drift.

What Hardline does **not** guarantee:

- **It is not atomic across steps.** If a step mutates three files and fails on the second one, the first file is changed and the third is not. Hardline will attempt to roll back the first via the journal; the third was never touched.
- **It does not replay network operations automatically.** If SSH drops mid-step, the step is considered failed, the journal records what had been captured, and recovery is your call.
- **It does not re-run a failed apply from the failure point.** A second `apply` invocation re-verifies, re-plans, and starts over. The lock prevents two concurrent applies, not two sequential ones.
- **It does not perform transactions on external state.** Package manager state, service state, and firewall state are real side effects. Rollback restores them best-effort from the captured snapshots, not from a filesystem-level checkpoint.

## Interrupting A Run (Ctrl-C)

Hardline installs a signal handler during `apply`:

- **First `SIGINT` or `SIGTERM`** cancels the apply context. The current plugin step runs to completion, any already-completed steps are rolled back via the journal, and Hardline exits non-zero because the apply did not complete. Today that graceful interrupted path surfaces as exit code `1`.
- **Second signal** exits immediately with code `130`. Any in-flight plugin step is left in whatever state it was in. The local journal is still on disk, so you can inspect it later.

If you accidentally hit Ctrl-C and want Hardline to finish cleanly, **do not press it again**. Let the graceful rollback run.

After a graceful cancel-and-rollback:

1. Confirm the host's current state with `hardline plan ...` against the same profile.
2. A clean rollback puts the host back where it was before the run, so the plan should read like the one you started from: the same steps planned, the same changes pending. Plan compares the profile against live host state, so that repeat is the success signal, not evidence the rollback did nothing.
3. If some steps now report as aligned while others still plan changes, the rollback did not revert everything - read the error message to see which object couldn't be reverted, then decide whether to fix manually, re-apply, or use `--force-rollback`.

## SSH Drops Mid-Apply

If the SSH connection to the target dies mid-apply, the step that was running returns an error to the apply loop. From Hardline's perspective this is the same as any other step failure:

1. The current step is marked failed.
2. Hardline attempts to roll back the already-completed steps via the local journal. This requires a working SSH connection to the target.
3. If the SSH connection is still broken, rollback itself fails, and Hardline exits with an error.

**If the connection comes back:**

- Run `hardline rollback <profile> --host ...` manually to attempt the rollback with the remote-persisted journal. This only works if a *previous* apply had succeeded and persisted a remote journal — a failed apply never writes one. If no remote journal exists, rollback has nothing to walk on that path.
- The runner-side journal at `${HARDLINE_STATE_DIR:-/tmp/hardline/runs}/<host>/<profileID>.json` is still on disk, carrying status `failed` or `interrupted`. **`--local-journal` will not replay it** - rollback runs only journals marked `success` or `rolling_back` (see [Partial Apply Left No Remote Journal](#partial-apply-left-no-remote-journal)). Read it directly instead, to understand what was captured, what was changed, and what needs manual cleanup.

**If the connection does not come back:** the target is in an intermediate state. The apply did not complete, there is no remote success journal, and the local journal is the only record of what was touched. Recovery is manual — typically via console access to the target — using the local journal as a map of affected objects.

## A Step Fails Mid-Apply

When a plugin's `Apply` returns an error:

1. Hardline records the failure on the step record.
2. If prior steps ran successfully and mutated state, Hardline walks the journal in reverse and rolls each one back in turn.
3. The auto-rollback uses the same conflict detection as a manual `rollback` run. If an intervening change prevents clean reversal, auto-rollback stops with an error — it will not silently force.
4. Hardline exits non-zero with the original failure as the root cause.

The target is typically left in the pre-apply state if auto-rollback succeeds, or in a partial state if auto-rollback hits a conflict. Read the final error lines carefully — they distinguish between "apply failed, rolled back cleanly" and "apply failed, rollback also failed."

## Stuck Apply Lock

`apply` and `rollback` both acquire `/var/lib/hardline/.apply-lock.d/` on the target before touching anything. Only one mutating run can be in flight per host at a time. If a previous run crashed without releasing the lock, the next `apply` or `rollback` will refuse to start.

To clear a stale lock:

1. **Confirm no other `apply` is actually running.** Hardline never runs on the target, so there is no `hardline` process there to look for - every remote command arrives as `sudo -n sh -lc ...` over its own SSH session. Check the *runners*: any machine that might be pointing at this host. On the target itself the only corroborating signal is an open SSH session for the admin user (`who`, `ss -tnp state established '( sport = :22 )'`), which tells you someone is connected but not that Hardline is mid-run.
2. **Confirm no partially-applied state is in flight.** If an apply was actively mutating the host when it crashed, check for a local journal on the runner that crashed — it tells you what was captured before the crash.
3. **Remove the empty lock directory** on the target:

   ```bash
   sudo rmdir /var/lib/hardline/.apply-lock.d
   ```

4. Re-run `hardline plan <profile> --host ...` to see the current drift, then decide whether to re-apply or roll back via the last persisted remote journal.

Do not clear the lock from a script. Treat it as a manual decision — the lock exists specifically because concurrent applies would corrupt the journal.

## Package Manager Lock Contention

The packages plugin checks the selected backend's locks before running: the dpkg locks for `apt`, the rpm and dnf metadata locks for `dnf4` and `dnf5`. If an auto-update job, another admin session, or a manual package command is holding the lock, Hardline fails fast with a lock-contention error instead of waiting.

Recovery is just waiting:

- On Ubuntu, `unattended-upgrades` runs on a systemd timer. Check with `systemctl status unattended-upgrades.service`. Wait for it to finish, then retry.
- On RHEL-family hosts the equivalent is `dnf-automatic.timer`. Check with `systemctl status dnf-automatic.service`.
- If the lock is held by a stale process (rare), investigate with `sudo fuser /var/lib/dpkg/lock-frontend` (apt) or `sudo fuser /var/lib/rpm/.rpm.lock` (rpm) before removing anything.

If your target runs `unattended-upgrades` frequently enough that it keeps racing Hardline, either:

- Schedule Hardline runs outside the upgrade window, or
- Manage `unattended-upgrades` itself through Hardline (the base profile already does this, so subsequent applies can disable or reschedule it).

## Rollback Conflicts

When `rollback` refuses to proceed with `step "<id>": files were modified after this profile ran — rolling back will overwrite those changes`, something — another tool, a manual edit, a second Hardline profile — touched a managed object between the apply and the rollback. The error lists each conflicting object and ends with `re-run with --force-rollback to overwrite`.

Options, in increasing risk order:

1. **Read the conflict report carefully.** Hardline tells you which object changed. Decide whether the change is wanted. If it is, you probably don't want to roll back.
2. **Fix the conflict at the source.** If another tool is overwriting the same file, reconcile there, not in Hardline.
3. **Use `--force-rollback`.** This bypasses the conflict check and overwrites the newer state with the pre-apply state. Only use this when you understand exactly what's being overwritten.

## Overlapping Profiles Writing The Same File

Two profiles that write the **same managed file** on the same host produce journals that describe contradictory histories. The conflict check in `rollback` catches this on the default path — but if you reach for `--force-rollback`, you will silently destroy state.

This is a file-specific problem. For packages and services the overlap is self-cancelling: if profile A installs `htop`, profile B's attempt to install it lands with `Before.WasInstalled = true` and `After.WasInstalled = true` — identical snapshots — so B's step is treated as a no-op and skipped during rollback (`stepActuallyChanged` in [`internals/rollback/rollback.go`](https://github.com/karvashish/hardline/blob/main/internals/rollback/rollback.go)). Service state is the same coarse binary (`enabled`, `active`), and service restarts are idempotent. File contents are not binary and not idempotent — every byte-level divergence between A and B is a real change that the journal records and that rollback will act on.

Each step's journal entry holds `Before` (pre-apply content) and `After` (post-apply content) snapshots. Rollback restores `Before`. Before restoring, it compares the **current** remote file to `After` and refuses if they differ (see `checkStepConflicts` in [`internals/rollback/rollback.go`](https://github.com/karvashish/hardline/blob/main/internals/rollback/rollback.go), which delegates to each plugin's `DetectConflict`). The overlap trap works like this:

1. Apply profile **A**. A's journal: `Before = original`, `After = A's contents`.
2. Apply profile **B**, which writes to the same file. B's journal: `Before = A's contents`, `After = B's contents`. The file on disk now holds `B's contents`.
3. Roll back **A**. Conflict check: current (`B's contents`) vs A's `After` (`A's contents`) → mismatch → rollback refuses with `current content differs from what this profile wrote (modified since apply)`.
4. If you re-run with `--force-rollback`, A's rollback writes A's `Before` (`original`) over `B's contents`. B's journal still says `Before = A's contents`, which is no longer true. Any later `rollback B` will hit the same conflict, and forcing *that* restores `A's contents` — not the original, and not what anyone expected.

On the default (non-forced) path the conflict check keeps the host consistent — it just makes rollback unusable for the earlier profile until you resolve the overlap. `--force-rollback` is where the data loss happens; both profiles' `Before` snapshots are now unreliable, and walking them in any order will leave the file in a state that matches neither profile's intent.

The rule: **one managed file, one profile.** If two profiles both want to render `/etc/ssh/sshd_config.d/00-hardline-ssh.conf`, merge them or split the destinations.

How to stay out of this trap:

- The template plugin's managed-destination rules (`/etc/...` + a `99-hardline` or `00-hardline` basename + `.conf`/`.nft`/`.rules` extension) make collisions visible at authoring time — if two profiles both want `00-hardline-ssh.conf`, the diff shows it before you sign.
- Reserve a basename prefix per profile if you author several for the same fleet (`99-hardline-<profile-id>-*.conf`).
- If you inherit two overlapping profiles, do **not** reach for `--force-rollback` to untangle them. Reapply the profile whose state you want to keep; that rewrites the current journal's `After` to match reality and gives you a clean rollback path for at least one of the two profiles.

## Runner-Side Journal

After a successful apply, Hardline persists the journal remotely and then deletes the runner-side local journal — unless you passed `--keep-local-rollback`, in which case the local copy is preserved.

The local journal path is:

```text
${HARDLINE_STATE_DIR:-/tmp/hardline/runs}/<host>/<profileID>.json
```

The default root is Go's `os.TempDir()` — `$TMPDIR` if set, otherwise `/tmp` — so it is wiped on runner reboot. If you rely on the local journal for post-hoc audit or disaster recovery, **set `HARDLINE_STATE_DIR` to a persistent location** (for example `/var/lib/hardline/runs` on the runner) and pass `--keep-local-rollback` on every apply.

## Partial Apply Left No Remote Journal

A remote journal is only written after a full, successful apply, so the interrupted or failed run itself leaves none. That does not always mean `rollback` finds nothing: it loads the newest file already under `/var/lib/hardline/runs/<profileID>/`, which is the last *earlier* successful apply, and only fails with `no journal found for profile` when the directory holds none. Walking that older run is rarely what a partial apply needs, and the conflict preflight normally refuses it anyway, because the host no longer matches the state that apply left behind.

`--local-journal` walks the runner-side journal instead:

```bash
hardline rollback <profile> -H example.com -u deploy -k ~/.ssh/id_ed25519 --local-journal
```

That reads `${HARDLINE_STATE_DIR:-/tmp/hardline/runs}/<host>/<profileID>.json`, refuses it if it was written for a different host than the one you passed, and otherwise runs the same conflict preflight, reverse walk, and per-plugin restore as a target-journal rollback. On success it deletes the runner-side journal instead of a remote one.

**It only accepts a journal whose status is `success` or `rolling_back`.** Anything else is refused with `last run is not marked successful (status=...)`. The status a local journal carries depends on how the run ended:

| How the run ended | Local journal status | `--local-journal` |
| --- | --- | --- |
| Every step applied, but the target journal could not be persisted | `success` | **Yes** - this is the case the flag exists for, and apply prints the exact command |
| Every step applied, target journal persisted, `--keep-local-rollback` passed | `success` | Yes - equivalent to the remote journal |
| A step failed | `failed` | No |
| `SIGINT`/`SIGTERM` cancelled the run | `failed`, or `interrupted` if the runner was killed during the inline rollback | No |
| The runner was killed outright | `in_progress` | No |

The three refused rows are not a gap in coverage: on the `failed` and `interrupted` paths apply has **already** walked the journal and rolled back the steps that had completed, before it exited. A second reverse walk is not what those runs need. What they need is the journal read as a record:

- Read the local journal to identify affected objects and reconcile manually. This is the only path when apply's automatic rollback itself failed - the error line says so explicitly, and the host is partly reverted.
- Re-run `apply` to force the host back into the desired state, if you're confident the partial state is safe to overwrite.

Both `--local-journal` and post-hoc inspection depend on that file still being there, which is the single most important reason to use `--keep-local-rollback` on critical targets: without it, the local journal disappears as soon as an apply succeeds, and the remote journal is the only surviving copy. If the remote host is subsequently unreachable, you have no record at all.

## Version Drift Between Runner And Target

Hardline checks the profile's `min_hardline` field against its own build version. If the runner is older than the profile expects, it refuses to run. Prerelease suffixes are ignored in that comparison, so an `-rc` build satisfies the same `min_hardline` as its final release.

It also checks the profile's `profile_schema` against the schema version the binary supports, and refuses when the profile's is newer. Both checks run in `plan` and again in `apply`. Upgrade the runner before applying.

There is no corresponding check for the *target* host — Hardline assumes the target does not need a Hardline binary. Nothing is installed on the target by Hardline itself.

## When In Doubt

- `hardline plan <profile> -H <host> -u <user> -k <key>` is always safe. It reads remote state, compares to the profile, and prints the drift. Run it any time you want to know where the host stands without touching anything.
- `--debug` (or `-d`) is verbose but grounded — use it for bug reports and for understanding what Hardline saw.
- `--log-file PATH` captures the full trace alongside whatever went wrong.

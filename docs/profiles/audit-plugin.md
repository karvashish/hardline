# Audit Plugin

Writes the Linux audit rule policy and loads it into the running kernel.

```json
{
  "id": "auditd-rules",
  "plugin": "audit",
  "config": {
    "src": "templates/40-audit-hardening-rules.tmpl",
    "dest": "/etc/audit/rules.d/99-hardline.rules",
    "mode": "0640"
  }
}
```

Config fields:

- `src`: **required**. Profile-relative rules file, declared in `profile.json` `templates[]` like any other signed content
- `dest`: **required**. Must be a managed path under `/etc/audit/rules.d/`, which is the directory `augenrules` compiles
- `mode`: octal, defaults to `0640`

## Why this is not a template plus a service step

Writing the rules file is the easy half. Making the kernel run it is the half
that has no service-plugin answer on a RHEL-family host:

- `auditd.service` sets `RefuseManualStop`, so `state: restarted` is refused.
- Its `ExecReload` sends `SIGHUP`, which makes auditd re-read `auditd.conf` and
  does **not** reload `rules.d`.
- The service plugin returns early when a unit is already active, so
  `state: started` runs no command at all on a host where auditd is up.

The result is a rules file on disk that the running kernel has never been told
about. `augenrules(8)` is the control path RHEL documents, so this plugin owns
the file and runs the load itself.

## What it does

Apply writes `dest` when its content or its mode differs, then runs
`augenrules --load` when either the file changed or the running policy does not
already carry the rules. A host that is already aligned gets no write and no
load. Mode counts as much as content: the right rules at `0666` are an audit
policy any unprivileged user can rewrite.

The load is then **verified against the kernel, not against the file**, and by
rule body rather than by label: every rule written is parsed and must appear in
`auditctl -l` with the same watch path and permissions, or the same list,
syscalls and field comparisons. A key alone proves nothing, because two rules
can carry the same `-k` and watch entirely different things. The two spellings
are reconciled, because `auditctl` re-renders every rule it prints and each
difference would otherwise fail the step right after a load that worked:

| A rules file writes | `auditctl -l` prints back |
| --- | --- |
| `-S a,b` | `-S a -S b` |
| `-k name`, on a syscall rule | `-F key=name` |
| `-F auid!=4294967295` | `-F auid!=unset`, or `-F auid!=-1` |
| `-w /etc/audit/` | `-w /etc/audit` |
| `-w /etc/passwd`, with no `-p` | `-w /etc/passwd -p rwxa` |
| `-w /etc/passwd -p wa` | that, or its `-F path= -F perm=` form |

A rule the kernel is not running is named in the failure. A file that declares
no rules at all is refused, because a load with nothing to check reports success
without proving anything.

The running policy carries whatever else the host loaded, so a rule in
`auditctl -l` that this comparison cannot model is ignored rather than failing
the step: it belongs to another owner and is never compared. Only the rules the
profile declares have to parse, and those are refused outright if they do not.

Before anything is written, apply refuses three states it cannot honestly act
on:

- `-D` in the managed rules. This file is loaded after the distribution's base
  config and anything else that owns part of the policy, so clearing the ruleset
  from it would delete rules the profile does not own.
- `-e 2`, in the file or already set on the host (`auditctl -s` reporting
  `enabled 2`). The policy is locked until reboot: a load is accepted and then
  ignored, and the run could not undo itself.
- A `-w` path that does not exist on the target. `auditctl` rejects that watch
  and `augenrules --load` then fails for the whole rule set, so the missing
  paths are named up front rather than surfacing as one opaque load failure.

Plan reports each of these as a highlight before apply refuses it.

Plan reports the two states separately, so "the file matches but the policy is
not loaded" is visible before you apply.

## Rollback

The plugin owns the rules file, so a single step captures it and rollback
restores it and re-runs `augenrules --load`, in that order. That ordering is
the reason the write and the load live in one plugin: rollback walks steps in
reverse, so a separate load step would have run before the file it depends on
had been put back, leaving the kernel enforcing rules that are no longer on
disk.

The capture records what `auditctl -l` reports alongside the file. A run that
finds the file already correct but the kernel missing rules still loads them,
and a file-only capture would show no delta for that run, so rollback would
skip a step that did change the running policy.

The reload after a restore is not verified against the rules. The previous rules are whatever
they were, and their keys are not known from the snapshot; a failure to reload
is still reported.

## Ordering with the service step

Enable and start `auditd` before this step so the daemon is up to log what the
rules match:

```json
{ "id": "auditd-service-enable", "plugin": "service",
  "config": { "name": "auditd", "enabled": true, "state": "started" } },
{ "id": "auditd-rules", "plugin": "audit",
  "config": { "src": "templates/40-audit-hardening-rules.tmpl",
              "dest": "/etc/audit/rules.d/99-hardline.rules", "mode": "0640" } }
```

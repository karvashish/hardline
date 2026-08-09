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

Apply writes `dest` when the content differs, then runs `augenrules --load`
when either the file changed or the running policy does not already carry the
rules. A host that is already aligned gets no write and no load.

The load is then **verified against the kernel, not against the file**: the
plugin extracts every `-k` key from the rules it wrote and requires each one to
appear in `auditctl -l`. If a key is missing, apply fails and names it. Rules
that declare no `-k` keys are refused at apply, because a load with nothing to
check would report success without proving anything.

Plan reports the two states separately, so "the file matches but the policy is
not loaded" is visible before you apply.

## Rollback

The plugin owns the rules file, so a single step captures it and rollback
restores it and re-runs `augenrules --load`, in that order. That ordering is
the reason the write and the load live in one plugin: rollback walks steps in
reverse, so a separate load step would have run before the file it depends on
had been put back, leaving the kernel enforcing rules that are no longer on
disk.

The reload after a restore is not key-verified. The previous rules are whatever
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

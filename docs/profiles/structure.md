# Profile Structure

A profile directory typically looks like this:

```text
my-profile/
  profile.json
  manifest.json
  manifest.sig
  actions/
    00-base.json
    10-journald.json
  templates/
    50-journald-hardening.conf.tmpl
  profile.overrides.json
```

Files have distinct roles:

- `profile.json` declares metadata, OS compatibility, action files, templates, and allowed override keys
- `actions/*.json` contain ordered steps
- `templates/*` hold static assets used by plugins
- `manifest.json` and `manifest.sig` provide integrity and signature verification
- `profile.overrides.json` is optional runtime input and is not part of the signed manifest

## `profile.json`

Example:

```json
{
  "id": "starter-secure-ubuntu-24.04-lts",
  "display_name": "Starter Secure Ubuntu 24.04 LTS",
  "version": "1.0.0",
  "os": {
    "family": "ubuntu",
    "version": "24.04",
    "variant": "lts"
  },
  "profile_schema": 1,
  "min_hardline": "0.0.1",
  "actions": [
    "actions/00-packages.json",
    "actions/10-journald.json"
  ],
  "templates": [
    "templates/50-journald-hardening.conf.tmpl"
  ],
  "allowed_overrides": [
    "ssh_port"
  ]
}
```

Field reference:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable profile identifier used in journals and logs. Must match `^[A-Za-z0-9][A-Za-z0-9._-]*$` |
| `display_name` | yes | Human-readable name shown in output |
| `version` | yes | Profile version string |
| `os` | yes | Target OS. All three subfields — `family`, `version`, `variant` — are required. `family` must match `^[a-z][a-z0-9._-]*$`; `version` must match `^[0-9]+(\.[0-9]+)*$` |
| `profile_schema` | yes | Schema version supported by Hardline |
| `min_hardline` | yes | Minimum Hardline version allowed to run the profile |
| `coverage_ledger` | no | Profile-relative path to a signed [coverage ledger](coverage-ledger.md): what each control wants, where it came from, and which steps produce it |
| `actions` | yes | Ordered list of action file paths, relative to the profile root |
| `templates` | yes | Declared template files that plugins may load |
| `allowed_overrides` | no | Allowed runtime override keys |

Override key names must match:

```text
^[a-z][a-z0-9_]*$
```

Duplicates are rejected. `additionalProperties` is `false`, so any field not in the table above fails schema validation.

At run time Hardline compares `os.family` against the target's `/etc/os-release` `ID`, `os.version` against `VERSION_ID`, and `os.variant` against `VARIANT_ID`. Version matching uses the components declared by the profile: `9` accepts `9` and any `9.x` value, while `24.04` accepts `24.04` and any `24.04.x` value but rejects `24.10`. Variant matching is case-insensitive and only refuses a host that publishes a different `VARIANT_ID`: a host that publishes none (the RHEL family, Ubuntu) cannot contradict the profile and is not refused on a guess.

## One Managed File, One Profile

A managed file must be written by **exactly one profile** on any given host. If profile A and profile B both render to `/etc/ssh/sshd_config.d/00-hardline-ssh.conf`, their journals record before/after snapshots that reference each other's writes. Rollback's conflict check catches the overlap on the default path — but once you reach for `--force-rollback`, both journals' `Before` snapshots are unreliable and restoring either one produces a file that matches neither profile's intent. See [Overlapping Profiles Writing The Same File](../users/failure-and-recovery.md#overlapping-profiles-writing-the-same-file) for the step-by-step trace.

This constraint applies to file contents only. Packages (`installed` / `not installed`) and services (`enabled`/`active`) are binary target states — if two profiles both say "install `htop`" or "enable `sshd`", the second apply records a no-op step and drops out of rollback harmlessly, and a service restart is idempotent. Every byte-level disagreement between two profiles on the same file, by contrast, is a real change that the journal commits to.

If you author multiple profiles for the same fleet, reserve a basename prefix per profile (for example `99-hardline-<profile-id>-*.conf`) so file collisions become obvious at authoring time.

Next:

- [Action Files](action-files.md)
- [Overrides And Signing](overrides-and-signing.md)

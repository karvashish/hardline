# hardline plan – design (pre-implementation)

## 0. Goal

`hardline plan` should, WITHOUT making changes on the target:

1. Load and validate a profile (and its actions/templates).
2. Contact the target server and inspect current state (read-only).
3. Generate a logical diff of what `apply` would do.
4. Compute per-step risk scores and priority order.
5. Derive mitigations and rollback strategies for each step and use them to reduce risk.
6. Aggregate a final run-level risk and present it clearly to the user.

Everything here is behavior and structure only, no implementation details.

---

## 1. Inputs and Outputs

### Input

- CLI parameters:
  - Profile identifier/path.
  - Host, user, key path (same as `apply`).
  - Optional flags (e.g. `--json` in future; not required for now).

- On-disk data (local):
  - `Profile` object:
    - `id`, `display_name`, `version`
    - `os` → `{ family, version, variant }`
    - `profile_schema`, `min_hardline`
    - `actions: []string` (file identifiers / paths)
    - `templates: []string` (template identifiers / paths)

  - Action files referenced in `profile.actions`:
    - `ActionFile` with `steps: []Step`.

  - Templates referenced by `Step.template.src` / `Step.template.dest`.

- On-target data (remote via SSH, read-only):
  - Package manager state.
  - Filesystem state for template destinations.
  - Service manager state.
  - Firewall state.
  - (Optionally) environment for validation commands (but NOT executing them in plan, unless explicitly tagged safe).

### Output

Human-oriented report (stdout), structured as:

1. Header (profile, host, OS info).
2. Validation report (profile + actions + templates).
3. Planned changes (diff) per step.
4. Risk scoring and prioritization per step.
5. Mitigations and rollback description per step.
6. Aggregated final risk for the whole run with a short justification.

---

## 2. Profile, Action, Step model (planner’s view)

### Profile

- Uses existing `Profile` schema as source of truth.
- Planner cares mainly about:
  - `id`, `display_name`, `version`
  - `os` for target compatibility
  - `profile_schema`, `min_hardline` for version gating
  - `actions` for which action files to load
  - `templates` for verifying template existence and mapping

### Steps

Existing `Step` schema:

- Core attributes:
  - `id: string`
  - `type: "packages" | "template" | "service" | "firewall" | "validate"`
  - `severity: "low" | "medium" | "high" | "critical"` (default: medium)
  - `risk_class: "none" | "access" | "availability" | "data_loss" | "integrity" | "compliance" | "other"`
  - `control_tags: []string`

- Type-specific specs:
  - `packages: PackageSpec`
  - `template: TemplateSpec`
  - `service: ServiceSpec`
  - `firewall: FirewallSpec`
  - `validate: string`

Planner attaches context:

- Step context:
  - Profile id
  - Action file identifier/path
  - Step index in that action file
  - Raw `Step` object

---

## 3. Phase A – Validation (local, pre-SSH)

### Objectives

- Catch structural or version mismatches before remote inspection.
- Produce a clear report of issues (errors vs warnings).
- Abort planning if there are blocking errors.

### Checks

1. Profile-level validation:
   - `profile_schema` is supported by this hardline version.
   - `min_hardline` is ≤ current hardline version.
   - `id`, `display_name`, `version`, `os` all present.
   - Each entry in `actions` is valid/resolvable to an ActionFile.
   - Each entry in `templates` is valid/resolvable (for existence / path sanity).

2. Action file validation:
   - ActionFile has `steps` array.
   - No unknown top-level fields.

3. Step-level validation:
   - Required fields present:
     - `id`, `type`, `severity`, `risk_class`, `control_tags`.
   - `type` is one of: `packages`, `template`, `service`, `firewall`, `validate`.
   - `severity` is one of: `low`, `medium`, `high`, `critical`.
   - `risk_class` is one of: `none`, `access`, `availability`, `data_loss`, `integrity`, `compliance`, `other`.
   - Payload consistency:
     - `type=packages` ⇒ `packages` populated; others empty.
     - `type=template` ⇒ `template` populated; others empty.
     - `type=service` ⇒ `service` populated; others empty.
     - `type=firewall` ⇒ `firewall` populated; others empty.
     - `type=validate` ⇒ `validate` string populated; others empty.

4. Payload-specific validation:
   - `PackageSpec`:
     - `update`, `upgrade`, `autoremove`, `install`, `purge` all present.
   - `TemplateSpec`:
     - `src`, `dest`, `mode` present and syntactically valid.
   - `ServiceSpec`:
     - `name` non-empty.
     - `state` either empty or in enum: `started | stopped | restarted | reloaded`.
   - `FirewallSpec`:
     - `backend` (`nftables`).
     - `policy` in: `allow | deny | reject | drop`.
     - If `template_src` / `template_dest` present, they are syntactically sane.
   - `validate`:
     - Non-empty command/spec string.

### Output of this phase

- List of issues, each with:
  - Location (profile vs action file vs step id).
  - Severity (`error` vs `warning`).
  - Message.

- If any `error` exists → `plan` stops, prints validation section, and exits non-zero.

---

## 4. Phase B – Remote inspection (read-only SSH)

### Objectives

- Discover the current state of all resources that actions would touch.
- Do this without changing anything.
- Produce a compact “current state summary” for each step.

### General behavior

- Open SSH connection using the same mechanism as `apply`.
- No commands are run that can change state (no writes, no restarts, no installs, no firewall modifications).
- Assume the current implementation tools:
  - APT for package operations.
  - systemd/systemctl for service operations.
  - nftables for firewall operations.

### Per-type inspection

1. `packages`:
   - Assume an apt-based system and inspect via apt/dpkg queries.
   - For `install`:
     - Check if each requested package is installed and get current version.
   - For `purge`:
     - Check if each package is installed/present.
   - For `update` / `upgrade` / `autoremove`:
     - Determine whether there are pending updates, upgradable packages, or removable deps (only enough to say “has effect” vs “no effect”, not a full list).

2. `template`:
   - Check existence of `dest` path:
     - Exists or not.
     - Type: regular file / symlink / directory.
     - Mode bits.
     - (Optionally) size and a small content hash.
   - Planner may optionally render template locally to compare content hashes (without showing full diff to user, just “will change / matches”).

3. `service`:
   - Using systemd via `systemctl`:
     - Query `is-enabled` for service.
     - Query `is-active` (running / stopped / failed).
   - Note any special states (masked, static) if discoverable.

4. `firewall`:
   - Assume nftables backend and query nftables configuration.
   - Extract:
     - Current default policy.
     - Existing rules relevant to `allow` (`port`, `proto` pairs).
     - Any rules clearly conflicting with the desired policy.

5. `validate`:
   - Plan mode treats these as “post-apply checks”.
   - Default behavior:
     - Do not execute in `plan` (to guarantee no side effects).
     - Optionally, some specific `validate` forms tagged in `control_tags` as “safe_in_plan` could be dry-run, but the design does NOT require this.

### Output of this phase

For each step context:

- A compact current state summary appropriate to its type.
- Enough data to decide:
  - whether `apply` would change anything,
  - and what kind of change it would be.

---

## 5. Phase C – Diff generation (“what apply would do”)

### Objectives

- Normalize planned work for each step into a small set of change kinds.
- Provide short, human-readable descriptions.

### Change kinds (generic)

- `none`     → desired state is already met; no change.
- `create`   → resource will be created.
- `modify`   → resource exists but will be changed.
- `delete`   → resource will be removed.
- `execute`  → action is an execution/check with no persistent resource (primarily `validate`).

### Per-type diff logic (conceptual)

1. `packages`:
   - If some in `install` are not installed:
     - change kind: `modify`
     - description: “will install: pkg1, pkg2…”
   - If some in `purge` are installed:
     - change kind: `delete` (or `modify` if you prefer to treat purge as modify+delete)
     - description: “will purge: pkg3, pkg4…”
   - If `update/upgrade/autoremove` will perform actions:
     - change kind: `modify`
     - description: e.g. “will upgrade N packages” or “will clean up unused packages”.
   - If no relevant changes:
     - change kind: `none`.

2. `template`:
   - If `dest` does not exist:
     - change kind: `create`
     - description: “create file at dest”.
   - If `dest` exists but mode or content differs from rendered template:
     - change kind: `modify`
     - description: “update config at dest”.
   - If everything matches:
     - change kind: `none`.

3. `service`:
   - Compare desired enabled state vs current:
     - If different → change kind: `modify` with description about enable/disable.
   - Compare desired `state` vs current:
     - If `started` desired and service is stopped → `modify` (“start service”).
     - If `restarted` and service is active → `modify` (“restart service”).
     - If `reloaded` needed → `modify` (“reload service”).
   - If no effective changes:
     - `none`.

4. `firewall`:
   - Policy changed:
     - `modify` with description: “set default policy to X”.
   - New allow rules needed:
     - `create` / `modify` with description: “add allow rules for port/proto set”.
   - If no effective changes:
     - `none`.

5. `validate`:
   - Always considered `execute`:
     - description: “post-apply check: <validate command/spec>”.

### Output of this phase

For each step context:

- `change_kind` (none/create/modify/delete/execute).
- Short description of intended change.
- Optional structured “details” (like lists of packages, ports, dest path).

---

## 6. Phase D – Risk scoring and prioritization

### Objectives

- Attach a numeric “risk score” to each step that actually changes something.
- Use that to sort and annotate steps by priority (critical/high/medium/low).

### Components of the score

1. Base from `severity`:

   Example mapping:
   - `low`      → 1
   - `medium`   → 3
   - `high`     → 6
   - `critical` → 10

2. Added from `risk_class` (worst-case consequence):

   Example mapping:
   - `none`         → 0
   - `access`       → 5   (could lose SSH or authentication)
   - `availability` → 4   (service outage)
   - `data_loss`    → 6
   - `integrity`    → 5
   - `compliance`   → 4
   - `other`        → 2

3. Added from `change_kind`:

   Example mapping:
   - `none`    → 0
   - `execute` → 1
   - `create`  → 2
   - `modify`  → 3
   - `delete`  → 5

4. Added from dynamic context (type-specific):

   Conceptual rules:
   - Services:
     - names related to SSH/auth/network/firewall (`ssh`, `sshd`, `sshd.service`, `firewalld`, `iptables`, `network`, `systemd-networkd` etc.) → +3
     - ordinary application service → +1
   - Firewall:
     - changing default policy to more restrictive → +3
     - affecting ports 22/80/443 → +3
     - touch only non-critical ports → +1
   - Packages:
     - `purge` of critical or core packages (ssh, kernel, libc, systemd, etc.) → +5
     - kernel/core system upgrade → +3
   - Templates:
     - target paths under `/etc/ssh/`, `/etc/systemd/`, `/etc/sudoers*`, `/etc/pam.d/`, firewall configs → +3
     - other `/etc/*` → +1

### Raw step score

- `raw_score = severity_points + risk_class_points + change_kind_points + dynamic_points`.

This is computed for all steps with `change_kind != none`.

### Prioritization

- Steps are sorted in descending `raw_score`.
- A simple classification can be:
  - `< 5`   → low
  - `5–9`   → medium
  - `10–17` → high
  - `≥ 18`  → critical

This gives an ordered list of “most dangerous planned actions”.

---

## 7. Phase E – Mitigations and rollback (negative of risk points)

### Objectives

- Identify per-step mitigations and rollback strategies.
- Convert “good mitigations” into negative risk points (credits).
- Produce final per-step risk scores after mitigation.

### Mitigation model

For each step, `plan` will:

1. Infer or recommend mitigations (what to do before/during/after apply).
2. Infer a rollback path (how to reverse the change if needed).
3. Convert these into mitigation credits (negative numbers) that reduce the score.

Mitigations may also use `control_tags` to adjust behavior if your conventions define meaning for certain tags (e.g. `must_run_in_maintenance`, `requires_snapshot`, `safe_in_plan`, etc.).

### Per-type mitigation patterns (conceptual)

1. `template` steps:
   - Mitigation:
     - “Backup existing dest file to hardline-managed backup directory before overwrite.”
     - Optionally, “Validate syntax of the rendered config (e.g. systemd, sshd) before restart.”
   - Rollback:
     - “Restore backup to original location and reload/restart related service.”
   - Credits:
     - If reliable backup and restore path exists → subtract 3 points.
     - If only syntax validation or partial safeguard → subtract 1 point.

2. `service` steps:
   - Mitigation:
     - “Ensure out-of-band access (cloud console, IPMI, etc.) if this step involves SSH/auth.”
     - “Execute in a maintenance window for `availability`/`compliance` steps.”
   - Rollback:
     - “Revert to previous enabled/disabled state and restart/stop as before.”
   - Credits:
     - For access-critical changes with OOB access available → −3 points.
     - For maintenance-window safeguards only → −1 point.

3. `packages` steps:
   - Mitigation:
     - “Confirm healthy package manager state (dry-run update).”
     - For risky `purge`:
       - “Avoid purging critical system packages unless absolutely necessary.”
       - “Ensure a tested restore path (snapshot, image, or known reinstall sequence).”
   - Rollback:
     - “Reinstall removed packages and restore configuration from backup if possible.”
   - Credits:
     - If there is a robust snapshot/rollback mechanism (e.g. filesystem snapshot) → −3 points.
     - If only manual reinstall path is available → −1 or −2 points.

4. `firewall` steps:
   - Mitigation:
     - “Use a mechanism that auto-reverts rules if connectivity is lost or on timeout.”
     - “Explicitly whitelist management IPs and SSH port before tightening policies.”
   - Rollback:
     - “Restore previously saved ruleset or reset to known safe policy.”
   - Credits:
     - Auto-revert or snapshot rollback → −4 points.
     - Manual rollback plan → −1 or −2 points.

5. `validate` steps:
   - Mitigation:
     - These are themselves mitigations; good `validate` checks reduce the effective risk of related steps.
     - Example: a validate check that confirms SSH login or HTTP health after apply.
   - Rollback:
     - Not directly applicable; but failed validation can trigger the rollback plan for preceding steps.
   - Credits:
     - Strong, targeted validation for a high-risk change → subtract 1–3 points from that step (or from the group of steps it covers).

### Final per-step score

- `final_score = max(raw_score + mitigation_credits, 0)`.
- Map to final level:
  - `0–4`   → low
  - `5–9`   → medium
  - `10–17` → high
  - `≥ 18`  → critical

Planner output shows both:

- Raw score (before mitigations).
- Mitigation credits.
- Final score + level.
- Mitigation and rollback description in plain English for the step.

---

## 8. Phase F – Run-level aggregation and reporting

### Aggregated metrics

From all steps with `change_kind != none`:

- `max_step_final_score` (maximum final score).
- `total_final_score` (sum of final scores).
- Counts by level:
  - `num_critical`, `num_high`, `num_medium`, `num_low`.

### Overall run risk level

Rules can be:

- If any step is final-level critical → overall at least “high”.
- If `max_step_final_score ≥ 18` or `total_final_score ≥ 40` → overall “high”.
- Else if `max_step_final_score ≥ 10` or `total_final_score ≥ 20` → overall “medium”.
- Else → overall “low”.

### Final report structure (human-readable)

1. Header:
   - Profile id, display name, version.
   - Target host.
   - Profile schema & min hardline version.

2. Validation summary:
   - Any warnings that did not block.
   - Errors if planning was aborted (in that case, no later sections).

3. Planned changes:
   - Table or list:
     - `STEP_ID`, `TYPE`, `CHANGE_KIND`, `SUMMARY`.

4. Per-step risk and mitigations:
   - For each step with changes:
     - `STEP_ID`
     - `TYPE`
     - `SEVERITY`, `RISK_CLASS`
     - `RAW_SCORE`
     - `MITIGATION_CREDITS`
     - `FINAL_SCORE`, `LEVEL`
     - Short mitigations list.
     - Short rollback plan.

5. Aggregated risk:
   - `OVERALL_LEVEL` with explanation:
     - Example: “Overall risk: HIGH because of firewall changes affecting SSH and critical service restarts.”
   - `max_step_final_score`, `total_final_score`.
   - Counts of critical / high / medium steps.

This design gives a complete behavioral spec for `hardline plan` using your current profile and action schemas, fully before any implementation details.

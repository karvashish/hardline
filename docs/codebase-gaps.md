# Codebase Gaps

Date: 2026-03-07

## Functional Gaps

1. `verify-profile` command is a stub and does not validate anything yet.
   - Reference: `internals/verify/verify.go`

2. `plan` output suggests a rollback command, but rollback is not implemented in CLI dispatch.
   - References: `internals/plan/plan.go`, `cmd/hardline/main.go`

3. Profile validation (`Affirm`) is hardcoded to read `base-secure-ubuntu-24.04-lts/profile.json` instead of validating the currently loaded profile.
   - Reference: `pkg/profile/validation.go`

4. `apply` performs version checks but does not run profile schema validation (`Affirm`), while `plan` does.
   - References: `internals/apply/apply.go`, `internals/plan/plan.go`

## Security Gaps

1. SSH host key verification is disabled (`ssh.InsecureIgnoreHostKey()`), which permits MITM risk.
   - Reference: `internals/connection/connection.go`

## Quality Gaps

1. No automated Go tests were found (`*_test.go` files are absent).
   - Scope: repository-wide

## Plan-Design Alignment Gaps (Additional)

1. `plan` does not expose a structured diff model (`change_kind`: `none/create/modify/delete/execute`) per step.
   - Design reference: `docs/plan-design.md` (Phase C).
   - Current code reference: `internals/plan/steps.go` (`StepPlan` lacks `change_kind` field).

2. Per-step numeric risk scoring and priority ordering are not implemented.
   - Design reference: `docs/plan-design.md` (Phase D).
   - Current code reference: `internals/plan/plan.go` (TODO for risk scores/priority).

3. Mitigation credits and per-step rollback strategy derivation are not implemented.
   - Design reference: `docs/plan-design.md` (Phase E).
   - Current code reference: `internals/plan/plan.go` (TODO for mitigations/rollback).

4. Run-level risk aggregation metrics and final justification are not implemented.
   - Design reference: `docs/plan-design.md` (Phase F).
   - Current code reference: `internals/plan/plan.go` (TODO for final run-level risk report).

5. Validation phase output is not structured as an issue list (`error` vs `warning` with location); current flow exits on first validation error.
   - Design reference: `docs/plan-design.md` (Phase A output requirements).
   - Current code reference: `internals/plan/plan.go` (direct `os.Exit(1)` on first failed check).

6. `plan` currently executes validate checks (`sshd -t`, `nft -c`), while design default says validate steps should not be executed in plan mode unless explicitly marked safe.
   - Design reference: `docs/plan-design.md` (Phase B, validate behavior).
   - Current code references: `internals/plan/steps.go`, `internals/inspector/inspector.go`.

## MVP-Prioritized Gap Order

Assumption used for prioritization:
- MVP is for the overall CLI purpose (`verify-profile`, `plan`, `apply`, `version`), not just `plan`.
- MVP must ensure: correct profile validation flow, safe plan semantics, and non-misleading CLI behavior for operators.
- Advanced risk analytics in `plan` are post-MVP.

### P0 - CLI MVP Blockers (Must Fix First)

1. `verify-profile` command is a stub and does not validate profiles.
   - Related gap above: Functional #1.
   - Reference: `internals/verify/verify.go`.

2. Profile validation (`Affirm`) is hardcoded to a fixed profile path instead of the loaded profile.
   - Related gap above: Functional #3.
   - Reference: `pkg/profile/validation.go`.

3. `apply` skips schema validation (`Affirm`) while `plan` runs it, causing inconsistent safety checks across CLI commands.
   - Related gap above: Functional #4.
   - References: `internals/apply/apply.go`, `internals/plan/plan.go`.

4. `plan` executes validate checks in plan mode, violating the stated read-only/no-change expectation.
   - Related gap above: Plan-Design Alignment #6.
   - References: `internals/plan/steps.go`, `internals/inspector/inspector.go`.

5. SSH host key verification is disabled (`InsecureIgnoreHostKey`), which is unsafe for a security-hardening CLI baseline.
   - Related gap above: Security #1.
   - Reference: `internals/connection/connection.go`.

### P1 - Important for First Usable Release

1. `plan` output suggests a rollback CLI command that is not implemented.
   - Related gap above: Functional #2.
   - References: `internals/plan/plan.go`, `cmd/hardline/main.go`.

2. Validation phase output in `plan` is not structured as issue lists (`error` vs `warning` with location), reducing operator clarity.
   - Related gap above: Plan-Design Alignment #5.
   - Reference: `internals/plan/plan.go`.

3. No automated tests currently exist.
   - Related gap above: Quality #1.
   - Scope: repository-wide.

### P2 - Post-MVP Enhancements (Plan Depth)

1. `plan` lacks structured `change_kind` output per step (`none/create/modify/delete/execute`).
   - Related gap above: Plan-Design Alignment #1.
   - Reference: `internals/plan/steps.go`.

2. Per-step numeric risk scoring and priority ordering are not implemented.
   - Related gap above: Plan-Design Alignment #2.
   - Reference: `internals/plan/plan.go`.

3. Mitigation credits and per-step rollback strategy derivation are not implemented.
   - Related gap above: Plan-Design Alignment #3.
   - Reference: `internals/plan/plan.go`.

4. Run-level risk aggregation and final justification are not implemented.
   - Related gap above: Plan-Design Alignment #4.
   - Reference: `internals/plan/plan.go`.

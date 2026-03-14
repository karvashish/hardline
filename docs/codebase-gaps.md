# Vision Status

This document is the bridge between intent and implementation.

Use it to answer four questions quickly:

- What is the intended shape of Hardline?
- What is already implemented?
- What is only partial?
- What is implemented in a way that currently diverges from the intended direction?

The code references below point to the current implementation as of this repository state.

## Vision

From the current architecture, shipped profile format, and planner TODOs, the project vision is:

- Hardline should execute deterministic host-hardening profiles over SSH.
- Profiles should be explicit, signed, schema-validated, and easy to audit on disk.
- Planning should give operators a trustworthy preflight report before any mutation happens.
- Apply should capture enough rollback state to recover automatically from mid-run failure.
- Domain behavior should live inside concrete plugins rather than in a generic orchestration framework.

This is the intended mental model for the repository even where the implementation is not complete yet.

## Status Summary

Areas that are effectively solid today:

- profile loading and JSON schema validation
- plugin execution for packages, templates, services, firewall, and the shipped `firewall_template` plugin
- SSH host key checking through `known_hosts`
- signed profile integrity verification
- rollback journal persistence and reverse-order rollback replay
- repo-wide automated tests with coverage enforcement

Areas that are only partially realized:

- plan/reporting depth
- contributor-facing architectural documentation
- rollback semantics around partial and failed runs

Areas where current behavior diverges from the likely intended product shape:

- `verify-profile` verifies integrity only, not full profile validity
- `apply` reruns load/validation after a separate preflight `plan`
- unknown plugins are skipped with warning during apply instead of being a hard failure

## Status By Area

### Profile Format

Vision:

- Profiles are directory-based, ordered, explicit, and machine-validated.

Implemented:

- [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go) loads `profile.json`, resolves ordered action files, and restricts template loading to declared template paths.
- [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go) validates `profile.json` and each action file against generated JSON schemas.
- [`cmd/genschema/genschema.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/genschema/genschema.go) generates the schemas from Go types.

Assessment:

- Implemented well enough for current use.

### Signing And Integrity

Vision:

- Profiles are signed artifacts, and operators can verify they were not tampered with before use.

Implemented:

- [`cmd/profiletool/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main.go) can generate Ed25519 keys and sign a profile directory.
- [`internals/verify/integrity.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/integrity.go) verifies the manifest signature and every regular file hash in the profile directory.

Missing:

- `verify-profile` does not also load the profile, run schema validation, or confirm plugin-level validity.

Divergence:

- The CLI name suggests broader validation than the implementation actually performs.

Assessment:

- Implemented, but named more broadly than its behavior.

### Planning

Vision:

- `plan` should be a strong operator preflight: validate the profile, inspect remote state, and explain what `apply` would do with useful risk framing.

Implemented:

- [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go) loads the profile, performs version/schema checks, connects to the target host, runs plugin planners, and prints a report.
- [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go) models per-step plan output as summary plus details.
- Built-in plugins already provide practical planner output:
  - `packages` previews apt changes
  - `template` compares mode and content
  - `service` reports current and desired state
  - `firewall` checks nftables assumptions and managed file state
  - `firewall_template` provides best-effort template-based planning

Missing:

- no machine-readable plan output
- no structured change model
- no scoring/prioritization engine
- no explicit run-level mitigation model

Assessment:

- Implemented enough to be useful, but still materially short of the implied “operator-grade planner” vision.

### Apply

Vision:

- `apply` should be the mutation path, guarded by the same validations as `plan`, with rollback capture around each step.

Implemented:

- [`cmd/hardline/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/hardline/main.go) forces `apply` to execute preflight `plan` first.
- [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go) reconnects, revalidates, captures rollback state, applies steps in order, and triggers automatic rollback on failure.

Divergence:

- The flow is safe but redundant: `apply` does a full `plan` and then repeats much of the same validation and connection work.

Assessment:

- Implemented correctly from a safety perspective, but not yet elegant.

### Rollback

Vision:

- Rollback should restore previously captured state for managed changes with predictable ordering and clear scope.

Implemented:

- [`internals/rollback/journal.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go) persists host-scoped journals under `.hardline/runs` by default.
- [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go) replays rollback records in reverse order.
- Current rollback object types cover files, services, packages, and validation markers.
- [`internals/plugins/rollbackutil/capture.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/rollbackutil/capture.go) constrains managed file rollback to normalized `/etc/99-hardline*` destinations with specific extensions.

Missing:

- there is no broader history browser or rollback target selection beyond `last`
- journals are only persisted for successful applies

Assessment:

- Implemented and useful, but operationally narrow.

### Plugin Model

Vision:

- Plugins should own their own domain logic for plan, apply, and rollback, while the core stays orchestration-focused.

Implemented:

- [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go) defines the plugin contract and registry.
- [`internals/registry/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/registry/registry.go) assembles the built-in plugin table.
- [`pluginprojects/firewalltemplate/export.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/export.go) exports the shipped external `firewall_template` plugin.
- Each shipped plugin validates its own config before plan/apply/rollback capture.

Divergence:

- [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go) treats unknown plugins as warnings and skips them.

Assessment:

- The core plugin shape is right.
- Unknown-plugin handling is not where it should be.

### Platform Assumptions

Vision:

- Hardline should have explicit platform assumptions rather than accidental ones.

Implemented:

- The shipped profile and plugin set clearly target Ubuntu-like systems with:
  - `apt-get`
  - `systemd`
  - `nftables`
  - SSH key auth
  - passwordless `sudo`

Where this lives in code:

- [`internals/plugins/packages/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go)
- [`internals/plugins/service/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go)
- [`internals/plugins/firewall/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go)
- [`internals/connection/connection.go`](/home/kartikeya_vashishtha/hardline-try2/internals/connection/connection.go)

Missing:

- these platform constraints are visible in code, but not enforced as a single explicit compatibility layer yet

Assessment:

- Implemented by assumption rather than by a formal platform contract.

## Call It Perfect?

Not yet.

The repository already has a coherent spine:

- explicit profile format
- concrete plugin ownership
- signed profile artifacts
- preflight planning
- rollback capture
- strong automated test coverage

But “perfect” would require at least:

- a cleaner contract for `verify-profile`
- harder failure behavior for unknown plugins
- a clearer plan/reporting model
- contributor docs that explain the plugin contract and architectural boundaries directly

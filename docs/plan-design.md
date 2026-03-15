# Plan Design

This page documents the current planning model in `internals/plan`, what it is missing, and the concrete work required to make it a durable typed execution plan.

## Assessment

Today Hardline has a strong structured dry-run, not yet a fully typed execution plan.

What already exists:

- `plan` validates the profile, connects to the target host, runs plugin `Plan` for each step, renders terminal output, and can write JSON, YAML, or Markdown artifacts.
- Each step already has a stable internal shape in `internals/plan.StepPlan`:
  - `StepID`
  - `StepType`
  - `Severity`
  - `RiskClass`
  - `Noop`
  - `Summary`
  - `Details`
  - `Diff`
  - `OperatorSummary`
  - `Highlights`
- Deterministic plugins such as `template`, `service`, and `firewall` already produce useful human-readable diffs.
- The report pipeline in `internals/plan/report.go` already produces machine-readable artifacts that operators can use.

What is still missing:

- no typed before/after change model
- no first-class action kinds such as `create`, `update`, `delete`, or `replace`
- no stable object addresses beyond step IDs
- no explicit unknown/computed value model
- no dependency or causal graph
- no saved plan artifact that `apply` can consume
- uneven plugin fidelity
- risk is still mostly profile metadata plus simple aggregation, not computed execution analysis

Hardline is already useful for humans, but it is not yet a durable execution contract.

## Current State

The current `plan` flow is:

1. parse CLI flags
2. load plugins
3. load the profile
4. validate version and schema compatibility
5. validate the profile and action files
6. ensure required plugins exist
7. connect to the remote host
8. run plugin `Plan` for each step
9. render terminal output
10. optionally write a JSON, YAML, or Markdown artifact

`apply` does not consume a saved plan. In `cmd/hardline/main.go`, `apply` first runs `plan`, then runs `apply`.

The current step disposition model is simple:

- `already aligned`
  - `Noop == 0`
  - no normalized highlights
- `change planned`
  - `Noop != 0`
  - no normalized highlights
- `needs attention`
  - any normalized highlight is present

The current file artifact contains:

- `kind`
- `profile`
- `target`
- `summary`
- `changes_planned`
- `needs_attention`
- `steps`
- `next_steps`

That is enough to render a good operator report, but not enough to behave like a stable plan contract.

## Why It Is Not There Yet

Hardline needs to be built around typed changes. Today it is still built around text.

Current Hardline output is mostly:

- `summary`
- `details`
- `diff`
- `operator_summary`
- `highlights`

Those fields are valuable, but they are presentation fields. They are not a durable execution model.

Examples from the current code:

- `pkg/pluginapi.PlanResult` only carries strings and `Noop`.
- `internals/plan/report.go` writes text-heavy step objects and summary rollups.
- `internals/plugins/packages.Plan` depends on package-manager preview output, so the plan model needs to represent solver-backed predictions with explicit fidelity instead of implying exactness.
- the external `pluginprojects/firewalltemplate.Plan` explicitly marks its diff as template-driven and best-effort, while the built-in `internals/plugins/firewall.Plan` is the deterministic default path for nftables state.
- `internals/plan/plan.go` still has TODOs for richer risk scoring, mitigations, and final run-level analysis.

## Target Contract

Hardline plan should eventually produce one consistent model for both humans and machines.

Each planned change should have:

- a stable address
- an object kind
- an action kind
- a `before` object
- an `after` object
- an `unknown` section for values that cannot be predicted
- a fidelity marker
- a human summary
- optional evidence or warnings

The action kind set should be explicit:

- `no_op`
- `create`
- `update`
- `delete`
- `replace`
- `restart`
- `reload`

The fidelity set should also be explicit:

- `exact`
- `best_effort`
- `unknown`

The terminal renderers and file artifacts should both derive from that same typed model.

## Explicit Plan

### Phase 1: Add a typed change model at the plugin boundary

Files to change first:

- `pkg/pluginapi/registry.go`
- `internals/plan/steps.go`

Work:

1. Add typed change structs to `pkg/pluginapi`, not to a renderer-only package.
2. Extend `pluginapi.PlanResult` with a machine-readable `Changes` field.
3. Keep the existing text fields during migration so the current CLI output does not regress.
4. Add fidelity and action enums instead of raw freeform strings.

Exit criteria:

- every plugin can return both human text and typed changes
- `StepPlan` can carry typed changes without losing the current fields

### Phase 2: Upgrade the plan artifact schema

Files to change:

- `internals/plan/report.go`
- `internals/plan/plan.go`

Work:

1. Add typed `changes` to each step in the file artifact.
2. Add an artifact `schema_version` so future changes are explicit.
3. Derive `status`, `changes_planned`, and `needs_attention` from typed changes plus fidelity, not only from `Noop` and `Highlights`.
4. Keep Markdown readable, but make JSON and YAML the canonical structured outputs.

Exit criteria:

- JSON and YAML artifacts expose typed changes
- terminal output still looks good
- current report flags still work

### Phase 3: Migrate deterministic plugins first

Files to change first:

- `internals/plugins/template/execution.go`
- `internals/plugins/service/execution.go`
- `internals/plugins/firewall/execution.go`

Reason for this order:

- these plugins already know enough to emit real before/after state
- they cover most of the visible behavior in the base profile

Work:

1. `template` should emit file address, action kind, before metadata, after metadata, and content hash changes.
2. `service` should emit enablement and activity transitions as typed state, not only text.
3. `firewall` should emit file changes and runtime table changes separately if both are known.

Exit criteria:

- the base profile plan contains typed changes for the deterministic steps
- the JSON artifact can describe those steps without parsing human text

### Phase 4: Represent uncertainty honestly for preview-based plugins

Files to change:

- `internals/plugins/packages/execution.go`
- `pluginprojects/firewalltemplate/execution.go`

Work:

1. Represent solver-backed package predictions with explicit fidelity metadata when they come from package-manager preview output.
2. Represent dependency installs, upgrades, and autoremove sets as predicted changes with uncertainty markers.
3. Preserve the boundary between deterministic built-ins and less-deterministic external plugins by keeping `firewall_template` explicitly marked as `best_effort` in the typed model.
4. Include explicit reasons for uncertainty in the artifact.

Exit criteria:

- no plugin pretends it has exact knowledge when it does not
- uncertainty is machine-readable

### Phase 5: Introduce stable object addressing

Files to change:

- `pkg/pluginapi/...`
- `internals/plan/...`
- plugin implementations that emit typed changes

Work:

1. Define address formats such as:
   - `file:/etc/ssh/sshd_config`
   - `service:ssh`
   - `package:fail2ban`
   - `firewall:nftables:/etc/nftables.d/99-hardline.nft`
2. Use those addresses consistently across plan, apply journals, and rollback data where possible.
3. Stop relying on step ID alone when reporting what changed.

Exit criteria:

- the same object can be recognized across multiple plans
- plan diffs are object-centric, not only step-centric

### Phase 6: Add plan/apply consistency

Files likely involved:

- `cmd/hardline/main.go`
- `internals/plan/...`
- `internals/apply/...`

Work:

1. Add a saved plan artifact format that `apply` can consume.
2. Keep the current preflight behavior initially, but add an explicit mode to apply a previously generated plan.
3. Validate that the saved plan still matches the target host before executing it.
4. Record in the apply journal whether the run used a live plan or a saved plan.

Exit criteria:

- `apply` can consume a saved plan
- the user can tell whether execution exactly matched a reviewed artifact

### Phase 7: Add causal and dependency context only after typed changes exist

Work:

1. Add optional `depends_on` or causal references between step changes.
2. Record why a step is changing when another step caused it.
3. Keep this narrow. Do not build a generic orchestration framework.

Exit criteria:

- the artifact can explain step ordering and blast radius
- dependency data stays explicit and local, not abstracted into a new framework

## Sequence Rules

The work should happen in this order:

1. typed change model
2. artifact schema
3. deterministic plugins
4. uncertainty model
5. stable addressing
6. saved plan/apply contract
7. causal metadata

Do not start with dependency graphs or saved-plan execution before the typed change model exists. That would add complexity on top of text output instead of replacing the real limitation.

## What Done Looks Like

The goal is not to clone another tool's UX. The goal is to give Hardline a precise, reviewable, machine-readable plan contract.

This work is complete when:

- every plugin emits typed changes
- exact and best-effort plans are clearly distinguished
- JSON and YAML artifacts are stable machine-readable contracts
- `apply` can consume a reviewed plan artifact
- operators can answer "what will change, why, and how certain is that?" without reading freeform diff text

Until those are true, Hardline should describe its plan honestly as a structured dry-run rather than a typed execution contract.

# Product Direction

This page describes the intended operator-facing shape of Hardline and points to the files that currently implement each part.

Use this together with [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md):

- this file says what the product should feel like
- `codebase-gaps.md` says where the code is still short or divergent

## Desired Operator Experience

The intended workflow is:

1. verify a shipped or reviewed profile artifact
2. inspect what it would do on a host
3. apply it with rollback protection
4. recover the last successful run if needed

Current implementing files:

- verify: [`internals/verify/verify.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/verify.go)
- plan: [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go)
- apply: [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go)
- rollback: [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go)

## Desired Product Properties

Hardline should be:

- deterministic
- explicit on disk
- safe to inspect before mutation
- rollback-aware
- plugin-owned at the domain layer

The main files that express those properties today are:

- deterministic profile structure: [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go)
- schema validation: [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go)
- plugin boundary: [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)
- rollback journal model: [`internals/rollback/journal.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go)

## Desired `plan`

`plan` should be an operator-grade preflight.

That means:

- validate local profile inputs
- inspect remote state
- explain what each step intends to change
- expose risk clearly enough that an operator can decide whether to proceed

Relevant files:

- orchestration: [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go)
- per-step planning: [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go)
- planner runtime: [`internals/runtime/runtime.go`](/home/kartikeya_vashishtha/hardline-try2/internals/runtime/runtime.go)
- plugin planners:
  - [`internals/plugins/packages/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go)
  - [`internals/plugins/template/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go)
  - [`internals/plugins/service/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go)
  - [`internals/plugins/firewall/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go)
  - [`internals/plugins/firewalltemplate/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/execution.go)

## Desired `apply`

`apply` should be the only mutation path and should never be blind.

That means:

- a preflight pass runs before mutation
- each step is validated before execution
- rollback state is captured before mutation for managed resources
- failures trigger automatic rollback where possible

Relevant files:

- apply orchestration: [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go)
- apply step dispatch: [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go)
- rollback capture helpers: [`internals/plugins/rollbackutil/capture.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/rollbackutil/capture.go)

## Desired `rollback`

Rollback should restore managed state in reverse order with bounded scope.

Relevant files:

- journal model: [`internals/rollback/journal.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go)
- rollback engine: [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go)

## Desired Verification Story

Verification should let a user trust both the artifact and the profile structure.

Current relevant files:

- integrity verification: [`internals/verify/integrity.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/integrity.go)
- signing tool: [`cmd/profiletool/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main.go)
- schema validation: [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go)

This is one of the areas where the implementation is not fully at the product shape yet. The exact gap is tracked in [`docs/codebase-gaps.md`](/home/kartikeya_vashishtha/hardline-try2/docs/codebase-gaps.md).

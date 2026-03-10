# Cleanup Refactor Plan

This document captures the breaking-change cleanup plan for the current architecture issues.

## Goals

- Remove plugin-aware shared abstractions.
- Keep runtime and SSH access generic.
- Move domain behavior into the owning plugins.
- Reduce hidden orchestration rules and heuristics.
- Keep the code aligned with [Contributing.md](/home/kartikeya_vashishtha/hardline-try2/Contributing.md).

## Standing Implementation Constraints

- Prefer minimal abstraction.
- Avoid compatibility shims unless they are required to finish the same branch safely.
- Run `make test` after all changes.
- Maintain at least 90% coverage for the affected work.

## Target Architecture

### 1. Host Runtime Layer

Owns only generic remote/runtime capabilities:

- run command
- run command with output
- stat file
- read file
- write file
- open SFTP or equivalent remote file transport

This layer must not know about packages, services, SSH config policy, or firewall policy.

### 2. Plugin Layer

Each plugin owns:

- config decoding
- validation
- planning
- apply behavior
- rollback capture
- rollback restore behavior

No generic plugin-aware inspector should remain.

### 3. Orchestration Layer

Owns only:

- CLI flow
- profile loading
- registry construction
- step ordering
- report aggregation

It must not know service names, path-to-service heuristics, or firewall/package semantics.

### 4. Rollback Layer

Owns replay and dispatch only.

Domain-specific restore logic belongs to the plugin that created the record.

## Cleanup Phases

### Phase 1. Replace Shared Runtime Boundaries

- Remove the current plugin-aware inspector model.
- Replace it with a minimal generic host/runtime interface.
- Remove plugin-specific inspection methods from `pluginapi` contexts.
- Make `plan` and `apply` build their own runtime contexts independently.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/inspector/inspector.go`
- `/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plan/actions_registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/apply/actions_registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/remote/exec.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/remote/fs.go`

### Phase 2. Split Plan and Apply Registry Composition

- Stop aliasing the plan registry to apply registry state.
- Use shared plugin factories if useful, but construct plan/apply registries independently.
- Remove adapter layers that only exist because of the old inspector design.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/plan/actions_registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/apply/actions_registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go`

### Phase 3. Make Template Generic Again

- Remove SSH/firewall-specific validation and notes from `template`.
- Delete path-based service inference.
- Keep template focused on render, compare, and write behavior only.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/handlers.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution_test.go`

### Phase 4. Move Domain Inspection Into Plugins

- Packages plugin owns apt/dpkg inspection.
- Service plugin owns `systemctl` inspection.
- Firewall plugins own nftables inspection and parsing.
- Delete remaining shared domain-aware inspection helpers.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/execution.go`

### Phase 5. Remove Hidden Dirty-Service Coordination

- Delete shared `MarkServiceDirty`, `IsServiceDirty`, and `ClearServiceDirty`.
- Replace them with explicit service-impact metadata or explicit plugin outputs.
- Do not infer restart behavior from file paths.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/apply/actions_registry.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/execution.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go`

### Phase 6. Simplify Plugin Internal Flow

- Collapse split wrapper orchestration where handlers call separate validate/apply or validate/plan functions.
- Keep handler files thin.
- Keep validation strategy explicit and local to each plugin.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/handlers.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/handlers.go`
- matching handler files for other plugins

### Phase 7. Move Rollback Ownership to Plugins

- Core rollback becomes dispatch and replay only.
- Plugin packages own restoration semantics for their records.
- Core rollback must stop embedding package/service restore logic directly.

Primary files:

- `/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go`
- `/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go`
- plugin rollback implementations under `/home/kartikeya_vashishtha/hardline-try2/internals/plugins/`

## Fixed Decisions

- Backward compatibility is not a goal for this cleanup.
- Minimal abstraction is preferred over reusable frameworks.
- Template remains a generic file plugin.
- Validation should be explicit and plugin-owned.
- Plan and apply registries must be separate.
- Hidden dirty-service state must be removed.
- Rollback semantics must move out of the core engine.

## Validation Gates

Each implementation phase should be considered incomplete unless all of the following are true:

- `make test` passes.
- Coverage for the affected work remains at or above 90%.
- The change follows the rules in `Contributing.md`.
- Old abstractions introduced only for compatibility are removed before the phase is declared done.

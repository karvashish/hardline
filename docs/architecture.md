# Architecture

This page is the fastest route from a concept to the files that implement it.

## Top-Level Shape

The repository is split into four main layers:

- `cmd/`
  Binary entry points.
- `internals/`
  Runtime orchestration, SSH/remote helpers, built-in plugins, and command implementations.
- `pkg/`
  Reusable domain packages such as profile loading, plugin contracts, and logging.
- profile directories such as [`base-secure-ubuntu-24.04-lts`](/home/kartikeya_vashishtha/hardline-try2/base-secure-ubuntu-24.04-lts)
  Declarative hardening content shipped with the repo.

## Main Execution Path

Start here for the CLI flow:

- [`cmd/hardline/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/hardline/main.go)

What it dispatches:

- `plan` -> [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go)
- `apply` -> [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go)
- `rollback` -> [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go)
- `verify-profile` -> [`internals/verify/verify.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/verify.go)

CLI parsing and version helpers live in:

- [`internals/cli/cli.go`](/home/kartikeya_vashishtha/hardline-try2/internals/cli/cli.go)
- [`internals/cli/version.go`](/home/kartikeya_vashishtha/hardline-try2/internals/cli/version.go)

## Profile Flow

These files define how profile directories are loaded and validated:

- [`pkg/profile/profile.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile.go)
  Loads `profile.json`, action files, and declared templates.
- [`pkg/profile/validation.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation.go)
  Runs JSON-schema validation for `profile.json` and action files.
- [`schema/profile.schema.json`](/home/kartikeya_vashishtha/hardline-try2/schema/profile.schema.json)
- [`schema/action-file.schema.json`](/home/kartikeya_vashishtha/hardline-try2/schema/action-file.schema.json)
- [`cmd/genschema/genschema.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/genschema/genschema.go)
  Regenerates the schema files from Go types.

The shipped example profile is:

- [`base-secure-ubuntu-24.04-lts/profile.json`](/home/kartikeya_vashishtha/hardline-try2/base-secure-ubuntu-24.04-lts/profile.json)

## Orchestration Flow

Planning:

- [`internals/plan/plan.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/plan.go)
- [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go)
- [`internals/plan/context.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/context.go)

Apply:

- [`internals/apply/apply.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/apply.go)
- [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go)
- [`internals/apply/context.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/context.go)

Rollback:

- [`internals/rollback/journal.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/journal.go)
- [`internals/rollback/rollback.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback.go)

## Plugin System

The plugin contract is defined in:

- [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)

The command-independent shared registry owner lives in:

- [`internals/registry/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/registry/registry.go)

Built-in plugin assembly lives in:

- [`internals/plugins/builtin/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go)

External shared-object loading lives in:

- [`internals/plugins/loader.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/loader.go)

Built-in plugin implementations:

- packages: [`internals/plugins/packages/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/handlers.go), [`internals/plugins/packages/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go)
- template: [`internals/plugins/template/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/handlers.go), [`internals/plugins/template/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go)
- service: [`internals/plugins/service/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/handlers.go), [`internals/plugins/service/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go)
- firewall: [`internals/plugins/firewall/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/handlers.go), [`internals/plugins/firewall/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go)
- firewall_template: [`internals/plugins/firewalltemplate/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/handlers.go), [`internals/plugins/firewalltemplate/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/execution.go)

## SSH And Remote Mutation

Connection setup:

- [`internals/connection/connection.go`](/home/kartikeya_vashishtha/hardline-try2/internals/connection/connection.go)

Remote command execution:

- [`internals/remote/exec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/remote/exec.go)

Privileged file writes and reads:

- [`internals/remote/fs.go`](/home/kartikeya_vashishtha/hardline-try2/internals/remote/fs.go)

Planner runtime wrapper:

- [`internals/runtime/runtime.go`](/home/kartikeya_vashishtha/hardline-try2/internals/runtime/runtime.go)

## Verification And Signing

Integrity verification:

- [`internals/verify/verify.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/verify.go)
- [`internals/verify/integrity.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/integrity.go)

Profile signing and key generation:

- [`cmd/profiletool/main.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main.go)

## Tests

The highest-signal tests for behavior are:

- CLI dispatch: [`cmd/hardline/main_test.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/hardline/main_test.go)
- profile loading and validation: [`pkg/profile/profile_test.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/profile_test.go), [`pkg/profile/validation_test.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/profile/validation_test.go)
- orchestration: [`internals/plan/orchestration_test.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/orchestration_test.go), [`internals/apply/orchestration_test.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/orchestration_test.go)
- rollback: [`internals/rollback/rollback_test.go`](/home/kartikeya_vashishtha/hardline-try2/internals/rollback/rollback_test.go)
- verify/signing: [`internals/verify/integrity_test.go`](/home/kartikeya_vashishtha/hardline-try2/internals/verify/integrity_test.go), [`cmd/profiletool/main_test.go`](/home/kartikeya_vashishtha/hardline-try2/cmd/profiletool/main_test.go)

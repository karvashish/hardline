# Plugins

This page explains the plugin contract and points to the files that own plugin behavior.

## Contract

The core plugin API lives in:

- [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)

A plugin must provide:

- `Name`
- `Apply`
- `Plan`
- `Rollback`

Optional behavior flags:

- `InternalValidation`

Important contract types:

- `pluginapi.ApplyContext`
- `pluginapi.PlanContext`
- `pluginapi.RollbackContext`
- `pluginapi.PlanResult`
- `pluginapi.StepRecord`

## Ownership Boundary

The intended ownership split is:

- core orchestration decides when a step is planned, applied, or rolled back
- the plugin owns how its `config` is decoded, validated, planned, executed, and snapshotted for rollback

The current code follows that model closely.

Relevant files:

- apply orchestration: [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go)
- plan orchestration: [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go)

## Built-In Plugins

Built-in plugin registration is assembled in:

- [`internals/plugins/builtin/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/builtin/registry.go)

Current built-ins:

- `packages`
- `template`
- `service`
- `firewall`
- `firewall_template`

### `packages`

Relevant files:

- spec: [`internals/plugins/packages/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/spec.go)
- validation wiring: [`internals/plugins/packages/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/handlers.go)
- plan/apply/rollback capture: [`internals/plugins/packages/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go)

Behavior:

- plans and applies `apt-get update`
- previews and applies `apt-get upgrade`
- installs packages
- purges packages
- previews and applies `autoremove`

### `template`

Relevant files:

- spec: [`internals/plugins/template/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/spec.go)
- validation wiring: [`internals/plugins/template/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/handlers.go)
- plan/apply/rollback capture: [`internals/plugins/template/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go)

Behavior:

- loads template bytes from the profile directory
- writes the rendered bytes to a managed destination on the target host
- plans by comparing remote mode and file contents
- snapshots the destination file for rollback

### `service`

Relevant files:

- spec: [`internals/plugins/service/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/spec.go)
- validation wiring: [`internals/plugins/service/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/handlers.go)
- plan/apply/rollback capture: [`internals/plugins/service/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go)

Behavior:

- enables or disables services
- starts, stops, restarts, or reloads services
- snapshots current enabled/active state for rollback

### `firewall`

Relevant files:

- spec: [`internals/plugins/firewall/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/spec.go)
- validation wiring: [`internals/plugins/firewall/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/handlers.go)
- plan/apply/rollback capture: [`internals/plugins/firewall/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go)

Behavior:

- currently supports `nftables` only
- renders deterministic managed rules to a configured destination
- ensures `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`
- validates current nftables configuration during planning and apply
- snapshots the managed firewall file for rollback

### `firewall_template`

Relevant files:

- spec: [`internals/plugins/firewalltemplate/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/spec.go)
- validation wiring: [`internals/plugins/firewalltemplate/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/handlers.go)
- plan/apply/rollback capture: [`internals/plugins/firewalltemplate/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewalltemplate/execution.go)

Behavior:

- loads a template from the profile
- injects allow rules into the rendered nftables output
- writes to `/etc/nftables.d/99-hardline-firewall.nft` by default
- plans with a best-effort template-oriented report
- snapshots the managed file for rollback

## Validation Policy

Validation policy is enforced by:

- [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)

If `InternalValidation` is `false`, the step must opt in with `allow_unvalidated=true`.

All current built-in plugins set `InternalValidation=true`.

## External Plugins

External plugin loading lives in:

- [`internals/plugins/loader.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/loader.go)

Requirements:

- compiled as `.so`
- placed in `plugins/` next to the built binary
- export the symbol `HardlinePluginV1`
- provide a `*pluginapi.PluginBundle`

Current caveat:

- external plugin registration is routed through the apply-side registry path, while planning has its own default registry bootstrap

That caveat is important enough that any contributor touching external plugin behavior should also read:

- [`internals/apply/actions_registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/actions_registry.go)
- [`internals/plan/actions_registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/actions_registry.go)

# Plugins

This page explains the plugin contract and points to the files that own plugin behavior.

## Contract

The core plugin API lives in:

- [`pkg/pluginapi/registry.go`](/home/kartikeya_vashishtha/hardline-try2/pkg/pluginapi/registry.go)

The intended model is:

- host = hardware
- hardline core = kernel
- plugins = userspace

The kernel decides when a step is planned, applied, or rolled back. Plugins do not get direct transport wiring anymore; they receive a kernel-owned host ABI through `pluginapi.Host` and use that syscall surface to inspect or mutate the target host.

A plugin must provide:

- `Name`
- `Apply`
- `Plan`
- `Capture`

Optional behavior flags:

- `InternalValidation`

Important contract types:

- `pluginapi.ApplyContext`
- `pluginapi.PlanContext`
- `pluginapi.CaptureContext`
- `pluginapi.Host`
- `pluginapi.PlanResult`
- `pluginapi.StepRecord`

## Ownership Boundary

The intended ownership split is:

- core orchestration decides when a step is planned, applied, or rolled back
- the plugin owns how its `config` is decoded, validated, planned, executed, and snapshotted for rollback
- the kernel-owned `pluginapi.Host` surface is the only host ABI plugins should rely on for mutation

The current code follows that model closely.

Relevant files:

- apply orchestration: [`internals/apply/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/apply/steps.go)
- plan orchestration: [`internals/plan/steps.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plan/steps.go)

## Built-In Plugins

Built-in plugin registration is assembled in:

- [`internals/registry/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/registry/registry.go)

Current built-ins:

- `packages`
- `template`
- `service`
- `firewall`

### `packages`

Relevant files:

- spec: [`internals/plugins/packages/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/spec.go)
- validation wiring: [`internals/plugins/packages/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/handlers.go)
- plan/apply/capture: [`internals/plugins/packages/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/packages/execution.go)

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
- plan/apply/capture: [`internals/plugins/template/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/template/execution.go)

Behavior:

- loads template bytes from the profile directory
- writes the rendered bytes to a managed destination on the target host
- plans by comparing remote mode and file contents
- snapshots the destination file for rollback

### `service`

Relevant files:

- spec: [`internals/plugins/service/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/spec.go)
- validation wiring: [`internals/plugins/service/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/handlers.go)
- plan/apply/capture: [`internals/plugins/service/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/service/execution.go)

Behavior:

- enables or disables services
- starts, stops, restarts, or reloads services
- snapshots current enabled/active state for rollback

### `firewall`

Relevant files:

- spec: [`internals/plugins/firewall/spec.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/spec.go)
- validation wiring: [`internals/plugins/firewall/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/handlers.go)
- plan/apply/capture: [`internals/plugins/firewall/execution.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/firewall/execution.go)

Behavior:

- currently supports `nftables` only
- renders deterministic managed rules to a configured destination
- ensures `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`
- validates current nftables configuration during planning and apply
- snapshots the managed firewall file for rollback

## External Plugins

This repository currently ships one external Go plugin project:

- `firewall_template`

### `firewall_template`

Relevant files:

- export: [`pluginprojects/firewalltemplate/export.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/export.go)
- spec: [`pluginprojects/firewalltemplate/spec.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/spec.go)
- validation wiring: [`pluginprojects/firewalltemplate/handlers.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/handlers.go)
- plan/apply/capture: [`pluginprojects/firewalltemplate/execution.go`](/home/kartikeya_vashishtha/hardline-try2/pluginprojects/firewalltemplate/execution.go)

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

All shipped plugins currently set `InternalValidation=true`.

## External Plugins

External plugin loading lives in:

- [`internals/plugins/loader.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/loader.go)

Requirements:

- compiled as `.so`
- placed in `plugins/` next to the built binary
- export the symbol `HardlinePluginV1`
- provide a `*pluginapi.Plugin`
- consume host access through `pluginapi.Host` from the passed contexts, not by importing runtime transport wiring
- built with a C compiler available in `PATH` because plugin builds and plugin-loading binaries both require cgo-enabled linking

`make build` currently emits the shipped `firewall_template` plugin to `tmp/plugins/firewall_template.so`.

Relevant registry files:

- [`internals/registry/registry.go`](/home/kartikeya_vashishtha/hardline-try2/internals/registry/registry.go)
- [`internals/plugins/loader.go`](/home/kartikeya_vashishtha/hardline-try2/internals/plugins/loader.go)

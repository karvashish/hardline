# Testing

Unit and package tests live alongside the code:

- `internals/.../*_test.go`
- `pkg/.../*_test.go`
- `cmd/.../*_test.go`

Repo-wide tests:

```bash
go test ./...
```

The `Makefile` wraps that with coverage gates:

```bash
make test
```

`make test` also enforces the repo-wide and per-package coverage threshold from `MIN_COVERAGE`, which defaults to `90`.

Build-related targets that matter for docs and internals work:

- `make build`
- `make profiletool`
- `make genschema`
- `make sign-profile`
- `make sign-profiles`

Integration tests:

- shell harness in `integration-tests/`
- Terraform definitions in `integration-tests/terraform/`
- scenarios in `integration-tests/lib/scenarios/`

Those flows bring up a real Ubuntu 24.04 target on GCP, extract SSH connection details from Terraform outputs, and exercise plan/apply/rollback plus plugin behavior against a live host.

They assume GCP, `gcloud`, and Terraform are available. The Makefile wraps the lifecycle:

- `make itest-all` — the reliable one-shot: builds a fresh binary, provisions the VM, runs **every** scenario, and **always** tears the VM down afterward (even on scenario failure). This is the command to reach for; it exits with the scenario status and warns loudly if teardown ever fails so a billable VM is never left running.
- `make itest-gcp-up` / `make itest-gcp-down` — provision / destroy the VM on their own. `up` does not return until the host is actually usable (see the readiness wait below); pair with the granular runners while iterating.
- `make itest-scenario ITEST_SCENARIO=<name>` — run a single scenario against an already-up host (e.g. `ITEST_SCENARIO=file-meta-rollback`). `make itest-scenarios` runs them all; `make itest` runs just `smoke`. These call `itest-gcp-up` first but do **not** tear down, so the host stays up for the next iteration — remember to `make itest-gcp-down` when finished.

> Never invoke these with `make -n`. GNU make executes any recipe line containing `$(MAKE)` even in dry-run mode, so `make -n itest-all` would really provision and destroy the VM. Use `make --print-data-base -n` only on terraform-free targets.

**Readiness wait.** `terraform apply` returns as soon as the VM resource exists, but its startup script is still installing packages and cloud-init / unattended-upgrades may hold the apt/dpkg lock for another minute or more — running scenarios into that window fails with `apt/dpkg lock is held by another process`. `itest-gcp-up` therefore calls `integration-tests/wait-host-ready.sh`, which polls over SSH until `nft` is installed (startup finished) and no apt/dpkg lock is held, for several consecutive checks. Tunable via `ITEST_READY_TIMEOUT` (default 720s), `ITEST_READY_STABLE` (3), and `ITEST_READY_INTERVAL` (10s).

What the integration harness covers:

- CLI and verification flows such as `version`, `verify-profile`, the `vp` alias, and rejection of unsigned or tampered profiles
- planning behavior including report generation, read-only planning, idempotent follow-up plans, and diff-bearing plan output
- apply and rollback behavior on a live host, including rollback journals, conflict handling, keep-local-rollback, and concurrent-apply locking
- layered and multi-profile interactions, where one profile is rolled back without deleting another profile's managed state
- built-in plugin behavior for packages, services, firewall rules, and file metadata, plus external plugin loading through `firewall_template.so`
- package install/purge/rollback cases, service enable/start/reload/restart policies, and nftables render/load/rollback behavior
- file_meta cases covering mode/owner/group changes, immutable/append-only set and clear, lift→chmod→relock on an immutable target, directory-target stamping, idempotency, deterministic rollback, drift conflict detection, absent-target failure, and rejected paths
- safety and failure paths such as wrong-OS rejection, unreachable hosts, unknown plugins, managed-path enforcement, malformed profiles, missing templates, and version gates
- runtime override behavior including auto-discovery, explicit override-file precedence, signature invariants, invalid override rejection, and remote apply/plan cases with overrides

The source of truth for the current scenario set is `integration-tests/itest.sh`, which groups the suite into core CLI, rollback/journal, plugin, error-path, edge-case, and override sections.

## Good Places To Start Reading

If you are new to the codebase, this order works well:

1. `cmd/hardline/main.go`
2. `internals/cli/cli.go`
3. `internals/verify/verify.go`
4. `internals/plan/plan.go`
5. `internals/apply/apply.go`
6. `internals/rollback/rollback.go`
7. `pkg/pluginapi/registry.go`
8. one built-in plugin such as `internals/plugins/template/`

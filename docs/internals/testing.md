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

Two guard targets are worth knowing:

- `make check-schemas` regenerates `schema/` and fails if the result differs from what is committed. The schemas are embedded into the binary, so a stale commit ships stale validation rules.
- `make check-standalone` runs `scripts/check-standalone.sh`.

`make examples` regenerates the artifacts under `docs/examples/` against a throwaway host, using the same provision-and-teardown wrapper as `make itest-all`.

Integration tests:

- shell harness in `integration-tests/` (orchestrator `itest.sh`; helpers in `lib/`: `harness.sh`, `os.sh`, `fixtures.sh`, `runners.sh`)
- Terraform definitions in `integration-tests/terraform/`
- scenarios in `integration-tests/lib/suite/`

Those flows bring up a real target on GCP, extract SSH connection details from Terraform outputs, and exercise plan/apply/rollback plus plugin behavior against a live host.

**Target OS.** `ITEST_OS` selects the target and flows through to both Terraform and the suite: `ubuntu` (default, apt, the Ubuntu starter profile), `rocky` (dnf4, the Rocky starter profile), and `fedora` (dnf5 verification only, no starter profile). `integration-tests/lib/os.sh` holds every per-target fact the suite needs: the package query and install commands, the nftables main config, the sshd unit name, the starter profile and the state it should end up in. dnf targets are pinned to `e2-medium` because dnf needs more memory than apt to resolve a transaction, and the boot disk is floored at the source image's own size because the RHEL-family images are larger than Ubuntu's. Every profile a scenario applies is generated per target by `integration-tests/lib/fixtures.sh`, so the whole suite runs on every OS rather than skipping the parts a committed Ubuntu profile could not express. Where a behavior cannot be triggered the same way on both families the fixture varies the trigger, not the assertion: an apply is forced to fail by reloading sshd against an invalid drop-in on Debian, whose `ExecReload` runs `sshd -t`, and by restarting a unit that does not exist on RHEL, whose `ExecReload` is `kill -HUP $MAINPID` and would exit 0 while leaving the daemon dead.

They assume GCP, `gcloud`, and Terraform are available. The Makefile wraps the lifecycle:

- `make itest-all` — the reliable one-shot: builds a fresh binary, provisions the VM, runs **every** scenario, and **always** tears the VM down afterward (even on scenario failure). This is the command to reach for; it exits with the scenario status and warns loudly if teardown ever fails so a billable VM is never left running.
- `make itest-gcp-up` / `make itest-gcp-down` — provision / destroy the VM on their own. `up` does not return until the host is actually usable (see the readiness wait below); pair with the granular runners while iterating.
- `make itest-scenario ITEST_SCENARIO=<name>` — run a single scenario against an already-up host (e.g. `ITEST_SCENARIO=filemeta-rollback-conflict`). `make itest-scenarios` runs them all; `make itest` runs just the base-profile scenario (the `smoke` alias). These call `itest-gcp-up` first but do **not** tear down, so the host stays up for the next iteration — remember to `make itest-gcp-down` when finished.

> Never invoke these with `make -n`. GNU make executes any recipe line containing `$(MAKE)` even in dry-run mode, so `make -n itest-all` would really provision and destroy the VM. Use `make --print-data-base -n` only on terraform-free targets.

**Readiness wait.** `terraform apply` returns as soon as the VM resource exists, but its startup script is still installing packages and the distribution's own auto-update job may hold the package manager lock for another minute or more; running scenarios into that window fails with a lock-contention error. `itest-gcp-up` therefore calls `integration-tests/wait-host-ready.sh`, which polls over SSH until `nft` is installed (startup finished) and no package manager lock is held, for several consecutive checks. It passes only the lock files that exist on the host to `fuser`, so the same predicate covers apt and rpm/dnf targets. Tunable via `ITEST_READY_TIMEOUT` (default 720s), `ITEST_READY_STABLE` (3), and `ITEST_READY_INTERVAL` (10s).

What the integration harness covers:

- CLI and verification flows such as `version`, `verify-profile`, the `vp` alias, and rejection of unsigned or tampered profiles
- planning behavior including report generation, read-only planning, and diff-bearing plan output
- apply and rollback behavior on a live host, including rollback journals, conflict handling, keep-local-rollback, and idempotent re-apply proven by an unchanged on-host fingerprint
- layered and multi-profile interactions, where one profile is rolled back without deleting another profile's managed state
- built-in plugin behavior for packages, services, firewall rules, and file metadata, plus external plugin loading through `firewall_template.so`
- package install/purge/rollback cases, service enable/start/reload/restart policies, and nftables render/load/rollback behavior
- file_meta cases covering mode/owner/group changes, immutable/append-only set and clear, lift→chmod→relock on an immutable target, directory-target stamping, idempotency, deterministic rollback, drift conflict detection, absent-target failure, and rejected paths
- safety and failure paths such as wrong-OS rejection, unreachable hosts, unknown plugins, managed-path enforcement, malformed profiles, missing templates, and version gates
- runtime override behavior including auto-discovery, explicit override-file precedence, signature invariants, invalid override rejection, and remote apply/plan cases with overrides
- trust-boundary cases: command-injection guards on root-executed values, signed-bundle coverage, refusal of a profile edited after verification, and firewall include rollback

The source of truth for the current scenario set is the `SCENARIOS` list in `integration-tests/itest.sh`, which groups the suite into CLI/verification, base-profile, template, packages, firewall, service, file-meta, rollback, overrides, trust-boundary, and SSH-policy sections. A subset listed in `BOOTSTRAP_SET` needs the base profile applied first for the nftables include and base table; the `all` run bootstraps that by ordering `base-profile` first. Each scenario runs the real command and then verifies the resulting host state independently over SSH — file content/mode, `dpkg`/`rpm`, `nft list`, service MainPID/state-change and journal entries — rather than asserting on hardline's own log output.

## Demo Profile

`profiles/demo-profile/` is a five-step profile covering `file_meta`, `ssh`, `service`, and `firewall`. It deliberately omits `packages`, whose package manager work would dominate the runtime, so a full verify/plan/apply/rollback cycle against a host provisioned by `make itest-gcp-up` finishes in about a minute. It is signed with the same key as the starter profile and is included in `make sign-profiles`.

It backs the demo recording in the README and on the docs home page. The recording tooling lives outside this repo; the GIF it produces is committed at `docs/assets/demo.gif`.

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

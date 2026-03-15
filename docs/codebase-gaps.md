# Current Gaps and Limits

This page is intentionally based on current code, not roadmap guesses.

## Signature verification is not enforced by `plan` or `apply`

`verify-profile` checks:

- manifest integrity
- signature validity
- plugin availability

`plan` and `apply` only perform:

- schema validation
- plugin availability checks
- version gating

If you want signed-profile enforcement today, you must run `verify-profile` separately.

## `rollback` only supports `last`

The rollback CLI rejects any target other than:

```text
last
```

There is no code path for:

- rollback by run ID
- rollback by profile ID
- rollback from local-only journal state

## Package rollback is best-effort

The `packages` plugin captures rollback state in `best_effort` mode.

Notes recorded in code:

- `apt update` is not directly reversible
- `apt upgrade` rollback is best-effort
- `apt autoremove` rollback is best-effort

## Firewall backends are narrow

Current backend support:

- `firewall`: `nftables` only
- `firewall_template`: `nftables` only

Any other backend value is outside the supported path and is rejected by normal validation.

## Managed file rollback is restricted to `/etc`

File snapshot capture and restore only support managed destinations that:

- live under `/etc`
- start with `99-hardline`
- end in `.conf`, `.nft`, or `.rules`

That makes the rollback path intentionally narrow.

## OS metadata is informational

Profiles carry:

- `os.family`
- `os.version`
- `os.variant`

The current runtime uses those values in plan/report output, but it does not enforce host OS compatibility.

## Plan risk modeling is still shallow

`internals/plan/plan.go` still contains TODOs for:

- per-step risk scoring
- mitigation derivation
- richer rollback-strategy derivation
- fuller run-level aggregation

Today, plan output mostly reflects:

- profile-authored severity and risk metadata
- plugin-authored plan summaries and highlights

## Dynamic plugin loading is directory-based only

Shared-object plugins are loaded from `plugins/` next to the executable.

There is no code for:

- plugin version pinning
- plugin manifests
- signature verification of plugin binaries
- remote plugin distribution

## Integration test infrastructure is GCP-specific

The shipped live integration path is wired around:

- Terraform
- GCP
- `gcloud`

There is no parallel integration harness for other clouds or local virtualization in the tracked code.

## Remote rollback journal is single-slot

The remote journal path is fixed at:

```text
/var/lib/hardline/runs/last.json
```

That means the remote state currently tracks only the latest successful apply snapshot, not a history.

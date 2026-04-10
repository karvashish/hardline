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

Those flows assume GCP, `gcloud`, and Terraform are available. The Makefile wraps common lifecycle tasks such as `itest-gcp-up`, `itest`, and `itest-scenarios`.

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

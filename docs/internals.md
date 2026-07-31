# Hardline Internals

This page is the internals docs hub. The detailed write-up is split into smaller topic files and follows the current code layout.

## Start Here

- [Architecture](internals/architecture.md)
- [Data Models](internals/data-models.md)
- [Execution Flow](internals/execution-flow.md)
- [Planning And Reports](internals/planning-and-reports.md)
- [Plugin System](internals/plugin-system.md)
- [Remote Execution](internals/remote-execution.md)
- [Rollback](internals/rollback.md)
- [Safety And Trust](internals/safety-and-trust.md)
- [Testing](internals/testing.md)

## Suggested Reading Order

1. [Architecture](internals/architecture.md)
2. [Data Models](internals/data-models.md)
3. [Execution Flow](internals/execution-flow.md)
4. [Plugin System](internals/plugin-system.md)
5. [Rollback](internals/rollback.md)

If you want to see how Hardline is tested, jump to [Testing](internals/testing.md) early. It covers both the local/unit test surface and the Terraform-backed integration harness used against real Ubuntu 24.04 hosts.

## Related Files

- [`cmd/hardline/main.go`](https://github.com/karvashish/hardline/blob/main/cmd/hardline/main.go)
- [`cmd/profiletool/main.go`](https://github.com/karvashish/hardline/blob/main/cmd/profiletool/main.go)
- [`integration-tests/itest.sh`](https://github.com/karvashish/hardline/blob/main/integration-tests/itest.sh)
- [`integration-tests/terraform/main.tf`](https://github.com/karvashish/hardline/blob/main/integration-tests/terraform/main.tf)
- [`internals/plan/plan.go`](https://github.com/karvashish/hardline/blob/main/internals/plan/plan.go)
- [`pkg/profile/profile.go`](https://github.com/karvashish/hardline/blob/main/pkg/profile/profile.go)
- [`schema/profile.schema.json`](https://github.com/karvashish/hardline/blob/main/schema/profile.schema.json)
- [`schema/action-file.schema.json`](https://github.com/karvashish/hardline/blob/main/schema/action-file.schema.json)

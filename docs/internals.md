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

## Related Files

- [`cmd/hardline/main.go`](../cmd/hardline/main.go)
- [`cmd/profiletool/main.go`](../cmd/profiletool/main.go)
- [`internals/plan/plan.go`](../internals/plan/plan.go)
- [`pkg/profile/profile.go`](../pkg/profile/profile.go)
- [`schema/profile.schema.json`](../schema/profile.schema.json)
- [`schema/action-file.schema.json`](../schema/action-file.schema.json)

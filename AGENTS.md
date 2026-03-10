# Agent Instructions

These instructions apply to the entire repository.

## Standing Rules

- Prefer minimal abstraction. Do not introduce extra layers, generic frameworks, or indirection unless there is a concrete need.
- Follow [Contributing.md](/home/kartikeya_vashishtha/hardline-try2/Contributing.md) for all code changes.
- After completing changes, run `make test`.
- Maintain at least 90% test coverage for the affected work. If a change would drop effective coverage below that bar, add tests before considering the work complete.

## Refactor Expectations

- Keep ownership boundaries explicit.
- Shared infrastructure should stay generic and runtime-oriented.
- Domain logic should live with the owning plugin or feature, not in orchestration code.

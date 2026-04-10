# Contributing

Thanks for your interest. This project has very specific style rules.

## Code style

- No generics in business / domain logic.
- No “generic step executors”, “pipelines”, or meta-frameworks.
- No DRY for its own sake. Local duplication is acceptable and often preferred.
- Helpers are only allowed for:
  - SSH connection and command execution
  - File loading / saving
  - Logging / error wrapping
- If a refactor adds extra layers of indirection (interfaces, type parameters, registries)
  without a measurable, concrete benefit, it will be rejected.

## Optimization / refactor PRs

Optimization / refactor PRs must:

- Show a clear measurable benefit (benchmark, profile, or simpler code),
- And not reduce readability of the hot path.

“Cleaner,” “more generic,” “more flexible,” or “more DRY” without hard justification
are not accepted reasons for changes.

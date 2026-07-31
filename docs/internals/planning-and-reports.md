# Planning And Reports

Planning is more than a dry-run boolean. It is Hardline's main operator-facing preview surface.

## Planner Output

Each planned step is represented as a `StepPlan`, which wraps:

- the plugin's `PlanResult`
- the step ID
- the step type

The plugin result can describe:

- a summary
- explanatory details
- final-state diff lines
- whether the step expects to change state
- an operator summary
- highlights or warnings

## Terminal Rendering

`plan.Plan` supports two terminal render styles:

- compact output by default
- detailed output in debug mode

The compact view emphasizes:

- summary counts
- top-level planned changes
- top-level attention items

The detailed view includes per-step sections with summaries, status, details, and diff lines.

## Report Files

Plan artifacts can be written as:

- JSON
- YAML
- Markdown

Rules:

- `--report-format` requires `--report-file`
- if no format is passed, Hardline infers it from the filename extension (`.json`, `.yaml`, `.yml`, `.md`); any other extension is an error
- directories for report files are created automatically, at mode `0755`
- both rules are checked by `validatePlanOutputs` at the top of `plan.Plan`, before the SSH connection is opened, so a bad `--report-file` fails without touching the host

## What Goes Into A Report

The generated report includes:

- `kind`, currently always `hardline_plan`
- `profile`: ID, display name, and version
- `target`: host plus OS family and version, taken from the profile's `os` block rather than from the host
- `summary`: `steps_inspected`, `already_aligned`, `changes_planned`, `needs_attention`, and `rollback_available`
- `changes_planned` and `needs_attention`: top-level rollups, omitted when empty
- `steps`: per-step `id`, `type`, `status`, `summary`, `operator_summary`, `details`, `diff`, `highlights`, and `will_change`
- `next_steps`: suggested apply and rollback commands, reusing the original profile argument path and carrying `--overrides-file` through when one was passed

Each step is classified into one of three dispositions — `aligned`, `planned`, or `attention` — and the summary counts are derived from that classification.

## Apply And Reports

`apply` accepts report flags because the CLI runs the planner before `apply.Apply`.

That means:

- report generation still happens in the planning phase
- the file represents the pre-apply plan, not a post-apply execution report

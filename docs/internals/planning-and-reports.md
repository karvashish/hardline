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
- if no format is passed, Hardline infers it from the filename extension
- directories for report files are created automatically

## What Goes Into A Report

The generated report includes:

- profile ID, display name, and version
- target host plus OS family and version
- summary counts for aligned, planned, and attention states
- per-step `status`, `summary`, `operator_summary`, `details`, `diff`, `highlights`, and `will_change`
- suggested next-step commands for apply and rollback

## Apply And Reports

`apply` accepts report flags because the CLI runs the planner before `apply.Apply`.

That means:

- report generation still happens in the planning phase
- the file represents the pre-apply plan, not a post-apply execution report

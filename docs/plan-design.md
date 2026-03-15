# Plan Design

This page describes the current planning model implemented in `internals/plan`.

## What `plan` does today

The code path for `plan` is:

1. parse CLI flags
2. load plugins
3. load the profile
4. validate version and schema compatibility
5. validate the profile and action files
6. ensure required plugins exist
7. connect to the remote host
8. run plugin `Plan` for each step
9. render terminal output
10. optionally write a JSON, YAML, or Markdown artifact

## Step result model

Each planned step becomes a `StepPlan` with:

- `StepID`
- `StepType`
- `Severity`
- `RiskClass`
- `Noop`
- `Summary`
- `Details`
- `Diff`
- `OperatorSummary`
- `Highlights`

`Severity` and `RiskClass` come from the profile step itself, not from dynamic scoring logic.

## Dispositions

The plan code classifies a step into one of three states:

- `already aligned`
  - `Noop == 0`
  - no normalized highlights
- `change planned`
  - `Noop != 0`
  - no normalized highlights
- `needs attention`
  - any normalized highlight is present

That same status is written into file artifacts.

## Terminal output

Two terminal views exist:

- compact mode
  - default
  - high-level summary and planned changes
- detailed mode
  - enabled by `--debug` or `-d`
  - per-step details, diff, and highlights

## File artifacts

Artifacts are optional and are controlled by:

- `--report-file`
- `--report-format`

Supported formats:

- `json`
- `yaml`
- `md`

If `--report-format` is omitted, the format is inferred from the file extension:

- `.json`
- `.yaml`
- `.yml`
- `.md`
- `.markdown`

## Artifact structure

JSON and YAML artifacts contain:

- `kind`
- `profile`
- `target`
- `summary`
- `changes_planned`
- `needs_attention`
- `steps`
- `next_steps`

`kind` is always:

```text
hardline_plan
```

## Summary fields

The summary currently reports:

- steps inspected
- already aligned
- changes planned
- needs attention
- overall risk
- risk breakdown
- rollback available

`overall risk` is aggregated from step severities already present in the profile data and step plan results.

## Next-step commands

The plan artifact always includes suggested commands for:

- `apply`
- `rollback last`

These are constructed from the profile ID and target host.

## Current design boundaries in code

The `plan` package still contains explicit TODOs for:

- computing per-step risk scores
- deriving mitigations and rollback strategies
- aggregating a final run-level risk from richer logic

Today, plan output is mostly a structured presentation of:

- plugin-provided plan details
- profile-provided severity and risk metadata
- simple aggregation logic

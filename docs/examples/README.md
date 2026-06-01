# Example Run Artifacts

Real output from running the shipped [`starter-secure-ubuntu-24.04-lts`](../../starter-secure-ubuntu-24.04-lts/) profile against a fresh Ubuntu 24.04 LTS host, captured so you can see what Hardline produces without running it yourself.

The run followed the documented flow: `verify-profile`, then `plan`, then `apply` (23 steps), then `rollback`. Logs are the `--log-file` output (plain text, one timestamped line per entry).

Host, IP, and runner home paths are replaced with placeholders (`203.0.113.10`, `/home/user`).

## `starter-secure-ubuntu-24.04-lts/`

| Path | What it is |
| --- | --- |
| [`verify/verify.log`](starter-secure-ubuntu-24.04-lts/verify/verify.log) | `verify-profile` run: manifest, signature, schema, templates, and plugins checked locally. |
| [`plan/plan.log`](starter-secure-ubuntu-24.04-lts/plan/plan.log) | `plan` run: per-step inspection and the changes Hardline would make. |
| [`plan/report.json`](starter-secure-ubuntu-24.04-lts/plan/report.json) / [`.yaml`](starter-secure-ubuntu-24.04-lts/plan/report.yaml) / [`.md`](starter-secure-ubuntu-24.04-lts/plan/report.md) | The same plan report in all three `--report-format` outputs. |
| [`apply/apply.log`](starter-secure-ubuntu-24.04-lts/apply/apply.log) | `apply` run: each of the 23 steps executed against the host, with a summary. |
| [`rollback/rollback.log`](starter-secure-ubuntu-24.04-lts/rollback/rollback.log) | `rollback` run: the apply reversed from the journal. |
| [`journal/starter-secure-ubuntu-24.04-lts.json`](starter-secure-ubuntu-24.04-lts/journal/starter-secure-ubuntu-24.04-lts.json) | The rollback journal written by `apply`: per-step before/after snapshots. |

The report lives under `plan/` because `apply` re-emits the identical plan report (`kind: hardline_plan`); the structured record of what `apply` changed is the rollback journal.

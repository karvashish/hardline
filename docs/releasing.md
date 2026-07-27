# Releasing Hardline

Releases are cut via a pull request to `main`. There is no manual `git tag` step — the CI workflows handle tagging, building, and publishing once the release PR is merged.

## Cutting a release

1. Decide the next version (e.g. `0.1.2`).
2. Create a branch and a single commit that:
   - Updates `internals/cli/version.json`'s `version` field to the new value.
   - Adds `changelog/v<version>.md` with the release notes.
   - Updates the top-level `CHANGELOG.md` index to point at the new entry.
3. Open a PR with the title **`[release] version <version>`**, e.g. `[release] version 0.1.2`.
4. Wait for CI to go green, then rebase-merge. Squash merge is disabled on the repository so the squashed `(#N)` suffix never enters the release commit subject, which `tag-release.yml` parses.

That's it — the rest is automatic.

## What CI enforces

The [`Validate release PR shape`](../.github/workflows/validate-release-pr.yml) check is a required status check on `main`. It applies two rule sets depending on the PR title.

### Release PRs (title matches `^\[release\] version X.Y.Z(-prerelease)?$`)

- Exactly **one commit** (so the squash subject is unambiguous).
- Only modifies files matching the allow-list:
  - `internals/cli/version.json`
  - `CHANGELOG.md`
  - `changelog/*.md`
- Must touch all three of: `internals/cli/version.json`, `CHANGELOG.md`, and `changelog/v<version>.md`.
- `internals/cli/version.json`'s `version` field must equal the version in the title.
- The tag `v<version>` must not already exist on the remote.

### Non-release PRs (any other title)

- Must **not** modify `internals/cli/version.json`. The file is "locked" to release PRs to prevent drift.

## What happens after merge

The [`tag-release.yml`](../.github/workflows/tag-release.yml) workflow runs on every push to `main`. When the squashed commit subject starts with `[release] version `, it:

1. Re-verifies that `internals/cli/version.json` matches the version in the subject.
2. Creates the annotated tag `v<version>` and pushes it to `origin`.

Pushing the tag is the only trigger. [`release.yml`](../.github/workflows/release.yml) fires on its own `push.tags` because the tag is pushed with `RELEASE_TAG_PAT` — a user PAT, not `GITHUB_TOKEN`, so GitHub's anti-recursion rule does not apply. And it cannot apply: the "Release tags" ruleset rejects a `GITHUB_TOKEN` tag push outright, so any tag that lands at all was pushed by a bypass-capable PAT and does trigger the build.

`release.yml` also keeps a `workflow_dispatch` entry taking a tag as input. That is a manual escape hatch for re-running a build against an existing tag; it is not part of the automatic path. An earlier version of `tag-release.yml` invoked it on every release, which produced two concurrent builds racing to publish the same GitHub Release (seen on `v0.2.0-rc1`).

`release.yml` then runs unit tests, builds Linux (amd64/arm64) and Windows (amd64/arm64) binaries, packages the starter profile, and publishes a GitHub Release with all the artifacts attached and auto-generated release notes.

### Required secret: `RELEASE_TAG_PAT`

The "Release tags" ruleset blocks creation of `v*.*.*` tags by anyone without bypass. `GITHUB_TOKEN` (the default workflow identity) cannot be added as a bypass actor on personal repositories, so `tag-release.yml` checks out using a fine-grained PAT stored as the repo secret `RELEASE_TAG_PAT`. The PAT is owned by a maintainer with admin role, and that role's existing bypass on the ruleset is what allows the tag push to succeed.

To rotate or initially provision:

1. Generate a fine-grained PAT scoped to this repo only, with **Contents: Read and write**.
2. Store as the repository secret named `RELEASE_TAG_PAT` (Settings → Secrets and variables → Actions).
3. Default expiration is 1 year — rotate before then; an expired PAT will fail `tag-release.yml` with an authentication error on the next release.

## Why version.json instead of `git describe`

The version is embedded into the binary at compile time by `//go:embed`-ing `internals/cli/version.json` (see [`internals/cli/version.go`](../internals/cli/version.go)). Keeping the source of truth in a tracked file (gated by the release-PR workflow) means:

- Every commit on `main` has a single, honest version on disk.
- `go run ./cmd/hardline` and `go build` without any flags produce a correctly-versioned binary.
- The release pipeline does not need to mutate tracked files or pass `-ldflags` at build time.

The trade-off is the small amount of CI machinery above. The release-PR validator is what makes this trade-off safe — it prevents `version.json` from being changed except via a release PR whose title, contents, and target tag are all consistent.

## Pre-release versions

Pre-releases use a suffix on the patch component: `0.1.0-rc1`, `0.2.0-beta.2`, etc. The validator accepts any `-[a-zA-Z0-9.]+` suffix. `release.yml` marks the GitHub Release as a pre-release automatically whenever the tag contains `-`.

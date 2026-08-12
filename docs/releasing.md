# Releasing Hardline

Releases are cut via a pull request to `main`. There is no manual `git tag` step — the CI workflows handle tagging, building, and publishing once the release PR is merged.

## Cutting a release

1. Decide the next version (e.g. `0.1.2`).
2. Create a branch named `release/v<version>` and a single commit that:
   - Updates `internals/cli/version.json`'s `version` field to the new value.
   - Adds `changelog/v<version>.md` with the release notes.
   - Updates the top-level `CHANGELOG.md` index to point at the new entry.
3. Open a PR with the title **`[release] version <version>`**, e.g. `[release] version 0.1.2`.
4. Wait for CI to go green, then rebase-merge. Squash merge is disabled on the repository so the squashed `(#N)` suffix never enters the release commit subject, which `tag-release.yml` parses.

That's it — the rest is automatic.

## Release branches are permanent

`Delete branch on merge` is on for the repository, so a merged head branch is
normally removed. Release branches are the exception: the **Release branches**
ruleset denies `deletion` and `non_fast_forward` on `refs/heads/release/**` and
`refs/heads/release-*`, which both stops the automatic delete and stops a merged
release branch being rewritten afterwards.

They have to survive because the documentation site builds each published
version from its release branch. A deleted branch takes that version's docs off
the site.

The name has not been consistent historically — `release/v0.1.2`, `release/0.2.0`
and `release-0.2.0-rc1` all exist. The site accepts `release/v<version>` and
`release/<version>`; use the first form.

## Documentation site versions

[`pages.yml`](https://github.com/karvashish/hardline/blob/main/.github/workflows/pages.yml)
runs [`build-docs-site.sh`](https://github.com/karvashish/hardline/blob/main/.github/scripts/build-docs-site.sh),
which builds one copy of the site per version:

| Path | Built from |
| --- | --- |
| `/` | a redirect to `/latest/` |
| `/latest/` | the newest released version |
| `/<version>/` | that version's release branch |
| `/dev/` | `main` |

The site root serves the newest release, not `main`. Documentation for work
that has merged but not shipped lives at `/dev/` and is reachable from the
version selector in the header, so a reader never lands on instructions for a
binary they cannot download.

A release branch is published only when the tag `v<version>` exists, so an
abandoned release PR whose branch survives never reaches the site. Prereleases
are not published. A branch that predates the site (no `mkdocs.yml` in its tree)
is skipped with a notice rather than failing the build.

The build ignores each version's own `site_url` and version-selector settings,
supplying them through an overlay config that `INHERIT`s the version's
`mkdocs.yml`. Released trees are immutable, so a version whose config was
written before the selector existed still gets one.

The push trigger for the deploy job carries no paths filter. A release commit
touches `internals/cli/version.json` and the changelog and nothing else, and
that push is exactly what has to promote the new release branch onto the site.

## Shipped profile minimums

`min_hardline` in a shipped profile states the oldest release that can run it.
When a release adds a capability a shipped profile then depends on (a new plugin
name, a newly required config key), that profile's `min_hardline` has to move
with it. Otherwise the profile claims to work on releases that will reject it.

This cannot be done inside the release PR. The validator's allow-list is
`internals/cli/version.json`, `CHANGELOG.md` and `changelog/*.md`, so a release
PR that also edits a `profile.json`, or the `manifest.json` / `manifest.sig`
that re-signing regenerates, fails its shape check.

Do it in a separate PR immediately after the release lands: set `min_hardline`
to the version just released, re-sign the affected profiles, and merge. In the
window before that PR, a shipped profile understates its requirement. The
failure an operator hits on an older binary is still an early and clear one,
because `verify-profile` rejects an unregistered plugin offline, before any
connection is made.

**Outstanding:** the starter profiles still carry `min_hardline: "0.0.1"`, which
predates the per-package-manager plugins, the profile-declared nftables main
config, the verbatim service unit names, and the audit plugin. Set both starters
to the first release that contains them.

## What CI enforces

The [`Validate release PR shape`](https://github.com/karvashish/hardline/blob/main/.github/workflows/validate-release-pr.yml) check is a required status check on `main`. It applies two rule sets depending on the PR title.

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

The [`tag-release.yml`](https://github.com/karvashish/hardline/blob/main/.github/workflows/tag-release.yml) workflow runs on every push to `main`. When the squashed commit subject starts with `[release] version `, it:

1. Re-verifies that `internals/cli/version.json` matches the version in the subject.
2. Creates the annotated tag `v<version>` and pushes it to `origin`.

Pushing the tag is the only trigger. [`release.yml`](https://github.com/karvashish/hardline/blob/main/.github/workflows/release.yml) fires on its own `push.tags` because the tag is pushed with `RELEASE_TAG_PAT` — a user PAT, not `GITHUB_TOKEN`, so GitHub's anti-recursion rule does not apply. And it cannot apply: the "Release tags" ruleset rejects a `GITHUB_TOKEN` tag push outright, so any tag that lands at all was pushed by a bypass-capable PAT and does trigger the build.

`release.yml` also keeps a `workflow_dispatch` entry taking a tag as input. That is a manual escape hatch for re-running a build against an existing tag; it is not part of the automatic path. An earlier version of `tag-release.yml` invoked it on every release, which produced two concurrent builds racing to publish the same GitHub Release (seen on `v0.2.0-rc1`).

`release.yml` then runs unit tests, builds Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64/arm64) binaries, packages the starter profile, and publishes a GitHub Release with all the artifacts attached and auto-generated release notes. Seven archives in total, each with a companion `.sha256`.

macOS `amd64` has no Intel runner, so it is built on Apple Silicon under Rosetta with an x86_64 Go toolchain — a native-amd64 environment rather than a cross build, so the cgo plugin links cleanly. Each Unix archive is checked with `file` against an expected architecture token before it is staged, so a silently mis-targeted build fails the job.

### Required secret: `RELEASE_TAG_PAT`

The "Release tags" ruleset blocks creation of `v*.*.*` tags by anyone without bypass. `GITHUB_TOKEN` (the default workflow identity) cannot be added as a bypass actor on personal repositories, so `tag-release.yml` checks out using a fine-grained PAT stored as the repo secret `RELEASE_TAG_PAT`. The PAT is owned by a maintainer with admin role, and that role's existing bypass on the ruleset is what allows the tag push to succeed.

To rotate or initially provision:

1. Generate a fine-grained PAT scoped to this repo only, with **Contents: Read and write**.
2. Store as the repository secret named `RELEASE_TAG_PAT` (Settings → Secrets and variables → Actions).
3. Default expiration is 1 year — rotate before then; an expired PAT will fail `tag-release.yml` with an authentication error on the next release.

## Why version.json instead of `git describe`

The version is embedded into the binary at compile time by `//go:embed`-ing `internals/cli/version.json` (see [`internals/cli/version.go`](https://github.com/karvashish/hardline/blob/main/internals/cli/version.go)). Keeping the source of truth in a tracked file (gated by the release-PR workflow) means:

- Every commit on `main` has a single, honest version on disk.
- `go run ./cmd/hardline` and `go build` without any flags produce a correctly-versioned binary.
- The release pipeline does not need to mutate tracked files or pass `-ldflags` at build time.

The trade-off is the small amount of CI machinery above. The release-PR validator is what makes this trade-off safe — it prevents `version.json` from being changed except via a release PR whose title, contents, and target tag are all consistent.

## Pre-release versions

Pre-releases use a suffix on the patch component: `0.1.0-rc1`, `0.2.0-beta.2`, etc. The validator's full title pattern is `^\[release\] version ([0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$`. `release.yml` marks the GitHub Release as a pre-release automatically whenever the tag contains `-`.

A prerelease suffix is ignored when a profile's `min_hardline` is checked, so an `-rc` build satisfies the same minimum as its final release.

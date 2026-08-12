#!/usr/bin/env bash
# =============================================================================
# build-docs-site.sh - build the versioned documentation site into ./site
# =============================================================================
# Each released version is built from its own release branch, so what the site
# serves by default is what shipped rather than what is on main. The current
# checkout is published alongside it as "dev", which keeps unreleased
# documentation reachable without it being what a visitor lands on.
#
# Run it from the repository root with mkdocs on PATH.
set -euo pipefail

SITE_ROOT="${SITE_ROOT:-https://karvashish.github.io/hardline/}"
OUT="$PWD/site"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

rm -rf "$OUT"
mkdir -p "$OUT"

# Both release/v1.2.3 and release/1.2.3 are accepted; the branch name has not
# been consistent historically. Prereleases are not published, and a branch is
# published only once its tag exists, so an abandoned release PR whose branch
# survives never reaches the site.
release_versions() {
  git for-each-ref --format='%(refname:short)' 'refs/remotes/origin/release/*' |
    sed 's#^origin/##' |
    while read -r branch; do
      version="${branch#release/}"
      version="${version#v}"
      case "$version" in
        *-*) continue ;;
        [0-9]*.[0-9]*.[0-9]*) ;;
        *) continue ;;
      esac
      if ! git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
        echo "skipping $branch: tag v$version does not exist" >&2
        continue
      fi
      printf '%s\t%s\n' "$version" "$branch"
    done | sort -Vr
}

# The build reads an overlay config rather than each version's own mkdocs.yml,
# because the version selector has to appear on versions whose config was
# written before the selector existed and those trees are immutable.
build_version() {
  local ref="$1" slug="$2"
  local src="$WORK/$slug"

  rm -rf "$src"
  mkdir -p "$src"
  git archive "$ref" | tar -x -C "$src"

  if [ ! -f "$src/mkdocs.yml" ]; then
    echo "$ref predates the docs site (no mkdocs.yml); skipping" >&2
    return 1
  fi

  cat >"$src/mkdocs.versioned.yml" <<EOF
INHERIT: ./mkdocs.yml
site_url: ${SITE_ROOT}${slug}/
extra:
  version:
    provider: mike
    default: latest
EOF

  mkdocs build --config-file "$src/mkdocs.versioned.yml" --site-dir "$OUT/$slug"
}

entries=()
latest_version=""
latest_branch=""

while IFS=$'\t' read -r version branch; do
  [ -n "$version" ] || continue
  if ! build_version "origin/$branch" "$version"; then
    continue
  fi
  if [ -z "$latest_version" ]; then
    latest_version="$version"
    latest_branch="$branch"
    entries+=("{\"version\":\"$version\",\"title\":\"$version (latest)\",\"aliases\":[\"latest\"]}")
  else
    entries+=("{\"version\":\"$version\",\"title\":\"$version\",\"aliases\":[]}")
  fi
done < <(release_versions)

if [ -z "$latest_version" ]; then
  echo "no release branch produced a docs build" >&2
  exit 1
fi

# latest/ is a second build rather than a copy of the version directory, so its
# canonical URL points at latest/. A canonical pinned to a version number would
# leave search engines serving whichever release they indexed, forever.
build_version "origin/$latest_branch" latest

build_version HEAD dev
entries+=('{"version":"dev","title":"dev (unreleased)","aliases":[]}')

printf '[%s]\n' "$(
  IFS=,
  echo "${entries[*]}"
)" >"$OUT/versions.json"

cat >"$OUT/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>Hardline documentation</title>
<link rel="canonical" href="${SITE_ROOT}latest/">
<meta http-equiv="refresh" content="0; url=./latest/">
<a href="./latest/">Hardline documentation</a>
EOF

echo "site root serves ${latest_version}; published ${#entries[@]} versions"

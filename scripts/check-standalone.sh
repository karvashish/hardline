#!/usr/bin/env bash
# Proves a released archive works without the source tree. Builds hardline into
# a scratch dir, copies the starter profile out, deletes the checkout copy, then
# verifies. Regression guard for schemas resolved from a compile-time path.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src"
git -C "$repo_root" ls-files -z --cached --others --exclude-standard |
	tar -C "$repo_root" --null -T - -cf - |
	tar -C "$work/src" -xf -

(cd "$work/src" && go build -o "$work/hardline" ./cmd/hardline)
cp -r "$work/src/starter-secure-ubuntu-24.04-lts" "$work/profile"
rm -rf "$work/src"

"$work/hardline" verify "$work/profile"
echo "standalone verify passed with no source tree present"

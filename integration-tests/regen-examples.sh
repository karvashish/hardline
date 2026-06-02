#!/usr/bin/env bash
# Capture example artifacts (verify, three plan-report formats, apply, rollback,
# journal) for a profile by running the documented flow against an ALREADY
# provisioned host, normalize host/home/build-version to fixed placeholders, and
# write the result into the examples dir. Invoked by `make examples`, which
# builds the binary, provisions the host, and tears it down around this script —
# so this script does none of those itself.
#
# Usage: regen-examples.sh <PROFILE_DIR> <OUTPUTS_JSON> <BIN> <EXAMPLES_DIR>
set -uo pipefail

PROFILE_DIR="${1:?profile dir required}"
OUTPUTS="${2:?terraform outputs json required}"
BIN="${3:?hardline binary path required}"
EXAMPLES_DIR="${4:?examples output dir required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PROFILE_ID="$(jq -er '.id' "${PROFILE_DIR}/profile.json")" || { echo "cannot read profile id from ${PROFILE_DIR}/profile.json"; exit 1; }
STAGE="$(mktemp -d "${ROOT_DIR}/tmp/examples-stage.XXXXXX")"
STATE_DIR="$(mktemp -d "${ROOT_DIR}/tmp/examples-state.XXXXXX")"
KH="$(mktemp "${ROOT_DIR}/tmp/examples-known_hosts.XXXXXX")"
trap 'rm -rf "${STAGE}" "${STATE_DIR}" "${KH}"' EXIT

mkdir -p "${STAGE}"/{verify,plan,apply,rollback,journal}

host="$(jq -er '.external_ip.value' "${OUTPUTS}")" || { echo "missing external_ip in ${OUTPUTS}"; exit 1; }
user="$(jq -er '.ssh_user.value' "${OUTPUTS}")" || { echo "missing ssh_user in ${OUTPUTS}"; exit 1; }
key="$(jq -er '.ssh_private_key_path_hint.value' "${OUTPUTS}")" || { echo "missing ssh key in ${OUTPUTS}"; exit 1; }
echo "host=${host} user=${user} key=${key}"

ssh-keyscan -H "${host}" > "${KH}" 2>/dev/null || { echo "keyscan failed"; exit 1; }
export HARDLINE_KNOWN_HOSTS="${KH}"
export HARDLINE_STATE_DIR="${STATE_DIR}"
RA=(--host "${host}" --user "${user}" --keypath "${key}")

run() {  # run <label> <cmd...>
  echo "--- ${1} ---"; shift
  "$@"; echo "  exit=$?"
}

echo "=== VERIFY ==="
run verify "${BIN}" verify-profile "${PROFILE_DIR}" --log-file "${STAGE}/verify/verify.log"

echo "=== PLAN (json/yaml/md, read-only) ==="
run plan-json "${BIN}" plan "${PROFILE_DIR}" "${RA[@]}" --log-file "${STAGE}/plan/plan.log" --report-file "${STAGE}/plan/report.json"
run plan-yaml "${BIN}" plan "${PROFILE_DIR}" "${RA[@]}" --log-file /dev/null               --report-file "${STAGE}/plan/report.yaml"
run plan-md   "${BIN}" plan "${PROFILE_DIR}" "${RA[@]}" --log-file /dev/null               --report-file "${STAGE}/plan/report.md"

echo "=== APPLY + JOURNAL, then ROLLBACK ==="
run apply "${BIN}" apply "${PROFILE_DIR}" "${RA[@]}" --keep-local-rollback --log-file "${STAGE}/apply/apply.log"
cp -f "${STATE_DIR}/${host}/${PROFILE_ID}.json" "${STAGE}/journal/${PROFILE_ID}.json" 2>/dev/null || echo "WARNING: journal not found"
run rollback "${BIN}" rollback "${PROFILE_DIR}" "${RA[@]}" --log-file "${STAGE}/rollback/rollback.log"

echo "=== NORMALIZE -> ${EXAMPLES_DIR} ==="
# Real host IP, the runner's home prefix (the repo's parent dir), and the build
# version become fixed placeholders so the committed artifacts are stable.
esc_host="$(printf '%s' "${host}" | sed 's/\./\\./g')"
home_prefix="$(dirname "${ROOT_DIR}")"
rm -rf "${EXAMPLES_DIR}"
while IFS= read -r f; do
  rel="${f#"${STAGE}"/}"
  mkdir -p "${EXAMPLES_DIR}/$(dirname "${rel}")"
  sed -e "s/${esc_host}/203.0.113.10/g" \
      -e "s|${home_prefix}|/home/user|g" \
      -e "s/version=[^ ]*/version=0.1.2/g" \
      "${f}" > "${EXAMPLES_DIR}/${rel}"
done < <(find "${STAGE}" -type f | sort)

echo "=== WROTE ==="
find "${EXAMPLES_DIR}" -type f -printf '%s\t%p\n' | sort -k2
echo "=== DONE ==="

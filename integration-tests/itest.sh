#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-smoke}"
PROFILE_DIR="${2:?profile path required}"
OUTPUTS_JSON="${3:?terraform outputs json path required}"
BINARY_PATH="${4:?hardline binary path required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KNOWN_HOSTS_PATH="${ROOT_DIR}/tmp/itest-known_hosts"
STATE_DIR="${ROOT_DIR}/tmp/itest-state"
ARTIFACT_ROOT="${ROOT_DIR}/tmp/itest-artifacts"
SUCCESS_PROFILE="${ROOT_DIR}/integration-tests/profiles/ssh-reload-success"
FAILURE_PROFILE="${ROOT_DIR}/integration-tests/profiles/ssh-reload-force-rollback"
SUCCESS_DEST="/etc/ssh/sshd_config.d/99-hardline-itest-ssh.conf"
FAILURE_DEST="/etc/ssh/sshd_config.d/99-hardline-itest-ssh-bad.conf"
REMOTE_JOURNAL="/var/lib/hardline/runs/last.json"

fail() {
  echo "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

ensure_file() {
  local path="$1"
  test -s "${path}" || fail "expected non-empty file: ${path}"
}

reset_dir() {
  local path="$1"
  rm -rf "${path}"
  mkdir -p "${path}"
}

local_journal_path() {
  printf '%s/%s/last.json\n' "${STATE_DIR}" "${host}"
}

ssh_cmd() {
  ssh \
    -i "${key_path}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${KNOWN_HOSTS_PATH}" \
    "${user}@${host}" \
    "$@"
}

remote_rm_file() {
  local path="$1"
  local quoted
  quoted="$(printf '%q' "${path}")"
  ssh_cmd "sudo rm -f ${quoted}"
}

assert_remote_present() {
  local path="$1"
  local quoted
  quoted="$(printf '%q' "${path}")"
  ssh_cmd "sudo test -f ${quoted}" || fail "expected remote file to exist: ${path}"
}

assert_remote_absent() {
  local path="$1"
  local quoted
  quoted="$(printf '%q' "${path}")"
  ssh_cmd "sudo test ! -e ${quoted}" || fail "expected remote file to be absent: ${path}"
}

assert_local_journal_status() {
  local expected_status="$1"
  local expected_profile="$2"
  local journal_path

  journal_path="$(local_journal_path)"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "${expected_status}" \
    --arg profile "${expected_profile}" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
}

run_success_apply() {
  local dir="${ARTIFACT_ROOT}/apply-keep-local-rollback"

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${SUCCESS_DEST}"

  echo "== itest scenario: apply-keep-local-rollback =="
  "${BINARY_PATH}" apply "${SUCCESS_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-ssh-reload-success"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected apply report contents"
  assert_remote_present "${SUCCESS_DEST}"
  assert_remote_present "${REMOTE_JOURNAL}"
  assert_local_journal_status "success" "itest-ssh-reload-success"
}

run_failure_apply() {
  local dir="${ARTIFACT_ROOT}/force-rollback-apply"
  local status

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${FAILURE_DEST}"

  echo "== itest scenario: force-rollback-apply =="
  set +e
  "${BINARY_PATH}" apply "${FAILURE_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.md" \
    --report-format md \
    --debug >"${dir}/output.txt" 2>&1
  status=$?
  set -e

  if [ "${status}" -eq 0 ]; then
    fail "expected forced rollback apply to fail"
  fi

  ensure_file "${dir}/apply.log"
  ensure_file "${dir}/apply-plan.md"
  ensure_file "${dir}/output.txt"
  grep -q "automatic rollback completed" "${dir}/output.txt" || fail "forced rollback apply did not report automatic rollback"
  grep -q "^# Hardline Plan Report" "${dir}/apply-plan.md" || fail "missing markdown apply report"
  assert_local_journal_status "failed" "itest-ssh-reload-force-rollback"
  assert_remote_absent "${FAILURE_DEST}"
}

scenario_smoke() {
  echo "== itest scenario: smoke =="
  "${BINARY_PATH}" plan "${PROFILE_DIR}" "${remote_args[@]}"
  "${BINARY_PATH}" apply "${PROFILE_DIR}" "${remote_args[@]}"
}

scenario_version() {
  local dir="${ARTIFACT_ROOT}/version"

  reset_dir "${dir}"

  echo "== itest scenario: version =="
  "${BINARY_PATH}" version >"${dir}/version.txt" 2>&1
  "${BINARY_PATH}" -v >"${dir}/version-short.txt" 2>&1

  grep -q "hardline version" "${dir}/version.txt" || fail "version command did not report version"
  grep -q "hardline version" "${dir}/version-short.txt" || fail "-v command did not report version"
}

scenario_verify() {
  local dir="${ARTIFACT_ROOT}/verify"

  reset_dir "${dir}"

  echo "== itest scenario: verify =="
  "${BINARY_PATH}" verify-profile "${PROFILE_DIR}" --log-file "${dir}/verify.log"
  "${BINARY_PATH}" vp "${PROFILE_DIR}" --log-file "${dir}/vp.log" --debug

  ensure_file "${dir}/verify.log"
  ensure_file "${dir}/vp.log"
}

scenario_plan_reports() {
  local dir="${ARTIFACT_ROOT}/plan-reports"

  reset_dir "${dir}"

  echo "== itest scenario: plan-reports =="
  "${BINARY_PATH}" plan "${SUCCESS_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/plan-long.log" \
    --report-file "${dir}/plan-auto.json"
  "${BINARY_PATH}" plan "${SUCCESS_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/plan-short.log" \
    --report-file "${dir}/plan-explicit.yaml" \
    --report-format yaml \
    -d
  "${BINARY_PATH}" plan "${SUCCESS_PROFILE}" "${remote_args[@]}" \
    --report-file "${dir}/plan.md" \
    --report-format md

  ensure_file "${dir}/plan-long.log"
  ensure_file "${dir}/plan-short.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-ssh-reload-success"' "${dir}/plan-auto.json" >/dev/null || fail "unexpected json plan report"
  grep -q "kind: hardline_plan" "${dir}/plan-explicit.yaml" || fail "unexpected yaml plan report"
  grep -q "^# Hardline Plan Report" "${dir}/plan.md" || fail "unexpected markdown plan report"
}

scenario_apply_keep_local_rollback() {
  run_success_apply
}

scenario_rollback_last() {
  local dir="${ARTIFACT_ROOT}/rollback-last"

  run_success_apply
  reset_dir "${dir}"

  echo "== itest scenario: rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d

  ensure_file "${dir}/rollback.log"
  assert_remote_absent "${SUCCESS_DEST}"
}

scenario_force_rollback_apply() {
  run_failure_apply
}

scenario_all() {
  scenario_version
  scenario_verify
  scenario_plan_reports
  scenario_apply_keep_local_rollback
  scenario_rollback_last
  scenario_force_rollback_apply
}

require_cmd jq
require_cmd ssh
require_cmd ssh-keyscan

test -f "${OUTPUTS_JSON}" || fail "missing terraform outputs json: ${OUTPUTS_JSON}"
test -x "${BINARY_PATH}" || fail "hardline binary missing: ${BINARY_PATH} (run: make build)"

host="$(jq -er '.external_ip.value' "${OUTPUTS_JSON}")"
user="$(jq -er '.ssh_user.value' "${OUTPUTS_JSON}")"
key_path="$(jq -er '.ssh_private_key_path_hint.value' "${OUTPUTS_JSON}")"

case "${key_path}" in
  /*) ;;
  *)
    fail "ssh_private_key_path_hint must be an absolute path: ${key_path}"
    ;;
esac

test -f "${key_path}" || fail "ssh private key not found: ${key_path}"

mkdir -p "${ROOT_DIR}/tmp" "${ARTIFACT_ROOT}"
ssh-keyscan -H "${host}" > "${KNOWN_HOSTS_PATH}" 2>/dev/null || fail "ssh-keyscan failed for ${host}"

export HARDLINE_KNOWN_HOSTS="${KNOWN_HOSTS_PATH}"
export HARDLINE_STATE_DIR="${STATE_DIR}"

remote_args=(--host "${host}" --user "${user}" --keypath "${key_path}")
short_remote_args=(-h "${host}" -u "${user}" -k "${key_path}")

case "${SCENARIO}" in
  smoke)
    scenario_smoke
    ;;
  version)
    scenario_version
    ;;
  verify)
    scenario_verify
    ;;
  plan-reports)
    scenario_plan_reports
    ;;
  apply-keep-local-rollback)
    scenario_apply_keep_local_rollback
    ;;
  rollback-last)
    scenario_rollback_last
    ;;
  force-rollback-apply)
    scenario_force_rollback_apply
    ;;
  all)
    scenario_all
    ;;
  *)
    fail "unknown itest scenario: ${SCENARIO}"
    ;;
esac

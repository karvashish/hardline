#!/usr/bin/env bash
# =============================================================================
# harness.sh — test framework: counters, multiplexed SSH, batched remote
#              assertions, command runners, idempotency/restart proofs.
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# Design goals (vs the old framework.sh):
#   * One persistent SSH connection (ControlMaster) instead of a fresh handshake
#     per call — every ssh_cmd reuses it.
#   * One batched remote script per scenario (remote()) instead of N round-trips;
#     the captured output names the failing assertion.
#   * hardline output is always captured to an artifact log (run_hl), never
#     silently discarded — failures are diagnosable.
#   * Real proofs for idempotency (file fingerprint) and restart (service stamp),
#     not stdout greps.
#
# The primitives ssh_cmd / fail / require_cmd / ensure_file / reset_dir /
# remote_journal_latest keep their old signatures so lib/runners.sh works
# unchanged — multiplexing just makes its ssh_cmd calls faster.

# ─── Test counters ───────────────────────────────────────────────────────────
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0
FAILURES=()

# Output of the most recent remote() call (set on failure for the caller to show).
REMOTE_OUT=""
# SSH control socket path for connection multiplexing (set by ssh_open_master).
SSH_CTL=""
# Per-scenario sub-check failures, reset by scenario_start, consumed by scenario_end.
SC_FAILS=()

# ─── Test reporting ──────────────────────────────────────────────────────────
# A scenario may run many sub-checks: note_fail records each, and scenario_end
# emits exactly one pass/fail so the counters stay consistent (one verdict per
# scenario). Fatal sub-checks use `|| { scenario_end; return; }`.
scenario_start() {
  local name="$1"
  TOTAL=$((TOTAL + 1))
  SC_FAILS=()
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  [${TOTAL}] ${name}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Record a sub-check failure for the current scenario.
note_fail() {
  local msg="${1:-}"
  echo "  - FAIL: ${msg}" >&2
  SC_FAILS+=("${msg}")
}

# Emit the scenario verdict from accumulated sub-check failures.
scenario_end() {
  if [[ ${#SC_FAILS[@]} -eq 0 ]]; then
    scenario_pass
  else
    scenario_fail "${#SC_FAILS[@]} check(s) failed: ${SC_FAILS[*]}"
  fi
}

scenario_pass() {
  echo "  PASSED"
  PASSED=$((PASSED + 1))
}

scenario_fail() {
  local msg="${1:-}"
  echo "  FAILED: ${msg}" >&2
  FAILED=$((FAILED + 1))
  FAILURES+=("S${TOTAL}: ${msg}")
}

scenario_skip() {
  local msg="${1:-}"
  echo "  SKIPPED: ${msg}" >&2
  SKIPPED=$((SKIPPED + 1))
}

print_summary() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  RESULTS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "  Total:   ${TOTAL}"
  echo "  Passed:  ${PASSED}"
  echo "  Failed:  ${FAILED}"
  echo "  Skipped: ${SKIPPED}"
  echo ""
  if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo "  Failures:"
    for f in "${FAILURES[@]}"; do
      echo "    - ${f}"
    done
    echo ""
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ─── Utility helpers ─────────────────────────────────────────────────────────
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

# Skip the current scenario when signing isn't available (dynamic profiles need
# a signed manifest). Returns non-zero so callers can `guard_can_sign || return`.
guard_can_sign() {
  if [[ "${CAN_SIGN:-false}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return 1
  fi
  return 0
}

# ─── SSH (multiplexed) ───────────────────────────────────────────────────────
# Open a single master connection that every ssh_cmd reuses. ControlPersist
# keeps it alive across the whole suite; ssh_close_master tears it down.
ssh_open_master() {
  SSH_CTL="$(mktemp -u "${ROOT_DIR}/tmp/itest-ctl.XXXXXX")"
  ssh \
    -i "${key_path}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${KNOWN_HOSTS_PATH}" \
    -o ControlMaster=yes \
    -o ControlPath="${SSH_CTL}" \
    -o ControlPersist=600 \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=4 \
    -fN "${user}@${host}" \
    || fail "failed to open ssh master connection to ${user}@${host}"
}

ssh_close_master() {
  if [ -n "${SSH_CTL}" ] && [ -S "${SSH_CTL}" ]; then
    ssh -o ControlPath="${SSH_CTL}" -O exit "${user}@${host}" >/dev/null 2>&1 || true
  fi
  [ -n "${SSH_CTL}" ] && rm -f "${SSH_CTL}" 2>/dev/null || true
}

# Run a command on the remote host over the shared connection. Falls back to a
# direct connection if the master is not up (e.g. sourced standalone).
ssh_cmd() {
  local ctl_opts=()
  if [ -n "${SSH_CTL}" ]; then
    ctl_opts=(-o ControlPath="${SSH_CTL}" -o ControlMaster=no)
  fi
  ssh \
    -i "${key_path}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${KNOWN_HOSTS_PATH}" \
    "${ctl_opts[@]}" \
    "${user}@${host}" \
    "$@"
}

# Run a root bash script (read from stdin) on the remote host in one round-trip.
# `set -e -o pipefail` so the first failing assertion aborts and is surfaced.
# On failure: returns non-zero and leaves combined output in REMOTE_OUT.
#
#   remote <<EOF
#   test -f /etc/foo
#   stat -c %a /etc/foo | grep -qx 600
#   EOF
remote() {
  REMOTE_OUT="$(ssh_cmd "sudo bash -seo pipefail" 2>&1)"
}

# Like remote(), but records a sub-check failure (with the remote output) when
# the script exits non-zero. Returns non-zero so callers can `|| ...`.
#   must_remote "drop-in reverted" <<EOF ... EOF
must_remote() {
  local desc="$1"
  if remote; then
    return 0
  fi
  note_fail "${desc}"
  [ -n "${REMOTE_OUT}" ] && echo "    remote output:" >&2 && echo "${REMOTE_OUT}" | sed 's/^/      /' >&2
  return 1
}

# Capture stdout of a remote root command (trimmed of CR/LF). For fingerprints
# and single-value probes.
remote_value() {
  ssh_cmd "sudo bash -seo pipefail" <<<"$*" | tr -d '\r' | tr -d '\n'
}

# ─── hardline command runner ─────────────────────────────────────────────────
# Run the binary, capturing stdout+stderr to an artifact log. Returns the exit
# code; never discards output. `--` separates the log path from hardline args.
#   run_hl "${dir}/apply.log" -- apply "${pdir}" "${remote_args[@]}"
run_hl() {
  local logf="$1"; shift
  [ "${1:-}" = "--" ] && shift
  "${BINARY_PATH}" "$@" >"${logf}" 2>&1
}

# Must-succeed wrapper: on non-zero, register a scenario failure with the log
# tail and return non-zero so callers can `|| return`.
must_hl() {
  local logf="$1" desc="$2"; shift 2
  [ "${1:-}" = "--" ] && shift
  local ec=0
  run_hl "${logf}" -- "$@" || ec=$?
  if [ "${ec}" -ne 0 ]; then
    note_fail "${desc} (hardline exit ${ec})"
    echo "    ${logf} tail:" >&2
    tail -n 15 "${logf}" 2>/dev/null | sed 's/^/      /' >&2
    return 1
  fi
  return 0
}

# Must-fail wrapper: succeeds (returns 0) only when hardline exits non-zero.
# Records a sub-check failure when hardline unexpectedly exits 0.
expect_hl_fail() {
  local logf="$1" desc="$2"; shift 2
  [ "${1:-}" = "--" ] && shift
  local ec=0
  run_hl "${logf}" -- "$@" || ec=$?
  if [ "${ec}" -eq 0 ]; then
    note_fail "${desc} (expected non-zero exit, got 0)"
    return 1
  fi
  return 0
}

# ─── Proof helpers ───────────────────────────────────────────────────────────
# Idempotency fingerprint: inode:mtime:mode:owner:group. A no-op apply must not
# change any of these.
fp_path() {
  remote_value "stat -c '%i:%Y:%a:%U:%G' -- '$1'"
}

# Restart proof: MainPID + monotonic active-enter timestamp. A real restart
# moves at least one of these; a skipped restart leaves both unchanged.
svc_stamp() {
  remote_value "systemctl show -p MainPID -p ActiveEnterTimestampMonotonic --value '$1' | tr '\n' ':'"
}

# Independent "service action" mark: MainPID + last state-change timestamp.
# A restart moves MainPID; a reload-in-place moves StateChangeTimestamp (the unit
# transitions through the reload sub-state). Both come straight from systemd.
svc_actmark() {
  remote_value "systemctl show -p MainPID -p StateChangeTimestampMonotonic --value '$1' | tr '\n' ':'"
}

# A journal cursor marking "now" — scopes a later journal query to entries
# produced after this point.
journal_cursor() {
  remote_value "journalctl -n 1 --show-cursor -o export 2>/dev/null | sed -n 's/^__CURSOR=//p' | tail -1"
}

# Did systemd actually act on the unit (reload OR restart) since the captured
# mark/cursor? Observes the OS, never hardline's log: the mark moves on a
# restart (MainPID) or reload (StateChange), and as a backstop systemd logs a
# Reload entry for the unit. Returns 0 (acted) / 1 (untouched). Use to verify a
# reload/restart without trusting hardline's REVERTED/SKIPPED narration.
#   mark0="$(svc_actmark cron)"; cur="$(journal_cursor)"; ... ; svc_acted_since cron "$mark0" "$cur"
svc_acted_since() {
  local unit="$1" mark0="$2" cursor="$3"
  [ "$(svc_actmark "${unit}")" != "${mark0}" ] && return 0
  ssh_cmd "sudo journalctl -u '${unit}' --after-cursor '${cursor}' 2>/dev/null | grep -qiE 'reload'" && return 0
  return 1
}

# ─── Journals ────────────────────────────────────────────────────────────────
# Path of the newest remote rollback journal for a profile id.
remote_journal_latest() {
  local profile_id="$1"
  local dir="/var/lib/hardline/runs/${profile_id}"
  local fname
  fname="$(ssh_cmd "sudo ls -1 ${dir} 2>/dev/null | sort | tail -1" | tr -d '\r\n')"
  if [ -z "${fname}" ]; then
    fail "no remote journal found for profile ${profile_id}"
  fi
  echo "${dir}/${fname}"
}

# Assert a journal file (local path or remote-fetched) has the expected
# profile_id, status, and a non-empty checksum. $1=json-on-stdin via caller.
assert_journal() {
  local label="$1" json="$2" want_profile="$3" want_status="$4"
  if ! echo "${json}" | jq -er \
      --arg p "${want_profile}" --arg s "${want_status}" \
      '.profile_id == $p and .status == $s and (.checksum | type == "string" and length > 0)' \
      >/dev/null 2>&1; then
    note_fail "${label}: expected profile=${want_profile} status=${want_status} with checksum"
    echo "    journal: ${json}" | head -c 400 >&2
    return 1
  fi
  return 0
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
  ssh_close_master
  if [ -n "${KNOWN_HOSTS_PATH:-}" ] && [ -f "${KNOWN_HOSTS_PATH}" ]; then
    rm -f "${KNOWN_HOSTS_PATH}"
  fi
  if [ -n "${DYNAMIC_PROFILES_DIR:-}" ] && [ -d "${DYNAMIC_PROFILES_DIR}" ]; then
    rm -rf "${DYNAMIC_PROFILES_DIR}"
  fi
}

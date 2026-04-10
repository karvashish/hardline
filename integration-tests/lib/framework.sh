#!/usr/bin/env bash
# =============================================================================
# framework.sh — Test framework, SSH helpers, utility functions
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ─── Test counters ───────────────────────────────────────────────────────────
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0
FAILURES=()

# ─── Test framework ─────────────────────────────────────────────────────────
scenario_start() {
  local name="$1"
  TOTAL=$((TOTAL + 1))
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  [${TOTAL}] ${name}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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

# ─── SSH ─────────────────────────────────────────────────────────────────────
ssh_cmd() {
  ssh \
    -i "${key_path}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${KNOWN_HOSTS_PATH}" \
    "${user}@${host}" \
    "$@"
}

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

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
  if [ -n "${KNOWN_HOSTS_PATH}" ] && [ -f "${KNOWN_HOSTS_PATH}" ]; then
    rm -f "${KNOWN_HOSTS_PATH}"
  fi
  if [ -n "${DYNAMIC_PROFILES_DIR:-}" ] && [ -d "${DYNAMIC_PROFILES_DIR}" ]; then
    rm -rf "${DYNAMIC_PROFILES_DIR}"
  fi
}

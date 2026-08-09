#!/usr/bin/env bash
# =============================================================================
# itest.sh — Hardline integration suite (consolidated, real-state verification)
# =============================================================================
# Usage: itest.sh <SCENARIO> <PROFILE_DIR> <OUTPUTS_JSON> <BINARY_PATH>
#
#   SCENARIO     scenario name, or "all" to run the whole suite
#   PROFILE_DIR  a valid signed profile (used by cli-basics / plan tests)
#   OUTPUTS_JSON terraform outputs JSON (host/user/key)
#   BINARY_PATH  path to the hardline binary
#
# Every scenario runs the real hardline command, then verifies the resulting
# system state over SSH the way an operator would. One multiplexed SSH
# connection is shared across the run; each scenario batches its verification
# into a single remote script (see lib/harness.sh).
set -uo pipefail

SCENARIO="${1:-base-profile}"
PROFILE_DIR="${2:?profile path required}"
OUTPUTS_JSON="${3:?terraform outputs json path required}"
BINARY_PATH="${4:?hardline binary path required}"

# A bare "smoke" (the Makefile `itest` default) maps to the base-profile run.
[[ "${SCENARIO}" == "smoke" ]] && SCENARIO="base-profile"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="${ROOT_DIR}/integration-tests/lib"
KNOWN_HOSTS_PATH=""
STATE_DIR="${ROOT_DIR}/tmp/itest-state"
ARTIFACT_ROOT="${ROOT_DIR}/tmp/itest-artifacts"
DYNAMIC_PROFILES_DIR=""

# ─── Static profile paths (used by runners.sh) ───────────────────────────────
# BASE_PROFILE is target-dependent and set by itest_os_init below.
MULTI_SUCCESS_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-success"
PACKAGE_ROLLBACK_PROFILE="${ROOT_DIR}/integration-tests/profiles/package-rollback"
LAYER_BASE_PROFILE="${ROOT_DIR}/integration-tests/profiles/layer-base"
FAILURE_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-force-rollback"
SSH_RELOAD_PROFILE="${ROOT_DIR}/integration-tests/profiles/ssh-reload-success"
SSH_RELOAD_FORCE_PROFILE="${ROOT_DIR}/integration-tests/profiles/ssh-reload-force-rollback"

# ─── Remote destination constants (used by runners.sh) ───────────────────────
MULTI_SUCCESS_TEMPLATE_DEST="/etc/hardline.d/99-hardline-itest-success.conf"
MULTI_SUCCESS_FIREWALL_DEST="/etc/nftables.d/99-hardline-itest-success.nft"
MULTI_SUCCESS_FIREWALL_TABLE="hardline_itest_success"
PACKAGE_ROLLBACK_PACKAGE="tree"
PACKAGE_ROLLBACK_TEMPLATE_DEST="/etc/hardline.d/99-hardline-itest-package-rollback.conf"
LAYER_BASE_TEMPLATE_DEST="/etc/hardline.d/99-hardline-itest-layer-base.conf"
LAYER_BASE_FIREWALL_DEST="/etc/nftables.d/99-hardline-itest-layer-base.nft"
LAYER_BASE_FIREWALL_TABLE="hardline_itest_layer_base"
MULTI_FAILURE_TEMPLATE_DEST="/etc/hardline.d/99-hardline-itest-force-rollback.conf"
MULTI_FAILURE_FIREWALL_DEST="/etc/nftables.d/99-hardline-itest-force-rollback.nft"
MULTI_FAILURE_FIREWALL_TABLE="hardline_itest_force_rollback"
FAILURE_DEST="/etc/ssh/sshd_config.d/99-hardline-itest-ssh-bad.conf"
SSH_RELOAD_DEST="/etc/ssh/sshd_config.d/99-hardline-itest-ssh.conf"
BOOTSTRAP_MARKER="/var/lib/hardline/itest-base-profile.sha256"

# ─── Source libraries ────────────────────────────────────────────────────────
source "${LIB_DIR}/harness.sh"
source "${LIB_DIR}/os.sh"
source "${LIB_DIR}/fixtures.sh"
source "${LIB_DIR}/runners.sh"
source "${LIB_DIR}/suite/00-cli.sh"
source "${LIB_DIR}/suite/10-base.sh"
source "${LIB_DIR}/suite/20-template.sh"
source "${LIB_DIR}/suite/30-packages.sh"
source "${LIB_DIR}/suite/40-firewall.sh"
source "${LIB_DIR}/suite/50-service.sh"
source "${LIB_DIR}/suite/60-filemeta.sh"
source "${LIB_DIR}/suite/70-rollback.sh"
source "${LIB_DIR}/suite/80-overrides.sh"
source "${LIB_DIR}/suite/90-trust-boundary.sh"

# ─── Prerequisites ───────────────────────────────────────────────────────────
require_cmd jq
require_cmd sha256sum
require_cmd ssh
require_cmd ssh-keyscan

test -f "${OUTPUTS_JSON}" || fail "missing terraform outputs json: ${OUTPUTS_JSON}"
test -x "${BINARY_PATH}" || fail "hardline binary missing: ${BINARY_PATH} (run: make build)"

itest_os_init
if [ -n "${BASE_PROFILE}" ]; then
  test -f "${BASE_PROFILE}/manifest.json" || fail "missing base profile manifest: ${BASE_PROFILE}/manifest.json"
fi

# ─── SSH connection info ──────────────────────────────────────────────────────
host="$(jq -er '.external_ip.value' "${OUTPUTS_JSON}")" || fail "failed to read external_ip from ${OUTPUTS_JSON}"
user="$(jq -er '.ssh_user.value' "${OUTPUTS_JSON}")" || fail "failed to read ssh_user from ${OUTPUTS_JSON}"
key_path="$(jq -er '.ssh_private_key_path_hint.value' "${OUTPUTS_JSON}")" || fail "failed to read ssh_private_key_path_hint from ${OUTPUTS_JSON}"

case "${key_path}" in
  /*) ;;
  *) fail "ssh_private_key_path_hint must be an absolute path: ${key_path}" ;;
esac
test -f "${key_path}" || fail "ssh private key not found: ${key_path}"

# ─── Setup ───────────────────────────────────────────────────────────────────
mkdir -p "${ROOT_DIR}/tmp" "${ARTIFACT_ROOT}"
KNOWN_HOSTS_PATH="$(mktemp "${ROOT_DIR}/tmp/itest-known_hosts.XXXXXX")"
DYNAMIC_PROFILES_DIR="$(mktemp -d "${ROOT_DIR}/tmp/itest-profiles.XXXXXX")"
trap cleanup EXIT

ssh-keyscan -H "${host}" > "${KNOWN_HOSTS_PATH}" 2>/dev/null || fail "ssh-keyscan failed for ${host}"

export HARDLINE_KNOWN_HOSTS="${KNOWN_HOSTS_PATH}"
export HARDLINE_STATE_DIR="${STATE_DIR}"

base_manifest_sha=""
if [ -n "${BASE_PROFILE}" ]; then
  base_manifest_sha="$(sha256sum "${BASE_PROFILE}/manifest.json" | awk '{print $1}')"
fi
remote_args=(--host "${host}" --user "${user}" --keypath "${key_path}")
short_remote_args=(-H "${host}" -u "${user}" -k "${key_path}")

init_signing
ssh_open_master
ssh_cmd "sudo mkdir -p /etc/hardline.d /etc/nftables.d"

# ─── Scenario registry (ordered) ─────────────────────────────────────────────
# Function name = scenario_<name-with-dashes-as-underscores>.
SCENARIOS=(
  # CLI + verify
  cli-basics verify-rejections plan-reports plugin-dir-rejected
  # Base profile (full apply + exhaustive state verification)
  base-profile
  # Template
  template-apply-idempotent-rollback template-conflict-force managed-path-enforcement
  # Packages
  package-lifecycle package-rollback
  # Firewall
  firewall-basic-rollback firewall-advanced firewall-external-plugin
  # Service
  service-state-matrix service-onchange-skip service-reload-rollback
  service-policy-always service-static-reload-rollback service-purged-unit-rollback
  service-state-rollback service-conflict
  # File meta
  filemeta-stamp filemeta-rollback-conflict filemeta-guards
  # Rollback (static-profile heavy applies)
  multi-plugin-rollback auto-rollback-on-failure layered-rollback layered-auto-rollback
  ssh-reload-rollback ssh-reload-auto-rollback rollback-no-journal apply-no-local-rollback
  # Overrides
  overrides-verify overrides-effect
  # Trust boundaries
  injection-guard signed-bundle-coverage edited-profile-refused firewall-include-rollback
)

# Scenarios that require the base profile applied first (nftables include +
# base table). "all" bootstraps via the base-profile scenario, which runs first.
BOOTSTRAP_SET="base-profile firewall-basic-rollback firewall-include-rollback firewall-advanced firewall-external-plugin multi-plugin-rollback auto-rollback-on-failure layered-rollback layered-auto-rollback apply-no-local-rollback overrides-effect"

run_scenario() {
  local name="$1"
  local fn="scenario_${name//-/_}"
  if ! declare -F "${fn}" >/dev/null 2>&1; then
    fail "unknown scenario: ${name} (no function ${fn})"
  fi
  "${fn}"
}

needs_bootstrap() {
  echo "${BOOTSTRAP_SET}" | grep -qw "$1"
}

# ─── Run ─────────────────────────────────────────────────────────────────────
if [[ "${SCENARIO}" == "all" ]]; then
  for s in "${SCENARIOS[@]}"; do
    run_scenario "${s}"
  done
else
  # No starter profile ships for every target. Bootstrapping without one
  # compares an empty marker and then fetches base files that do not exist, so
  # the bootstrap is skipped here and each scenario's own guard decides whether
  # it can still run.
  if needs_bootstrap "${SCENARIO}" && [[ "${SCENARIO}" != "base-profile" ]]; then
    if [[ -n "${BASE_PROFILE}" ]]; then
      ensure_base_bootstrap
    else
      echo "== itest bootstrap: skipped, no starter profile ships for ITEST_OS=${ITEST_OS} =="
    fi
  fi
  run_scenario "${SCENARIO}"
fi

print_summary
[[ ${FAILED} -gt 0 ]] && exit 1
exit 0

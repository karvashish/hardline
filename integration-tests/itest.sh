#!/usr/bin/env bash
# =============================================================================
# itest.sh — Hardline unified integration test suite (59 scenarios)
# =============================================================================
# Usage: itest.sh <SCENARIO> <PROFILE_DIR> <OUTPUTS_JSON> <BINARY_PATH>
#
# SCENARIO: scenario name or "all" to run everything
# PROFILE_DIR: path to a valid profile (used for smoke/verify/plan tests)
# OUTPUTS_JSON: terraform outputs JSON with host/user/key info
# BINARY_PATH: path to the hardline binary
set -uo pipefail

SCENARIO="${1:-smoke}"
PROFILE_DIR="${2:?profile path required}"
OUTPUTS_JSON="${3:?terraform outputs json path required}"
BINARY_PATH="${4:?hardline binary path required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="${ROOT_DIR}/integration-tests/lib"
KNOWN_HOSTS_PATH=""
STATE_DIR="${ROOT_DIR}/tmp/itest-state"
ARTIFACT_ROOT="${ROOT_DIR}/tmp/itest-artifacts"
DYNAMIC_PROFILES_DIR=""

# ─── Static profile paths ───────────────────────────────────────────────────
BASE_PROFILE="${ROOT_DIR}/starter-secure-ubuntu-24.04-lts"
MULTI_SUCCESS_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-success"
PACKAGE_ROLLBACK_PROFILE="${ROOT_DIR}/integration-tests/profiles/package-rollback"
LAYER_BASE_PROFILE="${ROOT_DIR}/integration-tests/profiles/layer-base"
FAILURE_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-force-rollback"

# ─── Remote destination constants ────────────────────────────────────────────
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
BOOTSTRAP_MARKER="/var/lib/hardline/itest-base-profile.sha256"

# ─── Source library files ────────────────────────────────────────────────────
source "${LIB_DIR}/framework.sh"
source "${LIB_DIR}/profiles.sh"
source "${LIB_DIR}/runners.sh"
source "${LIB_DIR}/scenarios/core.sh"
source "${LIB_DIR}/scenarios/rollback.sh"
source "${LIB_DIR}/scenarios/plugins.sh"
source "${LIB_DIR}/scenarios/errors.sh"
source "${LIB_DIR}/scenarios/overrides.sh"

# ─── Validate prerequisites ─────────────────────────────────────────────────
require_cmd jq
require_cmd sha256sum
require_cmd ssh
require_cmd ssh-keyscan

test -f "${OUTPUTS_JSON}" || fail "missing terraform outputs json: ${OUTPUTS_JSON}"
test -x "${BINARY_PATH}" || fail "hardline binary missing: ${BINARY_PATH} (run: make build)"
test -f "${BASE_PROFILE}/manifest.json" || fail "missing base profile manifest: ${BASE_PROFILE}/manifest.json"

# ─── Extract SSH connection info ─────────────────────────────────────────────
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

base_manifest_sha="$(sha256sum "${BASE_PROFILE}/manifest.json" | awk '{print $1}')"
remote_args=(--host "${host}" --user "${user}" --keypath "${key_path}")
short_remote_args=(-H "${host}" -u "${user}" -k "${key_path}")

# ─── Initialize signing for dynamic profiles ────────────────────────────────
init_signing

# Ensure remote dirs exist
ssh_cmd "sudo mkdir -p /etc/hardline.d /etc/nftables.d"

# ─── Scenario list ──────────────────────────────────────────────────────────
ALL_SCENARIOS=(
  # Core CLI (1-4)
  version verify verify-unsigned verify-tampered
  # Plan (5-8)
  plan-reports plan-readonly plan-idempotent plan-diff-output
  # Apply (9-14)
  smoke apply-template apply-package
  apply-keep-local-rollback apply-no-local-rollback apply-concurrent
  # Rollback (15-19)
  rollback-last package-rollback-last layered-rollback-last
  force-rollback-apply layered-force-rollback
  # Rollback extended (20-25)
  auto-rollback-synthetic manual-rollback rollback-no-journal
  local-journal-on-failure remote-journal-on-success journal-checksum
  # Firewall (26-29)
  firewall-nftables firewall-external-plugin firewall-forward-chain firewall-rollback
  # Service (30-34)
  service-on-change-skip service-restart-always service-reload-or-restart
  service-stopped service-enabled-false
  # Packages (35-39)
  package-update-always package-purge package-idempotent
  package-purge-absent package-rollback-reinstalls
  # Error paths (40-45)
  wrong-os-rejected unreachable-host unknown-plugin-rejected
  managed-path-enforcement malformed-profile verify-missing-template
  # Edge cases (46-51)
  min-hardline-version-gate env-state-dir env-known-hosts
  plugin-dir-warning empty-steps-profile invalid-report-format
  # Runtime overrides (52-59)
  overrides-auto-discovered overrides-signature-unaffected
  overrides-explicit-flag-wins overrides-unknown-key-rejected
  overrides-invalid-json-rejected overrides-missing-flag-file
  overrides-apply-auto overrides-apply-flag
)

# Scenarios that require base bootstrap
BOOTSTRAP_SCENARIOS="smoke plan-reports plan-diff-output apply-keep-local-rollback apply-no-local-rollback rollback-last package-rollback-last layered-rollback-last force-rollback-apply layered-force-rollback firewall-external-plugin journal-checksum all"

# ─── Scenario dispatch ──────────────────────────────────────────────────────
run_scenario() {
  local name="$1"
  case "${name}" in
    # Core CLI
    version)                    scenario_version ;;
    verify)                     scenario_verify ;;
    verify-unsigned)            scenario_verify_unsigned ;;
    verify-tampered)            scenario_verify_tampered ;;
    # Plan
    plan-reports)               scenario_plan_reports ;;
    plan-readonly)              scenario_plan_readonly ;;
    plan-idempotent)            scenario_plan_idempotent ;;
    plan-diff-output)           scenario_plan_diff_output ;;
    # Apply
    smoke)                      scenario_smoke ;;
    apply-template)             scenario_apply_template ;;
    apply-package)              scenario_apply_package ;;
    apply-keep-local-rollback)  scenario_apply_keep_local_rollback ;;
    apply-no-local-rollback)    scenario_apply_no_local_rollback ;;
    apply-concurrent)           scenario_apply_concurrent ;;
    # Rollback
    rollback-last)              scenario_rollback_last ;;
    package-rollback-last)      scenario_package_rollback_last ;;
    layered-rollback-last)      scenario_layered_rollback_last ;;
    force-rollback-apply)       scenario_force_rollback_apply ;;
    layered-force-rollback)     scenario_layered_force_rollback ;;
    # Rollback extended
    auto-rollback-synthetic)    scenario_auto_rollback_synthetic ;;
    manual-rollback)            scenario_manual_rollback ;;
    rollback-no-journal)        scenario_rollback_no_journal ;;
    local-journal-on-failure)   scenario_local_journal_on_failure ;;
    remote-journal-on-success)  scenario_remote_journal_on_success ;;
    journal-checksum)           scenario_journal_checksum ;;
    # Firewall
    firewall-nftables)          scenario_firewall_nftables ;;
    firewall-external-plugin)   scenario_firewall_external_plugin ;;
    firewall-forward-chain)     scenario_firewall_forward_chain ;;
    firewall-rollback)          scenario_firewall_rollback ;;
    # Service
    service-on-change-skip)     scenario_service_on_change_skip ;;
    service-restart-always)     scenario_service_restart_always ;;
    service-reload-or-restart)  scenario_service_reload_or_restart ;;
    service-stopped)            scenario_service_stopped ;;
    service-enabled-false)      scenario_service_enabled_false ;;
    # Packages
    package-update-always)      scenario_package_update_always ;;
    package-purge)              scenario_package_purge ;;
    package-idempotent)         scenario_package_idempotent ;;
    package-purge-absent)       scenario_package_purge_absent ;;
    package-rollback-reinstalls) scenario_package_rollback_reinstalls ;;
    # Error paths
    wrong-os-rejected)          scenario_wrong_os_rejected ;;
    unreachable-host)           scenario_unreachable_host ;;
    unknown-plugin-rejected)    scenario_unknown_plugin_rejected ;;
    managed-path-enforcement)   scenario_managed_path_enforcement ;;
    malformed-profile)          scenario_malformed_profile ;;
    verify-missing-template)    scenario_verify_missing_template ;;
    # Edge cases
    min-hardline-version-gate)  scenario_min_hardline_version_gate ;;
    env-state-dir)              scenario_env_state_dir ;;
    env-known-hosts)            scenario_env_known_hosts ;;
    plugin-dir-warning)         scenario_plugin_dir_warning ;;
    empty-steps-profile)        scenario_empty_steps_profile ;;
    invalid-report-format)      scenario_invalid_report_format ;;
    # Runtime overrides
    overrides-auto-discovered)      scenario_overrides_auto_discovered ;;
    overrides-signature-unaffected) scenario_overrides_signature_unaffected ;;
    overrides-explicit-flag-wins)   scenario_overrides_explicit_flag_wins ;;
    overrides-unknown-key-rejected) scenario_overrides_unknown_key_rejected ;;
    overrides-invalid-json-rejected) scenario_overrides_invalid_json_rejected ;;
    overrides-missing-flag-file)    scenario_overrides_missing_flag_file ;;
    overrides-apply-auto)           scenario_overrides_apply_auto ;;
    overrides-apply-flag)           scenario_overrides_apply_flag ;;
    *)
      fail "unknown scenario: ${name}"
      ;;
  esac
}

# ─── Bootstrap if needed ────────────────────────────────────────────────────
needs_bootstrap() {
  local name="$1"
  echo "${BOOTSTRAP_SCENARIOS}" | grep -qw "${name}"
}

if needs_bootstrap "${SCENARIO}"; then
  ensure_base_bootstrap
fi

# ─── Run ─────────────────────────────────────────────────────────────────────
if [[ "${SCENARIO}" == "all" ]]; then
  for s in "${ALL_SCENARIOS[@]}"; do
    run_scenario "${s}"
  done
else
  run_scenario "${SCENARIO}"
fi

# ─── Summary ────────────────────────────────────────────────────────────────
print_summary

if [[ ${FAILED} -gt 0 ]]; then
  exit 1
fi
exit 0

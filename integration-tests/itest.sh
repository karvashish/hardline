#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-smoke}"
PROFILE_DIR="${2:?profile path required}"
OUTPUTS_JSON="${3:?terraform outputs json path required}"
BINARY_PATH="${4:?hardline binary path required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KNOWN_HOSTS_PATH=""
STATE_DIR="${ROOT_DIR}/tmp/itest-state"
ARTIFACT_ROOT="${ROOT_DIR}/tmp/itest-artifacts"
BASE_PROFILE="${ROOT_DIR}/base-secure-ubuntu-24.04-lts"
MULTI_SUCCESS_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-success"
PACKAGE_ROLLBACK_PROFILE="${ROOT_DIR}/integration-tests/profiles/package-rollback"
LAYER_BASE_PROFILE="${ROOT_DIR}/integration-tests/profiles/layer-base"
FAILURE_PROFILE="${ROOT_DIR}/integration-tests/profiles/multi-plugin-force-rollback"
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
REMOTE_JOURNAL="/var/lib/hardline/runs/last.json"
BOOTSTRAP_MARKER="/var/lib/hardline/itest-base-profile.sha256"

fail() {
  echo "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${KNOWN_HOSTS_PATH}" ] && [ -f "${KNOWN_HOSTS_PATH}" ]; then
    rm -f "${KNOWN_HOSTS_PATH}"
  fi
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

assert_remote_file_mode() {
  local path="$1"
  local expected_mode="$2"
  local quoted
  local actual_mode

  quoted="$(printf '%q' "${path}")"
  actual_mode="$(ssh_cmd "sudo stat -c %a ${quoted}" | tr -d '\r\n')" || fail "failed to read remote mode: ${path}"
  test "${actual_mode}" = "${expected_mode}" || fail "unexpected remote mode for ${path}: got ${actual_mode}, want ${expected_mode}"
}

assert_remote_file_equals() {
  local path="$1"
  local local_path="$2"
  local quoted
  local remote_tmp

  quoted="$(printf '%q' "${path}")"
  remote_tmp="$(mktemp "${ROOT_DIR}/tmp/itest-remote.XXXXXX")"
  ssh_cmd "sudo cat ${quoted}" >"${remote_tmp}" || {
    rm -f "${remote_tmp}"
    fail "failed to read remote file: ${path}"
  }

  if ! cmp -s "${local_path}" "${remote_tmp}"; then
    diff -u "${local_path}" "${remote_tmp}" || true
    rm -f "${remote_tmp}"
    fail "remote file content mismatch: ${path}"
  fi
  rm -f "${remote_tmp}"
}

assert_remote_file_contains() {
  local path="$1"
  local expected_text="$2"
  local quoted

  quoted="$(printf '%q' "${path}")"
  ssh_cmd "sudo cat ${quoted}" | grep -F -q -- "${expected_text}" || fail "expected remote file ${path} to contain: ${expected_text}"
}

assert_remote_service_enabled() {
  local service="$1"
  local quoted

  quoted="$(printf '%q' "${service}")"
  ssh_cmd "sudo systemctl is-enabled ${quoted} >/dev/null 2>&1" || fail "expected service enabled: ${service}"
}

assert_remote_service_active() {
  local service="$1"
  local quoted

  quoted="$(printf '%q' "${service}")"
  ssh_cmd "sudo systemctl is-active ${quoted} >/dev/null 2>&1" || fail "expected service active: ${service}"
}

assert_remote_package_installed() {
  local package_name="$1"
  local quoted

  quoted="$(printf '%q' "${package_name}")"
  ssh_cmd "dpkg -s ${quoted} >/dev/null 2>&1" || fail "expected package installed: ${package_name}"
}

assert_remote_package_absent() {
  local package_name="$1"
  local quoted

  quoted="$(printf '%q' "${package_name}")"
  if ssh_cmd "dpkg -s ${quoted} >/dev/null 2>&1"; then
    fail "expected package absent: ${package_name}"
  fi
}

assert_remote_sysctl_value() {
  local key="$1"
  local expected_value="$2"
  local quoted
  local actual_value

  quoted="$(printf '%q' "${key}")"
  actual_value="$(ssh_cmd "sysctl -n ${quoted}" | tr -d '\r\n')" || fail "failed to read sysctl: ${key}"
  test "${actual_value}" = "${expected_value}" || fail "unexpected sysctl ${key}: got ${actual_value}, want ${expected_value}"
}

assert_remote_nft_include_present() {
  ssh_cmd "sudo grep -E -q 'include[[:space:]]+\"?/etc/nftables\\.d/\\*\\.nft\"?' /etc/nftables.conf" || fail "expected nftables include in /etc/nftables.conf"
}

assert_remote_nft_config_valid() {
  ssh_cmd "sudo nft -c -f /etc/nftables.conf >/dev/null 2>&1" || fail "expected nftables config to validate"
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

assert_local_journal_absent() {
  local journal_path

  journal_path="$(local_journal_path)"
  test ! -e "${journal_path}" || fail "expected local rollback journal to be removed: ${journal_path}"
}

assert_remote_journal_status() {
  local expected_status="$1"
  local expected_profile="$2"
  local quoted

  quoted="$(printf '%q' "${REMOTE_JOURNAL}")"
  ssh_cmd "sudo cat ${quoted}" | jq -er \
    --arg status "${expected_status}" \
    --arg profile "${expected_profile}" \
    '.status == $status and .profile_id == $profile' >/dev/null \
    || fail "unexpected remote rollback journal contents: ${REMOTE_JOURNAL}"
}

assert_remote_nft_table_present() {
  local family="$1"
  local table="$2"
  local family_quoted
  local table_quoted

  family_quoted="$(printf '%q' "${family}")"
  table_quoted="$(printf '%q' "${table}")"
  ssh_cmd "sudo nft list table ${family_quoted} ${table_quoted} >/dev/null 2>&1" || fail "expected nftables table present: ${family} ${table}"
}

assert_remote_nft_table_absent() {
  local family="$1"
  local table="$2"
  local family_quoted
  local table_quoted

  family_quoted="$(printf '%q' "${family}")"
  table_quoted="$(printf '%q' "${table}")"
  if ssh_cmd "sudo nft list table ${family_quoted} ${table_quoted} >/dev/null 2>&1"; then
    fail "expected nftables table absent: ${family} ${table}"
  fi
}

assert_remote_sshd_config_valid() {
  ssh_cmd "sudo /usr/sbin/sshd -t" || fail "expected sshd configuration to validate"
}

restart_remote_nftables() {
  ssh_cmd "sudo systemctl restart nftables" || fail "failed to restart nftables"
}

purge_remote_package_if_installed() {
  local package_name="$1"
  local quoted

  quoted="$(printf '%q' "${package_name}")"
  if ssh_cmd "dpkg -s ${quoted} >/dev/null 2>&1"; then
    ssh_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y ${quoted} >/dev/null 2>&1" || fail "failed to purge package during cleanup: ${package_name}"
  fi
}

assert_base_server_state() {
  echo "== itest verify: base server state =="

  assert_remote_package_installed "nftables"
  assert_remote_package_installed "auditd"
  assert_remote_package_installed "fail2ban"
  assert_remote_package_installed "unattended-upgrades"

  assert_remote_package_absent "telnet"
  assert_remote_package_absent "rsh-client"
  assert_remote_package_absent "ftp"
  assert_remote_package_absent "tftp"
  assert_remote_package_absent "cups"
  assert_remote_package_absent "rpcbind"
  assert_remote_package_absent "nfs-common"
  assert_remote_package_absent "snapd"
  assert_remote_package_absent "whoopsie"
  assert_remote_package_absent "apport"
  assert_remote_package_absent "landscape-client"

  assert_remote_present "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"
  assert_remote_file_mode "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" "600"
  assert_remote_file_equals "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" "${BASE_PROFILE}/templates/10-ssh-sshd-config.tmpl"
  assert_remote_sshd_config_valid

  assert_remote_present "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf"
  assert_remote_file_mode "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" "644"
  assert_remote_file_equals "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" "${BASE_PROFILE}/templates/15-unattended-upgrades.tmpl"

  assert_remote_present "/etc/sysctl.d/99-hardline-hardening.conf"
  assert_remote_file_mode "/etc/sysctl.d/99-hardline-hardening.conf" "644"
  assert_remote_file_equals "/etc/sysctl.d/99-hardline-hardening.conf" "${BASE_PROFILE}/templates/20-sysctl-hardening.conf.tmpl"

  assert_remote_present "/etc/fail2ban/jail.d/99-hardline-ssh.conf"
  assert_remote_file_mode "/etc/fail2ban/jail.d/99-hardline-ssh.conf" "644"
  assert_remote_file_equals "/etc/fail2ban/jail.d/99-hardline-ssh.conf" "${BASE_PROFILE}/templates/35-fail2ban-ssh-protection.tmpl"

  assert_remote_present "/etc/audit/rules.d/99-hardline.rules"
  assert_remote_file_mode "/etc/audit/rules.d/99-hardline.rules" "640"
  assert_remote_file_equals "/etc/audit/rules.d/99-hardline.rules" "${BASE_PROFILE}/templates/40-audit-hardening-rules.tmpl"

  assert_remote_present "/etc/systemd/journald.conf.d/99-hardline.conf"
  assert_remote_file_mode "/etc/systemd/journald.conf.d/99-hardline.conf" "644"
  assert_remote_file_equals "/etc/systemd/journald.conf.d/99-hardline.conf" "${BASE_PROFILE}/templates/50-journald-hardening.conf.tmpl"

  assert_remote_service_enabled "ssh"
  assert_remote_service_active "ssh"
  assert_remote_service_enabled "chrony"
  assert_remote_service_active "chrony"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_service_enabled "fail2ban"
  assert_remote_service_active "fail2ban"
  assert_remote_service_enabled "auditd"
  assert_remote_service_active "auditd"
  assert_remote_service_active "systemd-journald"

  assert_remote_sysctl_value "net.ipv4.ip_forward" "0"
  assert_remote_sysctl_value "net.ipv4.conf.all.rp_filter" "1"
  assert_remote_sysctl_value "net.ipv4.conf.default.rp_filter" "1"
  assert_remote_sysctl_value "net.ipv4.conf.all.accept_redirects" "0"
  assert_remote_sysctl_value "net.ipv4.conf.default.accept_redirects" "0"
  assert_remote_sysctl_value "net.ipv4.conf.all.secure_redirects" "0"
  assert_remote_sysctl_value "net.ipv4.conf.default.secure_redirects" "0"
  assert_remote_sysctl_value "net.ipv4.icmp_echo_ignore_broadcasts" "1"
  assert_remote_sysctl_value "kernel.kptr_restrict" "2"
  assert_remote_sysctl_value "kernel.dmesg_restrict" "1"
  assert_remote_sysctl_value "fs.protected_hardlinks" "1"
  assert_remote_sysctl_value "fs.protected_symlinks" "1"

  assert_remote_present "/etc/nftables.d/99-hardline-firewall.nft"
  assert_remote_file_mode "/etc/nftables.d/99-hardline-firewall.nft" "644"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "table inet filter {"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "policy drop;"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "iif \"lo\" accept"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "ct state invalid drop"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "ct state established,related accept"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "tcp dport 22 accept"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "ip protocol icmp accept"
  assert_remote_file_contains "/etc/nftables.d/99-hardline-firewall.nft" "ip6 nexthdr icmpv6 accept"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

assert_multi_success_state() {
  assert_remote_present "${MULTI_SUCCESS_TEMPLATE_DEST}"
  assert_remote_file_mode "${MULTI_SUCCESS_TEMPLATE_DEST}" "644"
  assert_remote_file_equals "${MULTI_SUCCESS_TEMPLATE_DEST}" "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl"

  assert_remote_present "${MULTI_SUCCESS_FIREWALL_DEST}"
  assert_remote_file_mode "${MULTI_SUCCESS_FIREWALL_DEST}" "644"
  assert_remote_file_contains "${MULTI_SUCCESS_FIREWALL_DEST}" "table inet hardline_itest_success {"
  assert_remote_file_contains "${MULTI_SUCCESS_FIREWALL_DEST}" "tcp dport 2222 accept"
  assert_remote_file_contains "${MULTI_SUCCESS_FIREWALL_DEST}" "udp dport 5353 accept"
  assert_remote_nft_table_present "inet" "${MULTI_SUCCESS_FIREWALL_TABLE}"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

assert_multi_success_rolled_back() {
  assert_remote_absent "${MULTI_SUCCESS_TEMPLATE_DEST}"
  assert_remote_absent "${MULTI_SUCCESS_FIREWALL_DEST}"
  assert_remote_nft_table_absent "inet" "${MULTI_SUCCESS_FIREWALL_TABLE}"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

assert_package_rollback_state() {
  assert_remote_package_installed "${PACKAGE_ROLLBACK_PACKAGE}"
  assert_remote_present "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
  assert_remote_file_mode "${PACKAGE_ROLLBACK_TEMPLATE_DEST}" "644"
  assert_remote_file_equals "${PACKAGE_ROLLBACK_TEMPLATE_DEST}" "${PACKAGE_ROLLBACK_PROFILE}/templates/10-managed.conf.tmpl"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
}

assert_package_rollback_rolled_back() {
  assert_remote_package_absent "${PACKAGE_ROLLBACK_PACKAGE}"
  assert_remote_absent "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
}

assert_layer_base_state() {
  assert_remote_present "${LAYER_BASE_TEMPLATE_DEST}"
  assert_remote_file_mode "${LAYER_BASE_TEMPLATE_DEST}" "644"
  assert_remote_file_equals "${LAYER_BASE_TEMPLATE_DEST}" "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl"

  assert_remote_present "${LAYER_BASE_FIREWALL_DEST}"
  assert_remote_file_mode "${LAYER_BASE_FIREWALL_DEST}" "644"
  assert_remote_file_contains "${LAYER_BASE_FIREWALL_DEST}" "table inet ${LAYER_BASE_FIREWALL_TABLE} {"
  assert_remote_file_contains "${LAYER_BASE_FIREWALL_DEST}" "tcp dport 2023 accept"
  assert_remote_file_contains "${LAYER_BASE_FIREWALL_DEST}" "udp dport 5355 accept"
  assert_remote_nft_table_present "inet" "${LAYER_BASE_FIREWALL_TABLE}"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

assert_layer_base_removed() {
  assert_remote_absent "${LAYER_BASE_TEMPLATE_DEST}"
  assert_remote_absent "${LAYER_BASE_FIREWALL_DEST}"
  assert_remote_nft_table_absent "inet" "${LAYER_BASE_FIREWALL_TABLE}"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

assert_multi_failure_rolled_back() {
  assert_remote_absent "${MULTI_FAILURE_TEMPLATE_DEST}"
  assert_remote_absent "${MULTI_FAILURE_FIREWALL_DEST}"
  assert_remote_absent "${FAILURE_DEST}"
  assert_remote_nft_table_absent "inet" "${MULTI_FAILURE_FIREWALL_TABLE}"
  assert_remote_sshd_config_valid
  assert_remote_service_enabled "ssh"
  assert_remote_service_active "ssh"
  assert_remote_service_enabled "nftables"
  assert_remote_service_active "nftables"
  assert_remote_nft_include_present
  assert_remote_nft_config_valid
}

ensure_base_bootstrap() {
  local dir="${ARTIFACT_ROOT}/bootstrap-base"
  local quoted_marker
  local marker_value

  quoted_marker="$(printf '%q' "${BOOTSTRAP_MARKER}")"
  if marker_value="$(ssh_cmd "sudo cat ${quoted_marker}" 2>/dev/null)"; then
    marker_value="$(printf '%s' "${marker_value}" | tr -d '\r\n')"
    if [ "${marker_value}" = "${base_manifest_sha}" ]; then
      assert_base_server_state
      return 0
    fi
  fi

  reset_dir "${dir}"

  echo "== itest bootstrap: base profile =="
  "${BINARY_PATH}" apply "${BASE_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "base-secure-ubuntu-24.04-lts"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected base bootstrap report contents"
  assert_base_server_state
  ssh_cmd "sudo mkdir -p /var/lib/hardline && printf '%s\n' '${base_manifest_sha}' | sudo tee ${quoted_marker} >/dev/null"
}

run_success_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/apply-keep-local-rollback}"

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${MULTI_SUCCESS_TEMPLATE_DEST}"
  remote_rm_file "${MULTI_SUCCESS_FIREWALL_DEST}"
  restart_remote_nftables
  assert_multi_success_rolled_back

  echo "== itest scenario: apply-keep-local-rollback =="
  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected apply report contents"
  assert_multi_success_state
  assert_remote_present "${REMOTE_JOURNAL}"
  assert_remote_journal_status "success" "itest-multi-plugin-success"
  assert_local_journal_status "success" "itest-multi-plugin-success"
}

run_failure_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/force-rollback-apply}"
  local status

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${MULTI_FAILURE_TEMPLATE_DEST}"
  remote_rm_file "${MULTI_FAILURE_FIREWALL_DEST}"
  remote_rm_file "${FAILURE_DEST}"
  restart_remote_nftables
  assert_multi_failure_rolled_back

  echo "== itest scenario: force-rollback-apply =="
  set +e
  "${BINARY_PATH}" apply "${FAILURE_PROFILE}" "${remote_args[@]}" \
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
  assert_local_journal_status "failed" "itest-multi-plugin-force-rollback"
  assert_multi_failure_rolled_back
}

run_package_rollback_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/package-rollback-apply}"

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  purge_remote_package_if_installed "${PACKAGE_ROLLBACK_PACKAGE}"
  remote_rm_file "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"

  echo "== itest scenario: package-rollback-apply =="
  "${BINARY_PATH}" apply "${PACKAGE_ROLLBACK_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-package-rollback"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected package rollback apply report contents"
  assert_package_rollback_state
  assert_remote_present "${REMOTE_JOURNAL}"
  assert_remote_journal_status "success" "itest-package-rollback"
  assert_local_journal_status "success" "itest-package-rollback"
}

run_layer_base_apply() {
  local dir="${1:?artifact directory required}"

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${LAYER_BASE_TEMPLATE_DEST}"
  remote_rm_file "${LAYER_BASE_FIREWALL_DEST}"
  restart_remote_nftables
  assert_layer_base_removed

  echo "== itest scenario: layer-base-apply =="
  "${BINARY_PATH}" apply "${LAYER_BASE_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-layer-base"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected layer base apply report contents"
  assert_layer_base_state
  assert_remote_present "${REMOTE_JOURNAL}"
  assert_remote_journal_status "success" "itest-layer-base"
  assert_local_journal_status "success" "itest-layer-base"
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
  "${BINARY_PATH}" plan "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/plan-long.log" \
    --report-file "${dir}/plan-auto.json"
  "${BINARY_PATH}" plan "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/plan-short.log" \
    --report-file "${dir}/plan-explicit.yaml" \
    --report-format yaml \
    -d
  "${BINARY_PATH}" plan "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --report-file "${dir}/plan.md" \
    --report-format md

  ensure_file "${dir}/plan-long.log"
  ensure_file "${dir}/plan-short.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' "${dir}/plan-auto.json" >/dev/null || fail "unexpected json plan report"
  grep -q "kind: hardline_plan" "${dir}/plan-explicit.yaml" || fail "unexpected yaml plan report"
  grep -q "^# Hardline Plan Report" "${dir}/plan.md" || fail "unexpected markdown plan report"
}

scenario_apply_keep_local_rollback() {
  run_success_apply
}

scenario_apply_no_local_rollback() {
  local dir="${ARTIFACT_ROOT}/apply-no-local-rollback"

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  remote_rm_file "${MULTI_SUCCESS_TEMPLATE_DEST}"
  remote_rm_file "${MULTI_SUCCESS_FIREWALL_DEST}"
  restart_remote_nftables
  assert_multi_success_rolled_back

  echo "== itest scenario: apply-no-local-rollback =="
  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.yaml" \
    --report-format yaml \
    --debug

  ensure_file "${dir}/apply.log"
  grep -q "kind: hardline_plan" "${dir}/apply-plan.yaml" || fail "unexpected yaml apply report"
  assert_multi_success_state
  assert_remote_journal_status "success" "itest-multi-plugin-success"
  assert_local_journal_absent

  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d
  ensure_file "${dir}/rollback.log"
  assert_multi_success_rolled_back
}

scenario_rollback_last() {
  local dir="${ARTIFACT_ROOT}/rollback-last"

  run_success_apply
  reset_dir "${dir}"

  echo "== itest scenario: rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d

  ensure_file "${dir}/rollback.log"
  assert_multi_success_rolled_back
  assert_remote_service_enabled "ssh"
  assert_remote_service_active "ssh"
}

scenario_package_rollback_last() {
  local dir="${ARTIFACT_ROOT}/package-rollback-last"

  run_package_rollback_apply "${dir}/apply"
  reset_dir "${dir}/rollback"

  echo "== itest scenario: package-rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback/rollback.log" -d

  ensure_file "${dir}/rollback/rollback.log"
  assert_package_rollback_rolled_back
}

scenario_layered_rollback_last() {
  local dir="${ARTIFACT_ROOT}/layered-rollback-last"

  reset_dir "${dir}"
  run_layer_base_apply "${dir}/layer-base-apply"
  run_success_apply "${dir}/multi-success-apply"

  echo "== itest scenario: layered-rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d

  ensure_file "${dir}/rollback.log"
  assert_layer_base_state
  assert_multi_success_rolled_back

  run_layer_base_apply "${dir}/layer-base-reapply"
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/cleanup-rollback.log" -d
  ensure_file "${dir}/cleanup-rollback.log"
  assert_layer_base_removed
}

scenario_force_rollback_apply() {
  run_failure_apply
}

scenario_layered_force_rollback() {
  local dir="${ARTIFACT_ROOT}/layered-force-rollback"

  reset_dir "${dir}"
  run_layer_base_apply "${dir}/layer-base-apply"
  run_failure_apply "${dir}/forced-failure"

  assert_layer_base_state
  assert_multi_failure_rolled_back
  assert_remote_journal_status "success" "itest-layer-base"

  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/cleanup-rollback.log" -d
  ensure_file "${dir}/cleanup-rollback.log"
  assert_layer_base_removed
}

scenario_all() {
  scenario_version
  scenario_verify
  scenario_plan_reports
  scenario_apply_no_local_rollback
  scenario_apply_keep_local_rollback
  scenario_rollback_last
  scenario_package_rollback_last
  scenario_layered_rollback_last
  scenario_force_rollback_apply
  scenario_layered_force_rollback
}

require_cmd jq
require_cmd sha256sum
require_cmd ssh
require_cmd ssh-keyscan

test -f "${OUTPUTS_JSON}" || fail "missing terraform outputs json: ${OUTPUTS_JSON}"
test -x "${BINARY_PATH}" || fail "hardline binary missing: ${BINARY_PATH} (run: make build)"
test -f "${BASE_PROFILE}/manifest.json" || fail "missing base profile manifest: ${BASE_PROFILE}/manifest.json"

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
KNOWN_HOSTS_PATH="$(mktemp "${ROOT_DIR}/tmp/itest-known_hosts.XXXXXX")"
trap cleanup EXIT
ssh-keyscan -H "${host}" > "${KNOWN_HOSTS_PATH}" 2>/dev/null || fail "ssh-keyscan failed for ${host}"

export HARDLINE_KNOWN_HOSTS="${KNOWN_HOSTS_PATH}"
export HARDLINE_STATE_DIR="${STATE_DIR}"

base_manifest_sha="$(sha256sum "${BASE_PROFILE}/manifest.json" | awk '{print $1}')"
remote_args=(--host "${host}" --user "${user}" --keypath "${key_path}")
short_remote_args=(-h "${host}" -u "${user}" -k "${key_path}")

case "${SCENARIO}" in
  smoke|plan-reports|apply-no-local-rollback|apply-keep-local-rollback|package-rollback-last|rollback-last|layered-rollback-last|force-rollback-apply|layered-force-rollback|all)
    ensure_base_bootstrap
    ;;
esac

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
  apply-no-local-rollback)
    scenario_apply_no_local_rollback
    ;;
  apply-keep-local-rollback)
    scenario_apply_keep_local_rollback
    ;;
  package-rollback-last)
    scenario_package_rollback_last
    ;;
  rollback-last)
    scenario_rollback_last
    ;;
  layered-rollback-last)
    scenario_layered_rollback_last
    ;;
  force-rollback-apply)
    scenario_force_rollback_apply
    ;;
  layered-force-rollback)
    scenario_layered_force_rollback
    ;;
  all)
    scenario_all
    ;;
  *)
    fail "unknown itest scenario: ${SCENARIO}"
    ;;
esac

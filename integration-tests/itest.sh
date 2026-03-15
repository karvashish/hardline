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

ssh_cmd() {
  ssh \
    -i "${key_path}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="${KNOWN_HOSTS_PATH}" \
    "${user}@${host}" \
    "$@"
}

ensure_base_bootstrap() {
  local dir="${ARTIFACT_ROOT}/bootstrap-base"
  local quoted_marker
  local marker_value
  local check_dir
  local remote_file

  quoted_marker="$(printf '%q' "${BOOTSTRAP_MARKER}")"
  marker_value="$(ssh_cmd "sudo cat ${quoted_marker} 2>/dev/null || true" | tr -d '\r\n')"

  if [ "${marker_value}" != "${base_manifest_sha}" ]; then
    reset_dir "${dir}"

    echo "== itest bootstrap: base profile =="
    "${BINARY_PATH}" apply "${BASE_PROFILE}" "${remote_args[@]}" \
      --log-file "${dir}/apply.log" \
      --report-file "${dir}/apply-plan.json" \
      --report-format json \
      --debug

    ensure_file "${dir}/apply.log"
    jq -er '.kind == "hardline_plan" and .profile.id == "base-secure-ubuntu-24.04-lts"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected base bootstrap report contents"
    ssh_cmd "sudo mkdir -p /var/lib/hardline && printf '%s\n' '${base_manifest_sha}' | sudo tee ${quoted_marker} >/dev/null"
  fi

  echo "== itest verify: base server state =="
  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-base.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/ssh/sshd_config.d/99-hardline-ssh.conf \
    etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf \
    etc/sysctl.d/99-hardline-hardening.conf \
    etc/fail2ban/jail.d/99-hardline-ssh.conf \
    etc/audit/rules.d/99-hardline.rules \
    etc/systemd/journald.conf.d/99-hardline.conf \
    etc/nftables.d/99-hardline-firewall.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch base profile files"
  }

  remote_file="${check_dir}/etc/ssh/sshd_config.d/99-hardline-ssh.conf"
  test "$(stat -c %a "${remote_file}")" = "600" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/10-ssh-sshd-config.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/10-ssh-sshd-config.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote ssh config mismatch"
  }

  remote_file="${check_dir}/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/15-unattended-upgrades.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/15-unattended-upgrades.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote unattended-upgrades config mismatch"
  }

  remote_file="${check_dir}/etc/sysctl.d/99-hardline-hardening.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/20-sysctl-hardening.conf.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/20-sysctl-hardening.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote sysctl config mismatch"
  }

  remote_file="${check_dir}/etc/fail2ban/jail.d/99-hardline-ssh.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/35-fail2ban-ssh-protection.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/35-fail2ban-ssh-protection.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote fail2ban config mismatch"
  }

  remote_file="${check_dir}/etc/audit/rules.d/99-hardline.rules"
  test "$(stat -c %a "${remote_file}")" = "640" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/40-audit-hardening-rules.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/40-audit-hardening-rules.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote audit config mismatch"
  }

  remote_file="${check_dir}/etc/systemd/journald.conf.d/99-hardline.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${BASE_PROFILE}/templates/50-journald-hardening.conf.tmpl" "${remote_file}" || {
    diff -u "${BASE_PROFILE}/templates/50-journald-hardening.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "remote journald config mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-firewall.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q 'table inet filter {' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables table header"; }
  grep -F -q 'policy drop;' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables drop policy"; }
  grep -F -q 'iif "lo" accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables loopback rule"; }
  grep -F -q 'ct state invalid drop' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables invalid-state rule"; }
  grep -F -q 'ct state established,related accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables established-state rule"; }
  grep -F -q 'tcp dport 22 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables ssh rule"; }
  grep -F -q 'ip protocol icmp accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables icmp rule"; }
  grep -F -q 'ip6 nexthdr icmpv6 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing nftables icmpv6 rule"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<'EOF'
set -euo pipefail
dpkg -s nftables >/dev/null 2>&1
dpkg -s auditd >/dev/null 2>&1
dpkg -s fail2ban >/dev/null 2>&1
dpkg -s unattended-upgrades >/dev/null 2>&1

! dpkg -s telnet >/dev/null 2>&1
! dpkg -s rsh-client >/dev/null 2>&1
! dpkg -s ftp >/dev/null 2>&1
! dpkg -s tftp >/dev/null 2>&1
! dpkg -s cups >/dev/null 2>&1
! dpkg -s rpcbind >/dev/null 2>&1
! dpkg -s nfs-common >/dev/null 2>&1
! dpkg -s snapd >/dev/null 2>&1
! dpkg -s whoopsie >/dev/null 2>&1
! dpkg -s apport >/dev/null 2>&1
! dpkg -s landscape-client >/dev/null 2>&1

/usr/sbin/sshd -t
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled chrony >/dev/null 2>&1
systemctl is-active chrony >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
systemctl is-enabled fail2ban >/dev/null 2>&1
systemctl is-active fail2ban >/dev/null 2>&1
systemctl is-enabled auditd >/dev/null 2>&1
systemctl is-active auditd >/dev/null 2>&1
systemctl is-active systemd-journald >/dev/null 2>&1

test "$(sysctl -n net.ipv4.ip_forward)" = "0"
test "$(sysctl -n net.ipv4.conf.all.rp_filter)" = "1"
test "$(sysctl -n net.ipv4.conf.default.rp_filter)" = "1"
test "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = "0"
test "$(sysctl -n net.ipv4.conf.default.accept_redirects)" = "0"
test "$(sysctl -n net.ipv4.conf.all.secure_redirects)" = "0"
test "$(sysctl -n net.ipv4.conf.default.secure_redirects)" = "0"
test "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" = "1"
test "$(sysctl -n kernel.kptr_restrict)" = "2"
test "$(sysctl -n kernel.dmesg_restrict)" = "1"
test "$(sysctl -n fs.protected_hardlinks)" = "1"
test "$(sysctl -n fs.protected_symlinks)" = "1"

grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
}

run_success_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/apply-keep-local-rollback}"
  local check_dir
  local remote_file
  local journal_path

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
rm -f "${MULTI_SUCCESS_TEMPLATE_DEST}" "${MULTI_SUCCESS_FIREWALL_DEST}"
systemctl restart nftables
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  echo "== itest scenario: apply-keep-local-rollback =="
  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-success.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-success.conf \
    etc/nftables.d/99-hardline-itest-success.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch success profile files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-success.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "success profile template mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-success.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${MULTI_SUCCESS_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall table"; }
  grep -F -q 'tcp dport 2222 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall tcp rule"; }
  grep -F -q 'udp dport 5353 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall udp rule"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  ssh_cmd "sudo cat ${REMOTE_JOURNAL}" | jq -er \
    --arg status "success" \
    --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/last.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
}

run_failure_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/force-rollback-apply}"
  local journal_path
  local status

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
rm -f "${MULTI_FAILURE_TEMPLATE_DEST}" "${MULTI_FAILURE_FIREWALL_DEST}" "${FAILURE_DEST}"
systemctl restart nftables
test ! -e "${MULTI_FAILURE_TEMPLATE_DEST}"
test ! -e "${MULTI_FAILURE_FIREWALL_DEST}"
test ! -e "${FAILURE_DEST}"
! nft list table inet "${MULTI_FAILURE_FIREWALL_TABLE}" >/dev/null 2>&1
/usr/sbin/sshd -t
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

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

  journal_path="${STATE_DIR}/${host}/last.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "failed" \
    --arg profile "itest-multi-plugin-force-rollback" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_FAILURE_TEMPLATE_DEST}"
test ! -e "${MULTI_FAILURE_FIREWALL_DEST}"
test ! -e "${FAILURE_DEST}"
! nft list table inet "${MULTI_FAILURE_FIREWALL_TABLE}" >/dev/null 2>&1
/usr/sbin/sshd -t
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
}

run_package_rollback_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/package-rollback-apply}"
  local check_dir
  local remote_file
  local journal_path

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
if dpkg -s "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get purge -y "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1
fi
rm -f "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
test ! -e "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF

  echo "== itest scenario: package-rollback-apply =="
  "${BINARY_PATH}" apply "${PACKAGE_ROLLBACK_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-package-rollback"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected package rollback apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-package.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - etc/hardline.d/99-hardline-itest-package-rollback.conf" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch package rollback files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-package-rollback.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${PACKAGE_ROLLBACK_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${PACKAGE_ROLLBACK_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "package rollback template mismatch"
  }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
dpkg -s "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF

  ssh_cmd "sudo cat ${REMOTE_JOURNAL}" | jq -er \
    --arg status "success" \
    --arg profile "itest-package-rollback" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/last.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-package-rollback" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
}

run_layer_base_apply() {
  local dir="${1:?artifact directory required}"
  local check_dir
  local remote_file
  local journal_path

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
rm -f "${LAYER_BASE_TEMPLATE_DEST}" "${LAYER_BASE_FIREWALL_DEST}"
systemctl restart nftables
test ! -e "${LAYER_BASE_TEMPLATE_DEST}"
test ! -e "${LAYER_BASE_FIREWALL_DEST}"
! nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  echo "== itest scenario: layer-base-apply =="
  "${BINARY_PATH}" apply "${LAYER_BASE_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-layer-base"' "${dir}/apply-plan.json" >/dev/null || fail "unexpected layer base apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch layer base files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "layer base template mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall table"; }
  grep -F -q 'tcp dport 2023 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall tcp rule"; }
  grep -F -q 'udp dport 5355 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall udp rule"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  ssh_cmd "sudo cat ${REMOTE_JOURNAL}" | jq -er \
    --arg status "success" \
    --arg profile "itest-layer-base" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/last.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-layer-base" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
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
  local check_dir
  local remote_file
  local journal_path

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
rm -f "${MULTI_SUCCESS_TEMPLATE_DEST}" "${MULTI_SUCCESS_FIREWALL_DEST}"
systemctl restart nftables
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  echo "== itest scenario: apply-no-local-rollback =="
  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.yaml" \
    --report-format yaml \
    --debug

  ensure_file "${dir}/apply.log"
  grep -q "kind: hardline_plan" "${dir}/apply-plan.yaml" || fail "unexpected yaml apply report"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-success.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-success.conf \
    etc/nftables.d/99-hardline-itest-success.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch success profile files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-success.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "success profile template mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-success.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${MULTI_SUCCESS_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall table"; }
  grep -F -q 'tcp dport 2222 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall tcp rule"; }
  grep -F -q 'udp dport 5353 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall udp rule"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  ssh_cmd "sudo cat ${REMOTE_JOURNAL}" | jq -er \
    --arg status "success" \
    --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/last.json"
  test ! -e "${journal_path}" || fail "expected local rollback journal to be removed: ${journal_path}"

  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d
  ensure_file "${dir}/rollback.log"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
}

scenario_rollback_last() {
  local dir="${ARTIFACT_ROOT}/rollback-last"

  run_success_apply
  reset_dir "${dir}"

  echo "== itest scenario: rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d

  ensure_file "${dir}/rollback.log"
  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
}

scenario_package_rollback_last() {
  local dir="${ARTIFACT_ROOT}/package-rollback-last"

  run_package_rollback_apply "${dir}/apply"
  reset_dir "${dir}/rollback"

  echo "== itest scenario: package-rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback/rollback.log" -d

  ensure_file "${dir}/rollback/rollback.log"
  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
! dpkg -s "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1
test ! -e "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF
}

scenario_layered_rollback_last() {
  local dir="${ARTIFACT_ROOT}/layered-rollback-last"
  local check_dir
  local remote_file

  reset_dir "${dir}"
  run_layer_base_apply "${dir}/layer-base-apply"
  run_success_apply "${dir}/multi-success-apply"

  echo "== itest scenario: layered-rollback-last =="
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d

  ensure_file "${dir}/rollback.log"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch layered rollback files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "layer base template mismatch after rollback"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall table after rollback"; }
  grep -F -q 'tcp dport 2023 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall tcp rule after rollback"; }
  grep -F -q 'udp dport 5355 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall udp rule after rollback"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  run_layer_base_apply "${dir}/layer-base-reapply"
  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/cleanup-rollback.log" -d
  ensure_file "${dir}/cleanup-rollback.log"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${LAYER_BASE_TEMPLATE_DEST}"
test ! -e "${LAYER_BASE_FIREWALL_DEST}"
! nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
}

scenario_force_rollback_apply() {
  run_failure_apply
}

scenario_layered_force_rollback() {
  local dir="${ARTIFACT_ROOT}/layered-force-rollback"
  local check_dir
  local remote_file

  reset_dir "${dir}"
  run_layer_base_apply "${dir}/layer-base-apply"
  run_failure_apply "${dir}/forced-failure"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch layered force-rollback files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"
    fail "layer base template mismatch after forced rollback"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall table after forced rollback"; }
  grep -F -q 'tcp dport 2023 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall tcp rule after forced rollback"; }
  grep -F -q 'udp dport 5355 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall udp rule after forced rollback"; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_FAILURE_TEMPLATE_DEST}"
test ! -e "${MULTI_FAILURE_FIREWALL_DEST}"
test ! -e "${FAILURE_DEST}"
! nft list table inet "${MULTI_FAILURE_FIREWALL_TABLE}" >/dev/null 2>&1
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
/usr/sbin/sshd -t
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF

  ssh_cmd "sudo cat ${REMOTE_JOURNAL}" | jq -er \
    --arg status "success" \
    --arg profile "itest-layer-base" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  "${BINARY_PATH}" rollback last "${short_remote_args[@]}" --log-file "${dir}/cleanup-rollback.log" -d
  ensure_file "${dir}/cleanup-rollback.log"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${LAYER_BASE_TEMPLATE_DEST}"
test ! -e "${LAYER_BASE_FIREWALL_DEST}"
! nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf
nft -c -f /etc/nftables.conf >/dev/null 2>&1
EOF
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

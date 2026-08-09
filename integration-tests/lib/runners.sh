#!/usr/bin/env bash
# =============================================================================
# runners.sh — Base bootstrap and shared apply/rollback runners
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# Requires: all variables from itest.sh (BINARY_PATH, remote_args, etc.)

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
    jq -er --arg id "${BASE_PROFILE_ID}" '.kind == "hardline_plan" and .profile.id == $id' \
      "${dir}/apply-plan.json" >/dev/null || fail "unexpected base bootstrap report contents"
    ssh_cmd "sudo mkdir -p /var/lib/hardline && printf '%s\n' '${base_manifest_sha}' | sudo tee ${quoted_marker} >/dev/null"
  fi

  echo "== itest verify: base server state =="
  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-base.XXXXXX")"

  # Fetch every managed file this target's starter profile writes, plus the
  # firewall drop-in, in one tar stream.
  local fetch_paths=("etc/nftables.d/99-hardline-firewall.nft")
  local entry remote_rel template mode
  for entry in "${BASE_FILE_CHECKS[@]}"; do
    fetch_paths+=("${entry%%|*}")
  done
  ssh_cmd "sudo tar -C / -cf - ${fetch_paths[*]}" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"
    fail "failed to fetch base profile files"
  }

  for entry in "${BASE_FILE_CHECKS[@]}"; do
    remote_rel="${entry%%|*}"
    template="${entry#*|}"; template="${template%%|*}"
    mode="${entry##*|}"
    remote_file="${check_dir}/${remote_rel}"
    test "$(stat -c %a "${remote_file}")" = "${mode}" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
    cmp -s "${BASE_PROFILE}/${template}" "${remote_file}" || {
      diff -u "${BASE_PROFILE}/${template}" "${remote_file}" || true
      rm -rf "${check_dir}"; fail "remote ${remote_rel} mismatch"
    }
  done

  # Firewall rules: mode 0644, content checks (identical across targets)
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

  # Package and service checks. The package query and unit names come from
  # os.sh; the sysctl and nftables assertions are target-independent.
  {
    echo 'set -euo pipefail'
    for entry in "${BASE_PKGS_PRESENT[@]}"; do pkg_installed_test "${entry}"; echo; done
    for entry in "${BASE_PKGS_ABSENT[@]}"; do pkg_absent_test "${entry}"; echo; done
    for entry in "${BASE_UNITS_RUNNING[@]}"; do
      echo "systemctl is-enabled '${entry}' >/dev/null 2>&1"
      echo "systemctl is-active '${entry}' >/dev/null 2>&1"
    done
    # An automatic-update timer that is installed but not scheduled applies no
    # updates, so the timer itself is asserted rather than only its package.
    for entry in "${BASE_TIMERS_ENABLED[@]}"; do
      echo "systemctl is-enabled '${entry}' >/dev/null 2>&1"
      echo "systemctl is-active '${entry}' >/dev/null 2>&1"
    done
    cat <<'INNER'
/usr/sbin/sshd -t
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
INNER
    nft_include_test
    echo
    echo "nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1"
  } | ssh_cmd "sudo bash -se"
}

# ─── Shared apply runners ───────────────────────────────────────────────────

run_success_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/apply-keep-local-rollback}"
  local check_dir remote_file journal_path

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
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF

  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' \
    "${dir}/apply-plan.json" >/dev/null || fail "unexpected apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-success.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-success.conf \
    etc/nftables.d/99-hardline-itest-success.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; fail "failed to fetch success profile files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-success.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"; fail "success profile template mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-success.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${MULTI_SUCCESS_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall table"; }
  grep -F -q 'tcp dport 2222 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall tcp rule"; }
  grep -F -q 'udp dport 5353 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing success firewall udp rule"; }
  rm -rf "${check_dir}"

  if ! ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF
  then fail "success apply did not load firewall/nftables state"; fi

  local remote_jpath
  remote_jpath="$(remote_journal_latest itest-multi-plugin-success)"
  ssh_cmd "sudo cat ${remote_jpath}" | jq -er \
    --arg status "success" \
    --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/itest-multi-plugin-success.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
  jq -er '.checksum | type == "string" and length > 0' \
    "${journal_path}" >/dev/null || fail "local rollback journal missing checksum: ${journal_path}"
  local remote_checksum
  remote_checksum="$(ssh_cmd "sudo cat ${remote_jpath}" | jq -er '.checksum')" || fail "remote rollback journal missing checksum"
  test -n "${remote_checksum}" || fail "remote rollback journal checksum is empty"
}

run_failure_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/force-rollback-apply}"
  local journal_path status

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
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF

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

  journal_path="${STATE_DIR}/${host}/itest-multi-plugin-force-rollback.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "failed" \
    --arg profile "itest-multi-plugin-force-rollback" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"

  if ! ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_FAILURE_TEMPLATE_DEST}"
test ! -e "${MULTI_FAILURE_FIREWALL_DEST}"
test ! -e "${FAILURE_DEST}"
systemctl restart nftables
! nft list table inet "${MULTI_FAILURE_FIREWALL_TABLE}" >/dev/null 2>&1
/usr/sbin/sshd -t
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF
  then fail "forced rollback did not restore clean remote state"; fi
}

run_package_rollback_apply() {
  local dir="${1:-${ARTIFACT_ROOT}/package-rollback-apply}"
  local check_dir remote_file journal_path

  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"

  # The static package-rollback profile declares backend=apt, so this runner is
  # Ubuntu-only and its assertions stay apt-specific on purpose.
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

  "${BINARY_PATH}" apply "${PACKAGE_ROLLBACK_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-package-rollback"' \
    "${dir}/apply-plan.json" >/dev/null || fail "unexpected package rollback apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-package.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - etc/hardline.d/99-hardline-itest-package-rollback.conf" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; fail "failed to fetch package rollback files"
  }
  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-package-rollback.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${PACKAGE_ROLLBACK_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${PACKAGE_ROLLBACK_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"; fail "package rollback template mismatch"
  }
  rm -rf "${check_dir}"

  if ! ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
dpkg -s "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF
  then fail "package apply did not install package or nftables not running"; fi

  local remote_jpath
  remote_jpath="$(remote_journal_latest itest-package-rollback)"
  ssh_cmd "sudo cat ${remote_jpath}" | jq -er \
    --arg status "success" \
    --arg profile "itest-package-rollback" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/itest-package-rollback.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-package-rollback" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
}

run_layer_base_apply() {
  local dir="${1:?artifact directory required}"
  local check_dir remote_file journal_path

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
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF

  "${BINARY_PATH}" apply "${LAYER_BASE_PROFILE}" "${remote_args[@]}" \
    --keep-local-rollback \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.json" \
    --report-format json \
    --debug

  ensure_file "${dir}/apply.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-layer-base"' \
    "${dir}/apply-plan.json" >/dev/null || fail "unexpected layer base apply report contents"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; fail "failed to fetch layer base files"
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    diff -u "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || true
    rm -rf "${check_dir}"; fail "layer base template mismatch"
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; fail "unexpected mode for ${remote_file}"; }
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall table"; }
  grep -F -q 'tcp dport 2023 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall tcp rule"; }
  grep -F -q 'udp dport 5355 accept' "${remote_file}" || { rm -rf "${check_dir}"; fail "missing layer base firewall udp rule"; }
  rm -rf "${check_dir}"

  if ! ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
$(nft_include_test)
nft -c -f ${NFT_MAIN_CONFIG} >/dev/null 2>&1
EOF
  then fail "layer-base apply did not load firewall/nftables state"; fi

  local remote_jpath
  remote_jpath="$(remote_journal_latest itest-layer-base)"
  ssh_cmd "sudo cat ${remote_jpath}" | jq -er \
    --arg status "success" \
    --arg profile "itest-layer-base" \
    '.status == $status and .profile_id == $profile' >/dev/null || fail "unexpected remote rollback journal contents"

  journal_path="${STATE_DIR}/${host}/itest-layer-base.json"
  test -f "${journal_path}" || fail "missing local rollback journal: ${journal_path}"
  jq -er \
    --arg status "success" \
    --arg profile "itest-layer-base" \
    '.status == $status and .profile_id == $profile' \
    "${journal_path}" >/dev/null || fail "unexpected local rollback journal contents: ${journal_path}"
}

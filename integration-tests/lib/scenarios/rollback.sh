#!/usr/bin/env bash
# =============================================================================
# rollback.sh — All rollback and journal scenarios (13 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── 15. rollback-last ────────────────────────────────────────────────────────
scenario_rollback_last() {
  local dir="${ARTIFACT_ROOT}/rollback-last"
  scenario_start "rollback-last: apply multi-plugin then rollback"

  run_success_apply
  reset_dir "${dir}"

  "${BINARY_PATH}" rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/rollback.log" -d
  ensure_file "${dir}/rollback.log"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
systemctl restart nftables
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
systemctl is-enabled ssh >/dev/null 2>&1
systemctl is-active ssh >/dev/null 2>&1
systemctl is-enabled nftables >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF
  scenario_pass
}

# ── 16. package-rollback-last ────────────────────────────────────────────────
scenario_package_rollback_last() {
  local dir="${ARTIFACT_ROOT}/package-rollback-last"
  scenario_start "package-rollback-last: rollback purges installed package"

  run_package_rollback_apply "${dir}/apply"
  reset_dir "${dir}/rollback"

  "${BINARY_PATH}" rollback "${PACKAGE_ROLLBACK_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/rollback/rollback.log" -d
  ensure_file "${dir}/rollback/rollback.log"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
! dpkg -s "${PACKAGE_ROLLBACK_PACKAGE}" >/dev/null 2>&1
test ! -e "${PACKAGE_ROLLBACK_TEMPLATE_DEST}"
EOF
  scenario_pass
}

# ── 17. layered-rollback-last ────────────────────────────────────────────────
scenario_layered_rollback_last() {
  local dir="${ARTIFACT_ROOT}/layered-rollback-last"
  local check_dir remote_file
  reset_dir "${dir}"
  scenario_start "layered-rollback-last: rollback top layer, bottom survives"

  run_layer_base_apply "${dir}/layer-base-apply"
  run_success_apply "${dir}/multi-success-apply"

  "${BINARY_PATH}" rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/rollback.log" -d
  ensure_file "${dir}/rollback.log"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; scenario_fail "failed to fetch layered rollback files"; return
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; scenario_fail "bad mode"; return; }
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    rm -rf "${check_dir}"; scenario_fail "layer base template mismatch after rollback"; return
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; scenario_fail "missing layer base fw table"; return; }
  grep -F -q 'tcp dport 2023 accept' "${remote_file}" || { rm -rf "${check_dir}"; scenario_fail "missing layer base tcp rule"; return; }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
systemctl restart nftables
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
EOF

  # Cleanup: rollback layer-base too
  run_layer_base_apply "${dir}/layer-base-reapply"
  "${BINARY_PATH}" rollback "${LAYER_BASE_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/cleanup-rollback.log" -d

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${LAYER_BASE_TEMPLATE_DEST}"
test ! -e "${LAYER_BASE_FIREWALL_DEST}"
systemctl restart nftables
! nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
EOF
  scenario_pass
}

# ── 18. force-rollback-apply ─────────────────────────────────────────────────
scenario_force_rollback_apply() {
  scenario_start "force-rollback-apply: bad SSH config triggers auto-rollback"
  run_failure_apply
  scenario_pass
}

# ── 19. layered-force-rollback ───────────────────────────────────────────────
scenario_layered_force_rollback() {
  local dir="${ARTIFACT_ROOT}/layered-force-rollback"
  local check_dir remote_file
  reset_dir "${dir}"
  scenario_start "layered-force-rollback: bottom layer survives auto-rollback"

  run_layer_base_apply "${dir}/layer-base-apply"
  run_failure_apply "${dir}/forced-failure"

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-layer.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-layer-base.conf \
    etc/nftables.d/99-hardline-itest-layer-base.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; scenario_fail "failed to fetch layered force-rollback files"; return
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-layer-base.conf"
  cmp -s "${LAYER_BASE_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    rm -rf "${check_dir}"; scenario_fail "layer base template mismatch"; return
  }
  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-layer-base.nft"
  grep -F -q "table inet ${LAYER_BASE_FIREWALL_TABLE} {" "${remote_file}" || {
    rm -rf "${check_dir}"; scenario_fail "missing layer base fw table"; return
  }
  rm -rf "${check_dir}"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_FAILURE_TEMPLATE_DEST}"
test ! -e "${MULTI_FAILURE_FIREWALL_DEST}"
test ! -e "${FAILURE_DEST}"
systemctl restart nftables
! nft list table inet "${MULTI_FAILURE_FIREWALL_TABLE}" >/dev/null 2>&1
nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
/usr/sbin/sshd -t
EOF

  # Cleanup
  "${BINARY_PATH}" rollback "${LAYER_BASE_PROFILE}" "${short_remote_args[@]}" \
    --log-file "${dir}/cleanup-rollback.log" -d

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${LAYER_BASE_TEMPLATE_DEST}"
test ! -e "${LAYER_BASE_FIREWALL_DEST}"
systemctl restart nftables
! nft list table inet "${LAYER_BASE_FIREWALL_TABLE}" >/dev/null 2>&1
EOF
  scenario_pass
}

# ── 20. auto-rollback-synthetic ──────────────────────────────────────────────
scenario_auto_rollback_synthetic() {
  scenario_start "auto-rollback-synthetic: nonexistent service triggers rollback of template"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-auto-rb.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_with_failing_step "auto-rollback" "${dest}" "RollbackTestContent=yes")

  local ec
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?

  if [[ $ec -eq 0 ]]; then
    scenario_fail "apply should have failed but exited 0"
    return
  fi

  if ssh_cmd "test -f ${dest}" 2>/dev/null; then
    scenario_fail "file from step 1 still exists after auto-rollback"
  else
    scenario_pass
  fi
}

# ── 21. manual-rollback ─────────────────────────────────────────────────────
scenario_manual_rollback() {
  scenario_start "manual-rollback: apply then rollback removes file"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-manual-rb.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_template "manual-rollback" "${dest}" "ManualRollbackTest=yes")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1
  if ! ssh_cmd "test -f ${dest}" 2>/dev/null; then
    scenario_fail "file not created by apply"
    return
  fi

  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "rollback command failed: ${ec}"
    return
  fi

  if ssh_cmd "test -f ${dest}" 2>/dev/null; then
    scenario_fail "file still exists after rollback"
  else
    scenario_pass
  fi
}

# ── 22. rollback-no-journal ──────────────────────────────────────────────────
scenario_rollback_no_journal() {
  scenario_start "rollback-no-journal: fails gracefully when no journal exists"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_template "no-journal" "/etc/hardline.d/99-hardline-no-journal.conf" "NoJournalTest=yes")
  # Clear any remote journal for this profile
  ssh_cmd "sudo rm -rf /var/lib/hardline/runs/no-journal" 2>/dev/null || true

  local ec
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?

  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "rollback should fail when no journal exists"
  fi
}

# ── 23. local-journal-on-failure ─────────────────────────────────────────────
scenario_local_journal_on_failure() {
  scenario_start "local-journal-on-failure: local journal created + valid JSON"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-journal-fail.conf"
  ssh_cmd "sudo rm -f ${dest}"
  rm -rf "${STATE_DIR:?}"/*
  local pdir
  pdir=$(make_profile_with_failing_step "journal-fail" "${dest}" "JournalTest=yes")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || true

  local journal_files
  journal_files=$(find "${STATE_DIR}" -name "*.json" 2>/dev/null | head -5)
  if [[ -n "${journal_files}" ]]; then
    local first_journal
    first_journal=$(echo "${journal_files}" | head -1)
    if jq . "${first_journal}" >/dev/null 2>&1; then
      scenario_pass
    else
      scenario_fail "journal file exists but is not valid JSON"
    fi
  else
    scenario_fail "no local journal file found in ${STATE_DIR}"
  fi
}

# ── 24. remote-journal-on-success ────────────────────────────────────────────
scenario_remote_journal_on_success() {
  scenario_start "remote-journal-on-success: remote journal written after success"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-rj-success.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_template "rj-success" "${dest}" "RemoteJournalTest=yes")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    return
  fi

  local rj_exists
  rj_exists=$(ssh_cmd "sudo find /var/lib/hardline/runs -name '*.json' 2>/dev/null | head -1" | tr -d '\r\n')
  if [[ -n "${rj_exists}" ]]; then
    scenario_pass
  else
    scenario_fail "no remote journal found"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── 25. journal-checksum ────────────────────────────────────────────────────
scenario_journal_checksum() {
  scenario_start "journal-checksum: local and remote journals contain checksum"

  # This uses the state from apply-keep-local-rollback (run_success_apply)
  run_success_apply

  local journal_path="${STATE_DIR}/${host}/itest-multi-plugin-success.json"
  if ! jq -er '.checksum | type == "string" and length > 0' "${journal_path}" >/dev/null 2>&1; then
    scenario_fail "local journal missing checksum"
    return
  fi

  local remote_jpath
  remote_jpath="$(remote_journal_latest itest-multi-plugin-success)"
  local remote_checksum
  remote_checksum="$(ssh_cmd "sudo cat ${remote_jpath}" | jq -er '.checksum')" || {
    scenario_fail "remote journal missing checksum"
    return
  }

  if [[ -n "${remote_checksum}" ]]; then
    scenario_pass
  else
    scenario_fail "remote checksum is empty"
  fi
}

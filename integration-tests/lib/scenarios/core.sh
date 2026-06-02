#!/usr/bin/env bash
# =============================================================================
# core.sh — CLI, plan, apply, and smoke scenarios (14 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── 1. version ───────────────────────────────────────────────────────────────
scenario_version() {
  local dir="${ARTIFACT_ROOT}/version"
  reset_dir "${dir}"
  scenario_start "version: version + -v output"

  "${BINARY_PATH}" version >"${dir}/version.txt" 2>&1
  "${BINARY_PATH}" -v >"${dir}/version-short.txt" 2>&1

  if grep -q "hardline version" "${dir}/version.txt" && \
     grep -q "hardline version" "${dir}/version-short.txt"; then
    scenario_pass
  else
    scenario_fail "version command output missing expected text"
  fi
}

# ── 2. verify-profile + vp alias ─────────────────────────────────────────────
scenario_verify() {
  local dir="${ARTIFACT_ROOT}/verify"
  reset_dir "${dir}"
  scenario_start "verify: verify-profile and vp alias"

  "${BINARY_PATH}" verify-profile "${PROFILE_DIR}" --log-file "${dir}/verify.log"
  "${BINARY_PATH}" vp "${PROFILE_DIR}" --log-file "${dir}/vp.log" --debug

  if [ -s "${dir}/verify.log" ] && [ -s "${dir}/vp.log" ]; then
    scenario_pass
  else
    scenario_fail "verify log files missing or empty"
  fi
}

# ── 3. verify-unsigned ───────────────────────────────────────────────────────
scenario_verify_unsigned() {
  scenario_start "verify-unsigned: rejects unsigned profile"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/unsigned"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "unsigned-test", "display_name": "Unsigned Test", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-pkg.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "packages", "config": { "install": ["tree"] } }] }
EOJSON
  # No signing — should fail
  local ec
  "${BINARY_PATH}" verify-profile "${dir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted unsigned profile"
  fi
}

# ── 4. verify-tampered ───────────────────────────────────────────────────────
scenario_verify_tampered() {
  scenario_start "verify-tampered: rejects tampered profile"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/tampered"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "tampered-test", "display_name": "Tampered Test", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-pkg.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "packages", "config": { "install": ["tree"] } }] }
EOJSON
  sign_profile "${dir}"
  # Tamper after signing
  sed -i 's/Tampered Test/HACKED PROFILE/' "${dir}/profile.json"

  local ec
  "${BINARY_PATH}" verify-profile "${dir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted tampered profile"
  fi
}

# ── 5. plan-reports ──────────────────────────────────────────────────────────
scenario_plan_reports() {
  local dir="${ARTIFACT_ROOT}/plan-reports"
  reset_dir "${dir}"
  scenario_start "plan-reports: JSON/YAML/MD formats with long and short flags"

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

  local ok=true
  ensure_file "${dir}/plan-long.log"
  ensure_file "${dir}/plan-short.log"
  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' \
    "${dir}/plan-auto.json" >/dev/null || { scenario_fail "unexpected json plan report"; return; }
  grep -q "kind: hardline_plan" "${dir}/plan-explicit.yaml" || { scenario_fail "unexpected yaml plan report"; return; }
  grep -q "^# Hardline Plan Report" "${dir}/plan.md" || { scenario_fail "unexpected markdown plan report"; return; }
  scenario_pass
}

# ── 6. plan-readonly ────────────────────────────────────────────────────────
scenario_plan_readonly() {
  scenario_start "plan-readonly: plan does not modify remote host"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-plan-readonly-test.conf"
  local pdir
  pdir=$(make_profile_template "plan-readonly" "${dest}" "PlanReadOnlyTest=true")
  ssh_cmd "sudo rm -f ${dest}"

  "${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" >/dev/null 2>&1

  if ssh_cmd "test -f ${dest}" 2>/dev/null; then
    scenario_fail "plan created file on remote host"
  else
    scenario_pass
  fi
}

# ── 7. plan-idempotent ──────────────────────────────────────────────────────
scenario_plan_idempotent() {
  scenario_start "plan-idempotent: second plan shows already aligned"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-plan-idem.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_template "plan-idempotent" "${dest}" "IdempotencyTest=yes")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local plan_out
  plan_out=$("${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" 2>&1) || true

  if echo "${plan_out}" | grep -qiE '(already aligned|no change|aligned)'; then
    scenario_pass
  else
    scenario_fail "second plan did not report aligned state"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── 8. plan-diff-output ─────────────────────────────────────────────────────
scenario_plan_diff_output() {
  local dir="${ARTIFACT_ROOT}/plan-diff"
  reset_dir "${dir}"
  scenario_start "plan-diff-output: plan JSON contains diff entries"

  "${BINARY_PATH}" plan "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --report-file "${dir}/plan.json" \
    --report-format json >/dev/null 2>&1

  # Plan report should contain steps with diffs
  if jq -er '.steps | length > 0' "${dir}/plan.json" >/dev/null 2>&1; then
    scenario_pass
  else
    scenario_fail "plan JSON has no steps"
  fi
}

# ── 9. smoke ─────────────────────────────────────────────────────────────────
scenario_smoke() {
  scenario_start "smoke: basic plan + apply"
  "${BINARY_PATH}" plan "${PROFILE_DIR}" "${remote_args[@]}"
  "${BINARY_PATH}" apply "${PROFILE_DIR}" "${remote_args[@]}"
  scenario_pass
}

# ── 10. apply-template ──────────────────────────────────────────────────────
scenario_apply_template() {
  scenario_start "apply-template: deploys file with correct content and perms"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-apply-template.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local content="# Apply template test\nHardeningLevel=strict"
  local pdir
  pdir=$(make_profile_template "apply-template" "${dest}" "${content}" "0600")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply exited non-zero: ${ec}"
    return
  fi

  local remote_content remote_perms
  remote_content=$(ssh_cmd "sudo cat ${dest}" 2>/dev/null)
  remote_perms=$(ssh_cmd "sudo stat -c '%a' ${dest}" 2>/dev/null | tr -d '\r\n')

  if [[ "${remote_content}" == *"HardeningLevel=strict"* && "${remote_perms}" == "600" ]]; then
    scenario_pass
  else
    scenario_fail "content or perms wrong (perms=${remote_perms})"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── 11. apply-package ───────────────────────────────────────────────────────
scenario_apply_package() {
  scenario_start "apply-package: installs cowsay via packages plugin"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  ssh_cmd "sudo apt-get purge -y cowsay 2>/dev/null" >/dev/null 2>&1 || true
  local pdir
  pdir=$(make_profile_packages_install "apply-package" "cowsay")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply exited non-zero: ${ec}"
    return
  fi

  if ssh_cmd "dpkg -l cowsay 2>/dev/null | grep -q '^ii'" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "package cowsay not installed after apply"
  fi
  ssh_cmd "sudo apt-get purge -y cowsay" >/dev/null 2>&1 || true
}

# ── 12. apply-keep-local-rollback ───────────────────────────────────────────
scenario_apply_keep_local_rollback() {
  scenario_start "apply-keep-local-rollback: multi-plugin apply, local journal kept"
  run_success_apply
  scenario_pass
}

# ── 13. apply-no-local-rollback ─────────────────────────────────────────────
scenario_apply_no_local_rollback() {
  local dir="${ARTIFACT_ROOT}/apply-no-local-rollback"
  local check_dir remote_file journal_path
  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"
  mkdir -p "${STATE_DIR}"
  scenario_start "apply-no-local-rollback: local journal removed, then rollback"

  ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
rm -f "${MULTI_SUCCESS_TEMPLATE_DEST}" "${MULTI_SUCCESS_FIREWALL_DEST}"
systemctl restart nftables
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
EOF

  "${BINARY_PATH}" apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --log-file "${dir}/apply.log" \
    --report-file "${dir}/apply-plan.yaml" \
    --report-format yaml \
    --debug

  ensure_file "${dir}/apply.log"
  grep -q "kind: hardline_plan" "${dir}/apply-plan.yaml" || { scenario_fail "unexpected yaml apply report"; return; }

  check_dir="$(mktemp -d "${ROOT_DIR}/tmp/itest-success.XXXXXX")"
  ssh_cmd "sudo tar -C / -cf - \
    etc/hardline.d/99-hardline-itest-success.conf \
    etc/nftables.d/99-hardline-itest-success.nft" | tar -C "${check_dir}" -xf - || {
    rm -rf "${check_dir}"; scenario_fail "failed to fetch success profile files"; return
  }

  remote_file="${check_dir}/etc/hardline.d/99-hardline-itest-success.conf"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; scenario_fail "unexpected mode"; return; }
  cmp -s "${MULTI_SUCCESS_PROFILE}/templates/10-managed.conf.tmpl" "${remote_file}" || {
    rm -rf "${check_dir}"; scenario_fail "template mismatch"; return
  }

  remote_file="${check_dir}/etc/nftables.d/99-hardline-itest-success.nft"
  test "$(stat -c %a "${remote_file}")" = "644" || { rm -rf "${check_dir}"; scenario_fail "unexpected fw mode"; return; }
  grep -F -q "table inet ${MULTI_SUCCESS_FIREWALL_TABLE} {" "${remote_file}" || { rm -rf "${check_dir}"; scenario_fail "missing fw table"; return; }
  rm -rf "${check_dir}"

  local remote_jpath
  remote_jpath="$(remote_journal_latest itest-multi-plugin-success)"
  ssh_cmd "sudo cat ${remote_jpath}" | jq -er \
    --arg status "success" --arg profile "itest-multi-plugin-success" \
    '.status == $status and .profile_id == $profile' >/dev/null || { scenario_fail "bad remote journal"; return; }

  journal_path="${STATE_DIR}/${host}/itest-multi-plugin-success.json"
  test ! -e "${journal_path}" || { scenario_fail "local journal should be removed: ${journal_path}"; return; }

  "${BINARY_PATH}" rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" --log-file "${dir}/rollback.log" -d
  ensure_file "${dir}/rollback.log"

  if ! ssh_cmd "sudo bash -se" <<EOF
set -euo pipefail
test ! -e "${MULTI_SUCCESS_TEMPLATE_DEST}"
test ! -e "${MULTI_SUCCESS_FIREWALL_DEST}"
# Restart nftables so the removed config file is no longer loaded
systemctl restart nftables
! nft list table inet "${MULTI_SUCCESS_FIREWALL_TABLE}" >/dev/null 2>&1
EOF
  then scenario_fail "remote state wrong after rollback"; return; fi

  scenario_pass
}

# ── 14. apply-concurrent ────────────────────────────────────────────────────
scenario_apply_concurrent() {
  scenario_start "apply-concurrent: parallel applies do not crash or corrupt"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local c1_dest="/etc/hardline.d/99-hardline-concurrent-a.conf"
  local c2_dest="/etc/hardline.d/99-hardline-concurrent-b.conf"
  ssh_cmd "sudo rm -f ${c1_dest} ${c2_dest}"

  local c1_dir c2_dir
  c1_dir=$(make_profile_template "concurrent-a" "${c1_dest}" "ConcurrentA=yes")
  c2_dir=$(make_profile_template "concurrent-b" "${c2_dest}" "ConcurrentB=yes")

  local dir="${ARTIFACT_ROOT}/concurrent"
  reset_dir "${dir}"

  "${BINARY_PATH}" apply "${c1_dir}" "${remote_args[@]}" >"${dir}/a.log" 2>&1 &
  local pid_a=$!
  "${BINARY_PATH}" apply "${c2_dir}" "${remote_args[@]}" >"${dir}/b.log" 2>&1 &
  local pid_b=$!

  local ec_a ec_b
  wait $pid_a && ec_a=0 || ec_a=$?
  wait $pid_b && ec_b=0 || ec_b=$?

  local panics=0
  for logf in "${dir}/a.log" "${dir}/b.log"; do
    if grep -qiE '(panic|segfault|SIGSEGV|fatal)' "${logf}" 2>/dev/null; then
      panics=$((panics + 1))
    fi
  done

  if [[ $panics -gt 0 ]]; then
    scenario_fail "panic/crash detected during concurrent apply"
  elif [[ $ec_a -eq 0 || $ec_b -eq 0 ]]; then
    scenario_pass
  else
    scenario_fail "both concurrent applies failed (a=${ec_a}, b=${ec_b})"
  fi
  ssh_cmd "sudo rm -f ${c1_dest} ${c2_dest}" 2>/dev/null || true
}

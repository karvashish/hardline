#!/usr/bin/env bash
# =============================================================================
# 70-rollback.sh — rollback + auto-rollback over the static multi-plugin / SSH
#                  profiles, driven by the rigorous runners in lib/runners.sh.
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── multi-plugin-rollback: apply (template + external firewall) then roll back
scenario_multi_plugin_rollback() {
  local dir="${ARTIFACT_ROOT}/multi-plugin-rollback"
  reset_dir "${dir}"
  scenario_start "multi-plugin-rollback: apply multi-plugin-success then rollback reverts everything"
  guard_static_profiles || return

  if ! ( run_success_apply "${dir}/apply" ); then
    note_fail "multi-plugin-success apply/verification failed"
    scenario_end; return
  fi
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "all multi-plugin artifacts reverted, ssh+nftables healthy" <<EOF
test ! -e ${MULTI_SUCCESS_TEMPLATE_DEST}
test ! -e ${MULTI_SUCCESS_FIREWALL_DEST}
systemctl restart nftables
if nft list table inet ${MULTI_SUCCESS_FIREWALL_TABLE} >/dev/null 2>&1; then exit 1; fi
systemctl is-active ${SSH_UNIT} >/dev/null 2>&1
systemctl is-active nftables >/dev/null 2>&1
EOF
  scenario_end
}

# ── auto-rollback-on-failure: a bad sshd drop-in triggers automatic rollback ─
#    run_failure_apply verifies "automatic rollback completed", artifacts gone,
#    sshd -t valid, and a local journal with status=failed.
scenario_auto_rollback_on_failure() {
  scenario_start "auto-rollback-on-failure: bad sshd config auto-rolls-back; failed journal recorded"
  guard_static_profiles || return
  if ( run_failure_apply "${ARTIFACT_ROOT}/auto-rollback-on-failure" ); then
    scenario_pass
  else
    note_fail "forced-failure apply did not auto-rollback as expected"
    scenario_end
  fi
}

# ── layered-rollback: rollback the top layer; the base layer survives ────────
scenario_layered_rollback() {
  local dir="${ARTIFACT_ROOT}/layered-rollback"
  reset_dir "${dir}"
  scenario_start "layered-rollback: rollback top layer (multi-success), base layer (layer-base) survives"
  guard_static_profiles || return

  if ! ( run_layer_base_apply "${dir}/layer-base-apply" ) || ! ( run_success_apply "${dir}/multi-success-apply" ); then
    note_fail "layered apply setup failed"; scenario_end; return
  fi
  must_hl "${dir}/rollback.log" "rollback top layer" -- rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "top layer reverted, base layer intact" <<EOF
test "\$(stat -c %a ${LAYER_BASE_TEMPLATE_DEST})" = "644"
test ! -e ${MULTI_SUCCESS_TEMPLATE_DEST}
test ! -e ${MULTI_SUCCESS_FIREWALL_DEST}
systemctl restart nftables
if nft list table inet ${MULTI_SUCCESS_FIREWALL_TABLE} >/dev/null 2>&1; then exit 1; fi
nft list table inet ${LAYER_BASE_FIREWALL_TABLE} >/dev/null 2>&1
grep -q 'tcp dport 2023 accept' ${LAYER_BASE_FIREWALL_DEST}
EOF

  # Cleanup: re-apply layer-base (success-apply wiped its local journal) and roll it back.
  ( run_layer_base_apply "${dir}/layer-base-reapply" ) || note_fail "layer-base re-apply for cleanup failed"
  must_hl "${dir}/cleanup.log" "rollback base layer" -- rollback "${LAYER_BASE_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "base layer reverted on cleanup" <<EOF
test ! -e ${LAYER_BASE_TEMPLATE_DEST}
test ! -e ${LAYER_BASE_FIREWALL_DEST}
systemctl restart nftables
if nft list table inet ${LAYER_BASE_FIREWALL_TABLE} >/dev/null 2>&1; then exit 1; fi
EOF
  scenario_end
}

# ── layered-auto-rollback: an auto-rollback leaves the base layer untouched ──
scenario_layered_auto_rollback() {
  local dir="${ARTIFACT_ROOT}/layered-auto-rollback"
  reset_dir "${dir}"
  scenario_start "layered-auto-rollback: forced-failure auto-rollback keeps the base layer"
  guard_static_profiles || return

  if ! ( run_layer_base_apply "${dir}/layer-base-apply" ); then
    note_fail "layer-base apply setup failed"; scenario_end; return
  fi
  if ! ( run_failure_apply "${dir}/forced-failure" ); then
    note_fail "forced-failure apply did not auto-rollback as expected"; scenario_end; return
  fi
  must_remote "base layer intact after auto-rollback of top failure" <<EOF
test "\$(stat -c %a ${LAYER_BASE_TEMPLATE_DEST})" = "644"
nft list table inet ${LAYER_BASE_FIREWALL_TABLE} >/dev/null 2>&1
test ! -e ${MULTI_FAILURE_TEMPLATE_DEST}
test ! -e ${MULTI_FAILURE_FIREWALL_DEST}
test ! -e ${FAILURE_DEST}
/usr/sbin/sshd -t
EOF

  # Cleanup: roll back layer-base.
  ( run_layer_base_apply "${dir}/layer-base-reapply" ) || note_fail "layer-base re-apply for cleanup failed"
  must_hl "${dir}/cleanup.log" "rollback base layer" -- rollback "${LAYER_BASE_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "base layer reverted on cleanup" <<EOF
test ! -e ${LAYER_BASE_TEMPLATE_DEST}
systemctl restart nftables
if nft list table inet ${LAYER_BASE_FIREWALL_TABLE} >/dev/null 2>&1; then exit 1; fi
EOF
  scenario_end
}

# ── ssh-reload-rollback: rollback reverts the sshd drop-in and reloads sshd ──
scenario_ssh_reload_rollback() {
  local dir="${ARTIFACT_ROOT}/ssh-reload-rollback"
  reset_dir "${dir}"
  scenario_start "ssh-reload-rollback: rollback reverts ssh drop-in and re-runs the sshd reload (observed via systemd)"
  guard_static_profiles || return

  must_hl "${dir}/apply.log" "apply ssh-reload profile" -- apply "${SSH_RELOAD_PROFILE}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }
  ssh_cmd "test -f ${SSH_RELOAD_DEST}" || { note_fail "ssh drop-in not deployed by apply"; scenario_end; return; }

  # Observe sshd directly across the rollback rather than reading hardline's log.
  local mark0 cur; mark0="$(svc_actmark ssh)"; cur="$(journal_cursor)"
  must_hl "${dir}/rollback.log" "rollback ssh-reload profile" -- rollback "${SSH_RELOAD_PROFILE}" "${short_remote_args[@]}" -d
  svc_acted_since ssh "${mark0}" "${cur}" \
    || note_fail "sshd not reloaded/restarted on rollback (independent: MainPID + StateChange unchanged, no journal reload)"
  must_remote "drop-in gone and sshd config valid after rollback" <<EOF
test ! -e ${SSH_RELOAD_DEST}
/usr/sbin/sshd -t
EOF
  scenario_end
}

# ── ssh-reload-auto-rollback: a failed sshd reload auto-removes the bad drop-in
scenario_ssh_reload_auto_rollback() {
  local dir="${ARTIFACT_ROOT}/ssh-reload-auto-rollback"
  reset_dir "${dir}"
  scenario_start "ssh-reload-auto-rollback: invalid sshd config fails apply and auto-rolls-back the bad drop-in"
  guard_static_profiles || return

  ssh_cmd "sudo rm -f ${FAILURE_DEST}"
  expect_hl_fail "${dir}/apply.log" "apply with invalid sshd config rejected" -- apply "${SSH_RELOAD_FORCE_PROFILE}" "${remote_args[@]}"
  must_remote "bad drop-in removed and sshd config valid" <<EOF
test ! -e ${FAILURE_DEST}
/usr/sbin/sshd -t
EOF
  ssh_cmd "sudo rm -f ${FAILURE_DEST}" 2>/dev/null || true
  scenario_end
}

# ── rollback-no-journal: rollback fails cleanly when no journal exists ───────
scenario_rollback_no_journal() {
  local dir="${ARTIFACT_ROOT}/rollback-no-journal"
  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"; mkdir -p "${STATE_DIR}"
  scenario_start "rollback-no-journal: rollback exits non-zero when there is no journal to apply"
  guard_static_profiles || return
  guard_can_sign || return

  local p; p=$(make_profile_template "no-journal" "/etc/hardline.d/99-hardline-no-journal.conf" "NoJournal=yes")
  ssh_cmd "sudo rm -rf /var/lib/hardline/runs/no-journal" 2>/dev/null || true
  expect_hl_fail "${dir}/rollback.log" "rollback without journal rejected" -- rollback "${p}" "${remote_args[@]}"
  scenario_end
}

# ── apply-no-local-rollback: default run drops the local journal, keeps remote;
#    rollback then works from the remote journal.
scenario_apply_no_local_rollback() {
  local dir="${ARTIFACT_ROOT}/apply-no-local-rollback"
  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"; mkdir -p "${STATE_DIR}"
  scenario_start "apply-no-local-rollback: local journal dropped, remote kept, rollback from remote reverts state"
  guard_static_profiles || return

  ssh_cmd "sudo bash -seo pipefail" <<EOF
rm -f ${MULTI_SUCCESS_TEMPLATE_DEST} ${MULTI_SUCCESS_FIREWALL_DEST}
systemctl restart nftables
EOF
  must_hl "${dir}/apply.log" "apply (no keep-local)" -- apply "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" || { scenario_end; return; }

  local ljournal="${STATE_DIR}/${host}/itest-multi-plugin-success.json"
  test ! -e "${ljournal}" || note_fail "local journal should have been removed: ${ljournal}"
  local rjpath; rjpath="$(remote_journal_latest itest-multi-plugin-success)"
  assert_journal "remote journal" "$(ssh_cmd "sudo cat ${rjpath}")" "itest-multi-plugin-success" "success"
  must_remote "managed artifacts present after apply" <<EOF
test "\$(stat -c %a ${MULTI_SUCCESS_TEMPLATE_DEST})" = "644"
test -e ${MULTI_SUCCESS_FIREWALL_DEST}
EOF

  must_hl "${dir}/rollback.log" "rollback from remote journal" -- rollback "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "artifacts reverted after remote-journal rollback" <<EOF
test ! -e ${MULTI_SUCCESS_TEMPLATE_DEST}
test ! -e ${MULTI_SUCCESS_FIREWALL_DEST}
systemctl restart nftables
if nft list table inet ${MULTI_SUCCESS_FIREWALL_TABLE} >/dev/null 2>&1; then exit 1; fi
EOF
  scenario_end
}

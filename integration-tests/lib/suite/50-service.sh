#!/usr/bin/env bash
# =============================================================================
# 50-service.sh — service plugin: state matrix (with real restart proof),
#                 on-change skip, and every rollback regression the recent
#                 commits fixed (reload re-run, static unit, purged unit, state).
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# Uses cron (always present, safe to bounce) as the test unit.

_cron_restore() { ssh_cmd "sudo systemctl enable --now cron" >/dev/null 2>&1 || true; }

# ── service-state-matrix: started/stopped/disabled/restart(real)/reload-or-restart
scenario_service_state_matrix() {
  local dir="${ARTIFACT_ROOT}/service-state-matrix"
  reset_dir "${dir}"
  scenario_start "service-state-matrix: started, stopped, enabled:false, restarted (MainPID/stamp moves), reload-or-restart"
  guard_can_sign || return

  # started: from stopped -> active.
  ssh_cmd "sudo systemctl stop cron" >/dev/null 2>&1 || true
  local p; p=$(make_profile_service "svc-started" "cron" "started" "true")
  must_hl "${dir}/started.log" "apply started" -- apply "${p}" "${remote_args[@]}"
  must_remote "cron active+enabled after started" <<'EOF'
systemctl is-active cron >/dev/null 2>&1
systemctl is-enabled cron >/dev/null 2>&1
EOF

  # stopped: from active -> inactive.
  ssh_cmd "sudo systemctl start cron" >/dev/null 2>&1 || true
  p=$(make_profile_service "svc-stopped" "cron" "stopped" "true")
  must_hl "${dir}/stopped.log" "apply stopped" -- apply "${p}" "${remote_args[@]}"
  must_remote "cron inactive after stopped" <<'EOF'
if systemctl is-active cron >/dev/null 2>&1; then exit 1; fi
EOF

  # enabled:false -> disabled.
  p=$(make_profile_service "svc-disabled" "cron" "stopped" "false")
  must_hl "${dir}/disabled.log" "apply enabled:false" -- apply "${p}" "${remote_args[@]}"
  must_remote "cron disabled after enabled:false" <<'EOF'
if systemctl is-enabled cron >/dev/null 2>&1; then exit 1; fi
EOF

  # restarted: real proof via MainPID + ActiveEnterTimestamp delta.
  ssh_cmd "sudo systemctl enable --now cron" >/dev/null 2>&1 || true
  local s1 s2; s1="$(svc_stamp cron)"
  p=$(make_profile_service "svc-restarted" "cron" "restarted" "true")
  must_hl "${dir}/restarted.log" "apply restarted" -- apply "${p}" "${remote_args[@]}"
  s2="$(svc_stamp cron)"
  [ -n "${s1}" ] && [ "${s1}" != "${s2}" ] || note_fail "restarted did not move MainPID/ActiveEnterTimestamp (${s1} -> ${s2})"
  ssh_cmd "systemctl is-active cron >/dev/null 2>&1" || note_fail "cron not active after restart"

  # reload-or-restart -> still active.
  p=$(make_profile_service "svc-ror" "cron" "reload-or-restart" "true")
  must_hl "${dir}/ror.log" "apply reload-or-restart" -- apply "${p}" "${remote_args[@]}"
  ssh_cmd "systemctl is-active cron >/dev/null 2>&1" || note_fail "cron not active after reload-or-restart"

  _cron_restore
  scenario_end
}

# ── service-onchange-skip: reload runs once; an unchanged re-apply is a no-op ─
scenario_service_onchange_skip() {
  local dir="${ARTIFACT_ROOT}/service-onchange-skip"
  reset_dir "${dir}"
  scenario_start "service-onchange-skip: second apply changes nothing (file fingerprint stable, daemon untouched)"
  guard_can_sign || return

  _cron_restore
  local dest="/etc/hardline.d/99-hardline-svc-onchange.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local p; p=$(make_profile_template_service "svc-onchange" "${dest}" "OnChange=yes" "cron")

  must_hl "${dir}/apply1.log" "first apply" -- apply "${p}" "${remote_args[@]}" || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }
  ssh_cmd "test -f ${dest}" || note_fail "config not deployed by first apply"
  local fp1 fp2 mark0 cur
  fp1="$(fp_path "${dest}")"
  mark0="$(svc_actmark cron)"; cur="$(journal_cursor)"

  must_hl "${dir}/apply2.log" "second apply (no-op)" -- apply "${p}" "${remote_args[@]}"
  fp2="$(fp_path "${dest}")"
  [ "${fp1}" = "${fp2}" ] || note_fail "second apply rewrote the config (fp ${fp1} -> ${fp2})"
  if svc_acted_since cron "${mark0}" "${cur}"; then
    note_fail "cron was reloaded/restarted on a no-op apply (should be untouched)"
  fi

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── service-reload-rollback: rollback re-runs the reload of an active service ─
#    whose config it reverts (observed via systemd). [regression]
scenario_service_reload_rollback() {
  local dir="${ARTIFACT_ROOT}/service-reload-rollback"
  reset_dir "${dir}"
  scenario_start "service-reload-rollback: rollback re-runs the reload of active cron whose config it reverts (observed via systemd)"
  guard_can_sign || return

  _cron_restore
  local dest="/etc/hardline.d/99-hardline-svc-reload-rb.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local p; p=$(make_profile_template_service "svc-reload-rb" "${dest}" "ReloadRollback=yes" "cron")

  must_hl "${dir}/apply.log" "apply" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }

  # Observe the daemon directly across the rollback (not hardline's log).
  local mark0 cur; mark0="$(svc_actmark cron)"; cur="$(journal_cursor)"
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${p}" "${remote_args[@]}"

  svc_acted_since cron "${mark0}" "${cur}" \
    || note_fail "cron not reloaded/restarted on rollback (independent: MainPID + StateChange unchanged, no journal reload)"
  must_remote "config removed after rollback" <<EOF
test ! -e ${dest}
EOF

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── service-policy-always: restart_policy type=always re-runs reload on rollback
scenario_service_policy_always() {
  local dir="${ARTIFACT_ROOT}/service-policy-always"
  reset_dir "${dir}"
  scenario_start "service-policy-always: type=always reload is re-run on rollback (observed via systemd)"
  guard_can_sign || return

  _cron_restore
  local dest="/etc/hardline.d/99-hardline-svc-always.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local p; p=$(make_profile_template_service "svc-always" "${dest}" "AlwaysReload=yes" "cron" "always")

  must_hl "${dir}/apply.log" "apply" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }
  local mark0 cur; mark0="$(svc_actmark cron)"; cur="$(journal_cursor)"
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${p}" "${remote_args[@]}"
  svc_acted_since cron "${mark0}" "${cur}" \
    || note_fail "type=always reload not re-run on rollback (independent: cron untouched)"

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── service-static-reload-rollback: a static unit reloads on rollback without a
#    false drift conflict (systemd-journald is static+active). [regression]
scenario_service_static_reload_rollback() {
  local dir="${ARTIFACT_ROOT}/service-static-reload-rollback"
  reset_dir "${dir}"
  scenario_start "service-static-reload-rollback: static unit reloads on rollback, no false drift conflict"
  guard_can_sign || return

  local dest="/etc/hardline.d/99-hardline-svc-static-rb.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local p; p=$(make_profile_template_service "svc-static-rb" "${dest}" "StaticReload=yes" "systemd-journald")

  must_hl "${dir}/apply.log" "apply" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }
  local mark0 cur; mark0="$(svc_actmark systemd-journald)"; cur="$(journal_cursor)"
  must_hl "${dir}/rollback.log" "rollback (static unit must not false-conflict)" -- rollback "${p}" "${remote_args[@]}" || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }
  svc_acted_since systemd-journald "${mark0}" "${cur}" \
    || note_fail "static unit (systemd-journald) not reloaded on rollback (independent check)"
  must_remote "config removed after rollback" <<EOF
test ! -e ${dest}
EOF

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── service-purged-unit-rollback: rollback skips restoring a service whose
#    package it purges in the same run (auditd). [regression]
scenario_service_purged_unit_rollback() {
  local dir="${ARTIFACT_ROOT}/service-purged-unit-rollback"
  reset_dir "${dir}"
  scenario_start "service-purged-unit-rollback: rollback purges auditd + no-ops the restore of its now-gone unit"
  guard_can_sign || return

  ssh_cmd "sudo apt-get purge -y auditd >/dev/null 2>&1" || true
  local p; p=$(make_profile_package_service "svc-purged-unit-rb" "auditd" "auditd")

  must_hl "${dir}/apply.log" "apply (install auditd + restart)" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { ssh_cmd "sudo apt-get purge -y auditd >/dev/null 2>&1" || true; scenario_end; return; }
  ssh_cmd "dpkg -s auditd >/dev/null 2>&1" || note_fail "auditd not installed by apply"

  must_hl "${dir}/rollback.log" "rollback (restore of purged unit must no-op)" -- rollback "${p}" "${remote_args[@]}"
  must_remote "auditd purged by rollback" <<'EOF'
if dpkg -s auditd >/dev/null 2>&1; then exit 1; fi
EOF

  ssh_cmd "sudo apt-get purge -y auditd >/dev/null 2>&1" || true
  scenario_end
}

# ── service-state-rollback: rollback restores a service it stopped+disabled ──
scenario_service_state_rollback() {
  local dir="${ARTIFACT_ROOT}/service-state-rollback"
  reset_dir "${dir}"
  scenario_start "service-state-rollback: rollback restarts+re-enables a service apply stopped+disabled"
  guard_can_sign || return

  _cron_restore
  local p; p=$(make_profile_service "svc-state-rb" "cron" "stopped" "false")
  must_hl "${dir}/apply.log" "apply stop+disable" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { _cron_restore; scenario_end; return; }
  must_remote "cron stopped+disabled after apply" <<'EOF'
if systemctl is-active cron >/dev/null 2>&1; then exit 1; fi
if systemctl is-enabled cron >/dev/null 2>&1; then exit 1; fi
EOF
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${p}" "${remote_args[@]}"
  must_remote "cron active+enabled after rollback" <<'EOF'
systemctl is-active cron >/dev/null 2>&1
systemctl is-enabled cron >/dev/null 2>&1
EOF

  _cron_restore
  scenario_end
}

# ── service-conflict: post-apply service drift blocks rollback unless forced ──
scenario_service_conflict() {
  local dir="${ARTIFACT_ROOT}/service-conflict"
  reset_dir "${dir}"
  scenario_start "service-conflict: post-apply drift blocks rollback; --force-rollback proceeds"
  guard_can_sign || return

  ssh_cmd "sudo systemctl start cron" >/dev/null 2>&1 || true
  local p; p=$(make_profile_service "svc-conflict" "cron" "stopped" "true")
  must_hl "${dir}/apply.log" "apply (stop cron)" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { _cron_restore; scenario_end; return; }
  ssh_cmd "sudo systemctl start cron" >/dev/null 2>&1 || true   # drift: current active != recorded inactive

  expect_hl_fail "${dir}/refuse.log" "rollback refused on service drift" -- rollback "${p}" "${remote_args[@]}"
  must_hl "${dir}/force.log" "force-rollback after drift" -- rollback "${p}" "${remote_args[@]}" --force-rollback

  _cron_restore
  scenario_end
}

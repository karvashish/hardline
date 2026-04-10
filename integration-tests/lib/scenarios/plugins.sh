#!/usr/bin/env bash
# =============================================================================
# plugins.sh — Firewall, service, and package plugin scenarios (14 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── 26. firewall-nftables ───────────────────────────────────────────────────
scenario_firewall_nftables() {
  scenario_start "firewall-nftables: deploys rules and nft loads table"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local fw_dest="/etc/nftables.d/99-hardline-fw-test.nft"
  local fw_table="hardline_fw_test"
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true

  local pdir
  pdir=$(make_profile_firewall "fw-test" "${fw_table}" "${fw_dest}")

  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    return
  fi

  if ssh_cmd "test -f ${fw_dest}" 2>/dev/null; then
    if ssh_cmd "sudo nft list table inet ${fw_table} 2>/dev/null" | grep -q "input"; then
      scenario_pass
    else
      scenario_fail "nftables table ${fw_table} not loaded or missing input chain"
    fi
  else
    scenario_fail "firewall config file not deployed"
  fi
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true
}

# ── 27. firewall-external-plugin ────────────────────────────────────────────
scenario_firewall_external_plugin() {
  scenario_start "firewall-external-plugin: firewall_template .so plugin loads and deploys"

  # This is covered by the static multi-plugin-success profile which uses firewall_template
  run_success_apply
  # run_success_apply already validates template + firewall_template content
  scenario_pass
}

# ── 28. firewall-forward-chain ──────────────────────────────────────────────
scenario_firewall_forward_chain() {
  scenario_start "firewall-forward-chain: forward chain, source CIDR, multi-port, non-lo interface"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local fw_dest="/etc/nftables.d/99-hardline-fw-adv.nft"
  local fw_table="hardline_fw_adv"
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true

  # Detect the primary non-lo interface on the remote host
  local remote_iface
  remote_iface=$(ssh_cmd "ip -o link show | awk -F': ' '!/lo/{print \$2; exit}'") || remote_iface=""
  remote_iface=$(echo "${remote_iface}" | tr -d '[:space:]')

  if [[ -z "${remote_iface}" ]]; then
    scenario_skip "could not detect non-lo interface on remote host"
    return
  fi

  local pdir
  pdir=$(make_profile_firewall_advanced "fw-advanced" "${fw_table}" "${fw_dest}" "${remote_iface}")

  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true
    return
  fi

  local all_ok=true
  local nft_out
  nft_out=$(ssh_cmd "sudo nft list table inet ${fw_table} 2>/dev/null")

  # Check forward chain exists
  echo "${nft_out}" | grep -q "chain forward" || { scenario_fail "missing forward chain"; all_ok=false; }
  # Check multi-port rule (ports 80,443)
  echo "${nft_out}" | grep -qE '(dport \{ 80, 443 \}|dport 80|dport 443)' || { scenario_fail "missing multi-port rule"; all_ok=false; }
  # Check source CIDR
  echo "${nft_out}" | grep -q "10.0.0.0/8" || { scenario_fail "missing source CIDR rule"; all_ok=false; }
  # Check input chain
  echo "${nft_out}" | grep -q "chain input" || { scenario_fail "missing input chain"; all_ok=false; }
  # Check non-lo interface in forward rule
  echo "${nft_out}" | grep -q "iif \"${remote_iface}\"" || { scenario_fail "missing non-lo interface ${remote_iface} in forward rule"; all_ok=false; }

  if $all_ok; then
    scenario_pass
  fi
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true
}

# ── 29. firewall-rollback ───────────────────────────────────────────────────
scenario_firewall_rollback() {
  scenario_start "firewall-rollback: rollback removes ruleset file and flushes table"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local fw_dest="/etc/nftables.d/99-hardline-fw-rb.nft"
  local fw_table="hardline_fw_rb"
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null; sudo rm -f ${fw_dest}" 2>/dev/null || true

  local pdir
  pdir=$(make_profile_firewall "fw-rollback" "${fw_table}" "${fw_dest}")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1 || { scenario_fail "apply failed"; return; }
  # Verify file exists before rollback
  ssh_cmd "test -f ${fw_dest}" 2>/dev/null || { scenario_fail "file not deployed before rollback"; return; }

  local ec=0
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "rollback failed: ${ec}"
    return
  fi

  if ssh_cmd "test -f ${fw_dest}" 2>/dev/null; then
    scenario_fail "firewall file still exists after rollback"
  else
    scenario_pass
  fi
  ssh_cmd "sudo nft delete table inet ${fw_table} 2>/dev/null" 2>/dev/null || true
}

# ── 30. service-on-change-skip ──────────────────────────────────────────────
scenario_service_on_change_skip() {
  scenario_start "service-on-change-skip: service not restarted when config unchanged"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-svc-onchange.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_template_service "svc-onchange" "${dest}" "SvcTest=yes" "cron")

  # First apply — deploys + reloads
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || { scenario_fail "first apply failed"; ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true; return; }
  # Second plan — should show aligned/skipped
  local plan_out
  plan_out=$("${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" 2>&1) || true

  if echo "${plan_out}" | grep -qiE '(already aligned|no change|skip|aligned)'; then
    scenario_pass
  else
    scenario_fail "service step not skipped on second run"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── 31. service-restart-always ──────────────────────────────────────────────
scenario_service_restart_always() {
  scenario_start "service-restart-always: service with no restart_policy always runs"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_service "svc-restart-always" "cron" "restarted" "true")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    return
  fi

  # Verify cron is still running
  if ssh_cmd "systemctl is-active cron >/dev/null 2>&1" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "cron not active after restart"
  fi
}

# ── 32. service-reload-or-restart ───────────────────────────────────────────
scenario_service_reload_or_restart() {
  scenario_start "service-reload-or-restart: reload-or-restart state works"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_service "svc-reload-or-restart" "cron" "reload-or-restart" "true")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -eq 0 ]]; then
    if ssh_cmd "systemctl is-active cron >/dev/null 2>&1" 2>/dev/null; then
      scenario_pass
    else
      scenario_fail "cron not active after reload-or-restart"
    fi
  else
    scenario_fail "apply failed: ${ec}"
  fi
}

# ── 33. service-stopped ─────────────────────────────────────────────────────
scenario_service_stopped() {
  scenario_start "service-stopped: stop a non-essential service, then restart"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  # Ensure cron is running first
  ssh_cmd "sudo systemctl start cron" 2>/dev/null || true

  local pdir
  pdir=$(make_profile_service "svc-stopped" "cron" "stopped" "true")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    ssh_cmd "sudo systemctl start cron" 2>/dev/null || true
    return
  fi

  if ssh_cmd "systemctl is-active cron >/dev/null 2>&1" 2>/dev/null; then
    scenario_fail "cron should be stopped but is still active"
  else
    scenario_pass
  fi
  # Restore cron
  ssh_cmd "sudo systemctl start cron" 2>/dev/null || true
}

# ── 34. service-enabled-false ───────────────────────────────────────────────
scenario_service_enabled_false() {
  scenario_start "service-enabled-false: disable a service, then re-enable"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_service "svc-disabled" "cron" "stopped" "false")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    ssh_cmd "sudo systemctl enable --now cron" 2>/dev/null || true
    return
  fi

  if ssh_cmd "systemctl is-enabled cron >/dev/null 2>&1" 2>/dev/null; then
    scenario_fail "cron should be disabled but is still enabled"
  else
    scenario_pass
  fi
  # Restore cron
  ssh_cmd "sudo systemctl enable --now cron" 2>/dev/null || true
}

# ── 35. package-update-always ───────────────────────────────────────────────
scenario_package_update_always() {
  scenario_start "package-update-always: update:always runs apt-get update"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_packages_update_always "pkg-update-always" "tree")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    return
  fi

  if ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "package tree not installed after apply with update:always"
  fi
  ssh_cmd "sudo apt-get purge -y tree" >/dev/null 2>&1 || true
}

# ── 36. package-purge ───────────────────────────────────────────────────────
scenario_package_purge() {
  scenario_start "package-purge: purge step removes package"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  # Install tree first
  ssh_cmd "sudo apt-get install -y tree" >/dev/null 2>&1 || true
  ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null || { scenario_fail "tree not installed for purge test"; return; }

  local pdir
  pdir=$(make_profile_packages_purge "pkg-purge" "tree")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed: ${ec}"
    return
  fi

  if ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null; then
    scenario_fail "package tree still installed after purge"
  else
    scenario_pass
  fi
}

# ── 37. package-idempotent ──────────────────────────────────────────────────
scenario_package_idempotent() {
  scenario_start "package-idempotent: installing already-installed package is idempotent"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  # Install tree first
  ssh_cmd "sudo apt-get install -y tree" >/dev/null 2>&1 || true

  local pdir
  pdir=$(make_profile_packages_install "pkg-idempotent" "tree")

  # Plan should show aligned
  local plan_out
  plan_out=$("${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" 2>&1) || true

  if echo "${plan_out}" | grep -qiE '(already aligned|no change|aligned|installed)'; then
    scenario_pass
  else
    # Even if plan doesn't say "aligned", apply should succeed without error
    "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
    local ec=$?
    if [[ $ec -eq 0 ]]; then
      scenario_pass
    else
      scenario_fail "apply failed on already-installed package: ${ec}"
    fi
  fi
  ssh_cmd "sudo apt-get purge -y tree" >/dev/null 2>&1 || true
}

# ── 38. package-purge-absent ────────────────────────────────────────────────
scenario_package_purge_absent() {
  scenario_start "package-purge-absent: purging already-absent package is idempotent"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  # Ensure tree is NOT installed
  ssh_cmd "sudo apt-get purge -y tree" >/dev/null 2>&1 || true

  local pdir
  pdir=$(make_profile_packages_purge "pkg-purge-absent" "tree")

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -eq 0 ]]; then
    scenario_pass
  else
    scenario_fail "apply failed on already-absent package: ${ec}"
  fi
}

# ── 39. package-rollback-reinstalls ─────────────────────────────────────────
scenario_package_rollback_reinstalls() {
  scenario_start "package-rollback-reinstalls: rollback after purge reinstalls package"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  # Install tree first
  ssh_cmd "sudo apt-get install -y tree" >/dev/null 2>&1 || true
  ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null || { scenario_fail "tree not installed before purge test"; return; }

  local pdir
  pdir=$(make_profile_packages_purge "pkg-rb-reinstall" "tree")

  # Apply purge with rollback journal
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1 || { scenario_fail "purge apply failed"; return; }
  # Verify tree is purged
  if ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null; then
    scenario_fail "tree not purged by apply"
    return
  fi

  # Rollback should reinstall
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "rollback failed: ${ec}"
    return
  fi

  if ssh_cmd "dpkg -l tree 2>/dev/null | grep -q '^ii'" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "tree not reinstalled after rollback"
  fi
  ssh_cmd "sudo apt-get purge -y tree" >/dev/null 2>&1 || true
}

#!/usr/bin/env bash
# =============================================================================
# 40-firewall.sh — firewall (nftables) plugin: basic + advanced rules, rollback,
#                  and the external firewall_template .so plugin.
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── firewall-basic-rollback: deploy ruleset, verify nft loaded it, roll back ─
scenario_firewall_basic_rollback() {
  local dir="${ARTIFACT_ROOT}/firewall-basic"
  reset_dir "${dir}"
  scenario_start "firewall-basic-rollback: load input ruleset (verify via nft list), then rollback flushes it"
  guard_can_sign || return

  local table="hardline_fw_basic"
  local dest="/etc/nftables.d/99-hardline-fw-basic.nft"
  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null; sudo rm -f ${dest}; sudo systemctl restart nftables" 2>/dev/null || true

  local pdir; pdir=$(make_profile_firewall "fw-basic" "${table}" "${dest}")
  must_hl "${dir}/apply.log" "apply firewall" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  must_remote "nftables table loaded with expected rules + file mode" <<EOF
test "\$(stat -c %a ${dest})" = "644"
out="\$(nft list table inet ${table})"
echo "\${out}" | grep -q 'tcp dport 22 accept'
echo "\${out}" | grep -q 'iif "lo" accept'
echo "\${out}" | grep -q 'ct state established,related accept'
echo "\${out}" | grep -qi 'icmp'
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  must_hl "${dir}/rollback.log" "rollback firewall" -- rollback "${pdir}" "${remote_args[@]}"
  must_remote "ruleset file gone + table flushed after rollback" <<EOF
test ! -e ${dest}
systemctl restart nftables
if nft list table inet ${table} >/dev/null 2>&1; then exit 1; fi
EOF

  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null" 2>/dev/null || true
  scenario_end
}

# ── firewall-advanced: forward chain, source CIDR, multi-port, non-lo iface ──
scenario_firewall_advanced() {
  local dir="${ARTIFACT_ROOT}/firewall-advanced"
  reset_dir "${dir}"
  scenario_start "firewall-advanced: forward chain + source CIDR + multi-port + non-lo interface in nft output"
  guard_can_sign || return

  local table="hardline_fw_adv"
  local dest="/etc/nftables.d/99-hardline-fw-adv.nft"
  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null; sudo rm -f ${dest}; sudo systemctl restart nftables" 2>/dev/null || true

  local iface
  iface=$(ssh_cmd "ip -o link show | awk -F': ' '!/lo/{print \$2; exit}'" | tr -d '[:space:]')
  if [[ -z "${iface}" ]]; then scenario_skip "no non-lo interface on remote host"; return; fi

  local pdir; pdir=$(make_profile_firewall_advanced "fw-adv" "${table}" "${dest}" "${iface}")
  must_hl "${dir}/apply.log" "apply advanced firewall" -- apply "${pdir}" "${remote_args[@]}" || { scenario_end; return; }

  must_remote "advanced nft rules present (chains, multi-port, CIDR, iface)" <<EOF
out="\$(nft list table inet ${table})"
echo "\${out}" | grep -q 'chain input'
echo "\${out}" | grep -q 'chain forward'
echo "\${out}" | grep -qE 'dport \{ 80, 443 \}|dport 80|dport 443'
echo "\${out}" | grep -q '10.0.0.0/8'
echo "\${out}" | grep -q 'iif "${iface}"'
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null; sudo rm -f ${dest}; sudo systemctl restart nftables" 2>/dev/null || true
  scenario_end
}

# ── firewall-external-plugin: the firewall_template .so external plugin loads ─
#    and deploys via the multi-plugin-success fixture. run_success_apply
#    (runners.sh) verifies template + firewall_template content + journals.
scenario_firewall_external_plugin() {
  scenario_start "firewall-external-plugin: external firewall_template .so deploys (multi-plugin-success)"
  guard_can_sign || return
  if ( run_success_apply "${ARTIFACT_ROOT}/firewall-external-plugin" ); then
    scenario_pass
  else
    note_fail "multi-plugin-success apply/verification failed (see output above)"
    scenario_end
  fi
}

#!/usr/bin/env bash
# =============================================================================
# 80-overrides.sh — runtime overrides: verify-path validation (host-free) and a
#                   real CLI-observable effect (firewall override opens a port).
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# profile.overrides.json is auto-discovered, excluded from the signed manifest
# (so it can be edited freely), and its keys must be in allowed_overrides.
# --overrides-file wins over auto-discovery. The firewall plugin's
# allow_tcp_ports / allow_udp_ports keys are the only override effect that is
# observable from the command line (they append accept rules).

# ── overrides-verify: every verify-profile override path behaves correctly ──
scenario_overrides_verify() {
  local dir="${ARTIFACT_ROOT}/overrides-verify"
  reset_dir "${dir}"
  scenario_start "overrides-verify: auto-discovery, signature-invariance, explicit-wins, unknown-key, invalid-json, missing-file"
  guard_can_sign || return

  local p

  # Auto-discovered overrides file with allowed keys verifies.
  p=$(make_profile_with_allowed_overrides "ov-auto" "/etc/hardline.d/x.conf" "Auto=ok" "ssh_port feature_flag")
  echo '{ "ssh_port": 2222, "feature_flag": true }' > "${p}/profile.overrides.json"
  must_hl "${dir}/auto.log" "auto-discovered overrides verify" -- verify-profile "${p}"

  # Signature is unaffected by writing/editing the overrides file post-sign.
  p=$(make_profile_with_allowed_overrides "ov-sig" "/etc/hardline.d/x.conf" "Sig=ok" "ssh_port")
  must_hl "${dir}/sig1.log" "verify without overrides file" -- verify-profile "${p}"
  echo '{ "ssh_port": 2222 }' > "${p}/profile.overrides.json"
  must_hl "${dir}/sig2.log" "verify after writing overrides file" -- verify-profile "${p}"
  echo '{ "ssh_port": 2200 }' > "${p}/profile.overrides.json"
  must_hl "${dir}/sig3.log" "verify after editing overrides file" -- verify-profile "${p}"

  # --overrides-file wins over auto-discovery: a banned key in the explicit file
  # must cause failure even though the auto-discovered file is clean.
  p=$(make_profile_with_allowed_overrides "ov-flag" "/etc/hardline.d/x.conf" "Flag=ok" "ssh_port")
  echo '{ "ssh_port": 2222 }' > "${p}/profile.overrides.json"
  echo '{ "banned_key": "value" }' > "${p}/explicit.json"
  expect_hl_fail "${dir}/explicit.log" "explicit overrides file with banned key rejected" -- verify-profile "${p}" --overrides-file "${p}/explicit.json"

  # Unknown key (not in allowed_overrides) is rejected with a clear message.
  p=$(make_profile_with_allowed_overrides "ov-bad-key" "/etc/hardline.d/x.conf" "Bad=key" "ssh_port")
  echo '{ "smtp_port": 25 }' > "${p}/profile.overrides.json"
  expect_hl_fail "${dir}/bad-key.log" "unknown override key rejected" -- verify-profile "${p}"
  grep -qi "does not allow overrides" "${dir}/bad-key.log" || note_fail "unknown-key error missing 'does not allow overrides'"

  # A JSON array (not an object) is invalid.
  p=$(make_profile_with_allowed_overrides "ov-bad-json" "/etc/hardline.d/x.conf" "Bad=json" "ssh_port")
  echo '["ssh_port", 2222]' > "${p}/profile.overrides.json"
  expect_hl_fail "${dir}/bad-json.log" "non-object overrides file rejected" -- verify-profile "${p}"

  # --overrides-file pointing at a missing path fails cleanly.
  p=$(make_profile_with_allowed_overrides "ov-missing" "/etc/hardline.d/x.conf" "Missing=flag" "ssh_port")
  expect_hl_fail "${dir}/missing.log" "missing overrides file rejected" -- verify-profile "${p}" --overrides-file "${DYNAMIC_PROFILES_DIR}/nope/overrides.json"
  grep -qi "overrides file" "${dir}/missing.log" || note_fail "missing-file error missing 'overrides file'"

  scenario_end
}

# ── overrides-effect: an override value changes the applied nftables ruleset ─
scenario_overrides_effect() {
  local dir="${ARTIFACT_ROOT}/overrides-effect"
  reset_dir "${dir}"
  scenario_start "overrides-effect: firewall override opens a port only when present (auto + --overrides-file)"
  guard_can_sign || return

  local table="hardline_fw_ovr"
  local dest="/etc/nftables.d/99-hardline-fw-ovr.nft"
  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null; sudo rm -f ${dest}; sudo systemctl restart nftables" 2>/dev/null || true

  local pdir; pdir=$(make_profile_firewall_overridable "fw-ovr" "${table}" "${dest}")

  # (a) No overrides: the port is closed.
  must_hl "${dir}/apply-none.log" "apply without overrides" -- apply "${pdir}" "${remote_args[@]}" || { scenario_end; return; }
  must_remote "without override: tcp dport 9999 is NOT present" <<EOF
out="\$(nft list table inet ${table})"
echo "\${out}" | grep -q 'tcp dport 22 accept'
if echo "\${out}" | grep -q 'dport 9999'; then exit 1; fi
EOF

  # (b) Auto-discovered override opens tcp/9999.
  echo '{ "allow_tcp_ports": [9999] }' > "${pdir}/profile.overrides.json"
  must_hl "${dir}/apply-auto.log" "apply with auto-discovered override" -- apply "${pdir}" "${remote_args[@]}"
  must_remote "auto override: tcp dport 9999 accept present" <<EOF
nft list table inet ${table} | grep -q 'tcp dport 9999 accept'
EOF

  # (c) --overrides-file wins (udp/9998 opens, the auto tcp/9999 is ignored).
  local ext="${DYNAMIC_PROFILES_DIR}/fw-ovr-external.json"
  echo '{ "allow_udp_ports": [9998] }' > "${ext}"
  must_hl "${dir}/apply-flag.log" "apply with --overrides-file" -- apply "${pdir}" "${remote_args[@]}" --overrides-file "${ext}"
  must_remote "explicit override: udp dport 9998 present, tcp 9999 absent (auto ignored)" <<EOF
out="\$(nft list table inet ${table})"
echo "\${out}" | grep -q 'udp dport 9998 accept'
if echo "\${out}" | grep -q 'dport 9999'; then exit 1; fi
EOF

  ssh_cmd "sudo nft delete table inet ${table} 2>/dev/null; sudo rm -f ${dest}; sudo systemctl restart nftables" 2>/dev/null || true
  scenario_end
}

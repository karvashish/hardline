#!/usr/bin/env bash
# =============================================================================
# 90-trust-boundary.sh — the boundaries a signed profile must not cross:
#   root command injection, unsigned content behind a signed reference, an
#   edited profile reaching apply, and the ${NFT_MAIN_CONFIG} mutation apply
#   makes outside its managed destination.
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# expect_hl_fail only proves a non-zero exit, so on its own it cannot tell a
# real rejection from a fixture that was broken for some unrelated reason.
# Every rejection case here is therefore paired with a benign twin built by the
# same generator: the twin must pass, which pins the failure to the one value
# that differs.

# ── injection-guard: hostile values must never reach a root shell ────────────
scenario_injection_guard() {
  local dir="${ARTIFACT_ROOT}/injection-guard"
  reset_dir "${dir}"
  scenario_start "injection-guard: metacharacters in a signed profile are rejected and never execute as root"
  guard_can_sign || return

  local marker="/tmp/hardline-pwn"
  ssh_cmd "sudo rm -f ${marker}" >/dev/null 2>&1 || true

  # Control: the same generator with a real unit name must verify, proving the
  # fixture is well-formed and correctly signed.
  local ok_svc; ok_svc=$(make_profile_service_raw_name "inject-svc-ok" "cron")
  must_hl "${dir}/svc-control.log" "benign service profile verifies (control: proves the fixture is valid and signed)" \
    -- verify-profile "${ok_svc}" || { scenario_end; return; }

  local bad_svc; bad_svc=$(make_profile_service_raw_name "inject-svc" "ssh\$(touch ${marker})")
  expect_hl_fail "${dir}/svc-verify.log" "hostile service unit accepted at verify" -- verify-profile "${bad_svc}"
  expect_hl_fail "${dir}/svc-plan.log" "hostile service unit accepted at plan" -- plan "${bad_svc}" "${remote_args[@]}"
  expect_hl_fail "${dir}/svc-apply.log" "hostile service unit accepted at apply" -- apply "${bad_svc}" "${remote_args[@]}"

  # Control: the same generator with a clean path must verify.
  local ok_path; ok_path=$(make_profile_file_meta_badpath "inject-path-ok" "/etc/hardline.d/itest-inject-ok.conf")
  must_hl "${dir}/path-control.log" "benign file_meta path verifies (control: proves the fixture is valid and signed)" \
    -- verify-profile "${ok_path}" || { scenario_end; return; }

  local bad_path; bad_path=$(make_profile_file_meta_badpath "inject-path" "/etc/hardline.d/\$(touch ${marker}).conf")
  expect_hl_fail "${dir}/path-verify.log" "hostile file_meta path accepted" -- verify-profile "${bad_path}"
  expect_hl_fail "${dir}/path-apply.log" "hostile file_meta path accepted at apply" -- apply "${bad_path}" "${remote_args[@]}"

  # The claim that matters: no substitution ran on the host.
  must_remote "no command substitution executed as root" <<EOF
test ! -e ${marker}
EOF

  scenario_end
}

# ── signed-bundle-coverage: a signed reference to unsigned content ───────────
scenario_signed_bundle_coverage() {
  local dir="${ARTIFACT_ROOT}/signed-bundle-coverage"
  reset_dir "${dir}"
  scenario_start "signed-bundle-coverage: an action file outside the signed tree is refused"
  guard_can_sign || return

  # Control: identical profile, reference inside the profile directory.
  local ok; ok=$(make_profile_action_ref "action-ref-ok" "actions/00-pkg.json")
  must_hl "${dir}/control.log" "in-profile action reference verifies (control: proves the fixture is valid and signed)" \
    -- verify-profile "${ok}" || { scenario_end; return; }

  local escaped; escaped=$(make_profile_action_ref "action-ref-escape" "../shared/x.json")
  expect_hl_fail "${dir}/escape.log" "escaping action reference accepted" -- verify-profile "${escaped}"
  expect_hl_fail "${dir}/escape-apply.log" "escaping action reference accepted at apply" \
    -- apply "${escaped}" "${remote_args[@]}"

  # An absolute reference is the same class of escape.
  local abs; abs=$(make_profile_action_ref "action-ref-abs" "/etc/hardline/x.json")
  expect_hl_fail "${dir}/abs.log" "absolute action reference accepted" -- verify-profile "${abs}"

  scenario_end
}

# ── edited-profile-refused: the tree must match the signature at apply ───────
# NOTE: this covers an edit made before the run. The re-check between the verify
# phase and the first write happens inside a single process and cannot be raced
# from the shell; that path is covered by a unit test in internals/apply.
scenario_edited_profile_refused() {
  local dir="${ARTIFACT_ROOT}/edited-profile-refused"
  reset_dir "${dir}"
  scenario_start "edited-profile-refused: a profile edited after signing is refused and writes nothing"
  guard_can_sign || return

  local dest="/etc/hardline.d/99-hardline-itest-pinning.conf"
  ssh_cmd "sudo rm -f ${dest}" >/dev/null 2>&1 || true

  # Control: the unedited profile must actually write dest, so "dest is absent"
  # below means the write was prevented rather than never attempted.
  local pdir; pdir=$(make_profile_template "pinning" "${dest}" "itest pinning\n")
  must_hl "${dir}/control-apply.log" "unedited profile applies (control: proves this profile does write dest)" \
    -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }
  must_remote "unedited profile wrote its destination" <<EOF
test -e ${dest}
EOF
  must_hl "${dir}/control-rollback.log" "control apply rolled back" \
    -- rollback "${pdir}" "${remote_args[@]}"
  ssh_cmd "sudo rm -f ${dest}" >/dev/null 2>&1 || true

  # Now edit an action file: the tree no longer matches the signed manifest.
  local action; action="$(find "${pdir}/actions" -name '*.json' | head -n 1)"
  printf '\n' >> "${action}"

  expect_hl_fail "${dir}/edited-apply.log" "edited profile accepted by apply" -- apply "${pdir}" "${remote_args[@]}"
  must_remote "edited profile wrote nothing" <<EOF
test ! -e ${dest}
EOF

  scenario_end
}

# ── firewall-include-rollback: ${NFT_MAIN_CONFIG} restored byte-for-byte ─────
scenario_firewall_include_rollback() {
  local dir="${ARTIFACT_ROOT}/firewall-include-rollback"
  reset_dir "${dir}"
  scenario_start "firewall-include-rollback: rollback removes the include apply appended to ${NFT_MAIN_CONFIG}"
  guard_can_sign || return

  local table="hardline_fw_include"
  local dest="/etc/nftables.d/99-hardline-fw-include.nft"

  # Start from a config with no hardline include, so apply has to add one.
  ssh_cmd "sudo bash -seo pipefail" <<EOF
nft delete table inet ${table} 2>/dev/null || true
rm -f ${dest}
sed -i '/nftables\\.d/d' ${NFT_MAIN_CONFIG}
EOF

  must_remote "include line absent before apply (control: proves apply has to add it)" <<EOF
if $(nft_include_test "${dest}"); then exit 1; fi
EOF

  local before; before="$(remote_value "sha256sum ${NFT_MAIN_CONFIG} | cut -d' ' -f1")"
  if [ -z "${before}" ]; then
    note_fail "could not read ${NFT_MAIN_CONFIG} before apply"
    scenario_end
    return
  fi

  local pdir; pdir=$(make_profile_firewall "fw-include" "${table}" "${dest}")
  must_hl "${dir}/apply.log" "apply firewall" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  # Prove apply really mutated the file, otherwise the post-rollback hash match
  # below would hold trivially.
  must_remote "apply added an include naming this file, not its directory, and a flush header" <<EOF
$(nft_include_test "${dest}")
grep -F -q 'include "${dest}"' ${NFT_MAIN_CONFIG}
$(nft_flush_test)
test "\$(grep -E -v '^[[:space:]]*(#|\$)' ${NFT_MAIN_CONFIG} | head -n 1 | tr -s ' ')" = "flush ruleset"
EOF
  local after; after="$(remote_value "sha256sum ${NFT_MAIN_CONFIG} | cut -d' ' -f1")"
  [ "${after}" != "${before}" ] || note_fail "${NFT_MAIN_CONFIG} hash unchanged by apply (${before})"

  must_hl "${dir}/rollback.log" "rollback firewall" -- rollback "${pdir}" "${remote_args[@]}"
  must_remote "${NFT_MAIN_CONFIG} byte-identical to its pre-apply content and still parses" <<EOF
test "\$(sha256sum ${NFT_MAIN_CONFIG} | cut -d' ' -f1)" = "${before}"
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  # Leave the host as the rest of the suite expects it: no leftover table, no
  # include naming a file that is gone.
  ssh_cmd "sudo bash -seo pipefail" <<EOF >/dev/null 2>&1 || true
nft delete table inet hardline_fw_include 2>/dev/null || true
$(nft_forget_managed "${dest}")
EOF
  scenario_end
}

# ── firewall-include-layering: one profile's rollback keeps another's include ─
scenario_firewall_include_layering() {
  local dir="${ARTIFACT_ROOT}/firewall-include-layering"
  reset_dir "${dir}"
  scenario_start "firewall-include-layering: rolling back one profile leaves the other profile's include in ${NFT_MAIN_CONFIG}"
  guard_can_sign || return

  local first_table="hardline_fw_layer_a"
  local second_table="hardline_fw_layer_b"
  local first_dest="/etc/nftables.d/97-hardline-fw-layer-a.nft"
  local second_dest="/etc/nftables.d/98-hardline-fw-layer-b.nft"

  ssh_cmd "sudo bash -seo pipefail" <<EOF
nft delete table inet ${first_table} 2>/dev/null || true
nft delete table inet ${second_table} 2>/dev/null || true
$(nft_forget_managed "${first_dest}")
$(nft_forget_managed "${second_dest}")
EOF

  local first; first=$(make_profile_firewall "fw-layer-a" "${first_table}" "${first_dest}")
  local second; second=$(make_profile_firewall "fw-layer-b" "${second_table}" "${second_dest}")

  must_hl "${dir}/apply-a.log" "apply first firewall profile" -- apply "${first}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }
  must_hl "${dir}/apply-b.log" "apply second firewall profile" -- apply "${second}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  must_remote "both profiles are included by name and both tables are loaded" <<EOF
$(nft_include_test "${first_dest}")
$(nft_include_test "${second_dest}")
nft list table inet ${first_table} >/dev/null 2>&1
nft list table inet ${second_table} >/dev/null 2>&1
EOF

  must_hl "${dir}/rollback-a.log" "rollback the first profile" -- rollback "${first}" "${remote_args[@]}"

  must_remote "only the first profile's include and file are gone; the second survives" <<EOF
if $(nft_include_test "${first_dest}"); then exit 1; fi
test ! -e ${first_dest}
$(nft_include_test "${second_dest}")
test -e ${second_dest}
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  must_hl "${dir}/rollback-b.log" "rollback the second profile" -- rollback "${second}" "${remote_args[@]}"

  must_remote "the second rollback leaves no hardline include behind" <<EOF
if $(nft_include_test "${second_dest}"); then exit 1; fi
test ! -e ${second_dest}
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  ssh_cmd "sudo bash -seo pipefail" <<EOF >/dev/null 2>&1 || true
nft delete table inet ${first_table} 2>/dev/null || true
nft delete table inet ${second_table} 2>/dev/null || true
$(nft_forget_managed "${first_dest}")
$(nft_forget_managed "${second_dest}")
EOF
  scenario_end
}

# ── firewall-activation: apply loads the ruleset, with no service step at all ─
scenario_firewall_activation() {
  local dir="${ARTIFACT_ROOT}/firewall-activation"
  reset_dir "${dir}"
  scenario_start "firewall-activation: the firewall step loads the ruleset itself, in declared order"
  guard_can_sign || return

  local table="hardline_fw_activate"
  local dest="/etc/nftables.d/96-hardline-fw-activate.nft"

  ssh_cmd "sudo bash -seo pipefail" <<EOF
nft delete table inet ${table} 2>/dev/null || true
$(nft_forget_managed "${dest}")
EOF

  must_remote "table absent before apply (control: proves apply has to load it)" <<EOF
if nft list table inet ${table} >/dev/null 2>&1; then exit 1; fi
EOF

  local pdir; pdir=$(make_profile_firewall_only "fw-activate" "${table}" "${dest}")
  must_hl "${dir}/apply.log" "apply firewall-only profile" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  # No service step exists in this profile, so a live table can only have come
  # from the plugin's own load.
  must_remote "the table is live immediately after apply, without any service restart" <<EOF
nft list table inet ${table} >/dev/null 2>&1
nft list chain inet ${table} input | grep -q 'policy drop'
EOF

  # The kernel prints a chain in evaluation order, so this is the declared
  # order surviving all the way to the running ruleset: the invalid-state drop
  # has to precede the accepts it was written before.
  must_remote "the loaded chain keeps the declared rule order" <<EOF
order=\$(nft list chain inet ${table} input | grep -n -e 'ct state invalid drop' -e 'iif "lo" accept' -e 'tcp dport 22 accept' | cut -d: -f1 | tr '\n' ' ')
test "\$(echo \${order} | awk '{print (\$1<\$2 && \$2<\$3) ? "ok" : "bad"}')" = "ok"
EOF

  must_hl "${dir}/rollback.log" "rollback firewall-only profile" -- rollback "${pdir}" "${remote_args[@]}"

  must_remote "rollback leaves no include, no file, and a config that still parses" <<EOF
if $(nft_include_test "${dest}"); then exit 1; fi
test ! -e ${dest}
nft -c -f ${NFT_MAIN_CONFIG}
EOF

  ssh_cmd "sudo bash -seo pipefail" <<EOF >/dev/null 2>&1 || true
nft delete table inet ${table} 2>/dev/null || true
$(nft_forget_managed "${dest}")
EOF
  scenario_end
}

# ── ssh-policy-activation: apply proves the policy from sshd, not from the file ─
# The drop-in sorts before the starter profile's own file, so its keywords win
# the first-match-wins race in sshd_config.d. They are chosen not to overlap
# with what the starter declares, so this scenario reads cleanly whether or not
# the base profile has been applied.
scenario_ssh_policy_activation() {
  local dir="${ARTIFACT_ROOT}/ssh-policy-activation"
  reset_dir "${dir}"
  scenario_start "ssh-policy-activation: the ssh step activates the policy and verifies it with sshd -T"
  guard_can_sign || return

  local dest="/etc/ssh/sshd_config.d/00-hardline-itest-ssh.conf"
  ssh_cmd "sudo rm -f ${dest}"

  must_remote "sshd does not already report the test policy (control)" <<EOF
if sudo sshd -T | grep -qix 'maxsessions 7'; then exit 1; fi
EOF

  local pdir; pdir=$(make_profile_ssh_only "ssh-activate" "${dest}" '{"MaxSessions": 7, "ClientAliveInterval": 300}')
  local mark0 cur; mark0="$(svc_actmark "${SSH_UNIT}")"; cur="$(journal_cursor)"
  must_hl "${dir}/apply.log" "apply ssh-only profile" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  # sshd is the witness: the running daemon has to report the policy, and the
  # unit has to show it was actually reloaded. Neither fact comes from hardline.
  must_remote "sshd reports the declared policy at the declared mode" <<EOF
test "\$(sudo stat -c %a ${dest})" = "600"
sudo sshd -T | grep -qix 'maxsessions 7'
sudo sshd -T | grep -qix 'clientaliveinterval 300'
EOF
  svc_acted_since "${SSH_UNIT}" "${mark0}" "${cur}" \
    || note_fail "sshd not reloaded on apply (independent: MainPID + StateChange unchanged, no journal reload)"

  must_hl "${dir}/rollback.log" "rollback ssh-only profile" -- rollback "${pdir}" "${remote_args[@]}"
  must_remote "rollback removes the drop-in, and sshd no longer runs its policy" <<EOF
test ! -e ${dest}
sudo sshd -t
if sudo sshd -T | grep -qix 'maxsessions 7'; then exit 1; fi
EOF

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── ssh-lockout-refused: a policy that would cut this run off is not activated ─
scenario_ssh_lockout_refused() {
  local dir="${ARTIFACT_ROOT}/ssh-lockout-refused"
  reset_dir "${dir}"
  scenario_start "ssh-lockout-refused: apply refuses a policy that would lock hardline out, and leaves nothing behind"
  guard_can_sign || return

  local dest="/etc/ssh/sshd_config.d/00-hardline-itest-lockout.conf"
  ssh_cmd "sudo rm -f ${dest}"

  # This run authenticates by key, so a policy disabling public keys would take
  # the host away from the tool applying it.
  local pdir; pdir=$(make_profile_ssh_only "ssh-lockout" "${dest}" '{"PubkeyAuthentication": "no"}')
  expect_hl_fail "${dir}/apply.log" "apply refuses the lockout policy" -- apply "${pdir}" "${remote_args[@]}"

  grep -qi "refusing to activate" "${dir}/apply.log" \
    || note_fail "apply failed for some other reason than the lockout guard"

  # The refusal has to leave the host as it was. sshd may well be reloaded on
  # the way out, because the rollback reloads whatever is on disk once the bad
  # drop-in is gone; what must never happen is the daemon running the policy
  # that was refused.
  must_remote "no drop-in survives and sshd still accepts public keys" <<EOF
test ! -e ${dest}
sudo sshd -t
sudo sshd -T | grep -qix 'pubkeyauthentication yes'
EOF

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

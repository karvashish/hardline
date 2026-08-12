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
  must_remote "apply added an include naming this file, not its directory" <<EOF
$(nft_include_test "${dest}")
grep -F -q 'include "${dest}"' ${NFT_MAIN_CONFIG}
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

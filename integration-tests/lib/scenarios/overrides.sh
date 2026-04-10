#!/usr/bin/env bash
# =============================================================================
# overrides.sh — runtime overrides feature scenarios (8 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# The runtime-overrides feature follows the terraform.tfvars pattern:
#   * A single "profile.overrides.json" file per profile directory is
#     auto-discovered when present.
#   * `--overrides-file PATH` takes precedence over auto-discovery.
#   * `profile.overrides.json` is EXCLUDED from the signed manifest so users
#     can freely edit it without invalidating the signature.
#   * Keys must appear in the profile's `allowed_overrides` list.
#
# These scenarios exercise the feature end-to-end: verify-profile error paths
# (local to the runner, no VM needed), plus plan/apply on the remote VM.

# ── OV-1. overrides-auto-discovered ─────────────────────────────────────────
scenario_overrides_auto_discovered() {
  scenario_start "overrides-auto-discovered: verify-profile picks up profile.overrides.json automatically"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-auto.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-auto" "${dest}" "AutoOverride=true" "ssh_port feature_flag")
  # Write the overrides file AFTER signing — mandatory to prove the file does
  # not invalidate the signature (the editability invariant).
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "ssh_port": 2222, "feature_flag": true }
EOJSON

  local ec
  "${BINARY_PATH}" verify-profile "${pdir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -eq 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile rejected auto-discovered overrides (ec=${ec})"
  fi
}

# ── OV-2. overrides-signature-unaffected ────────────────────────────────────
scenario_overrides_signature_unaffected() {
  scenario_start "overrides-signature-unaffected: editing profile.overrides.json after signing does not break verify"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-sig.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-sig" "${dest}" "SigInvariant=yes" "ssh_port")

  # First pass: no overrides file present — must verify.
  "${BINARY_PATH}" verify-profile "${pdir}" >/dev/null 2>&1 || {
    scenario_fail "verify-profile failed on signed profile without overrides file"
    return
  }

  # Second pass: write overrides file post-sign and verify again.
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "ssh_port": 2222 }
EOJSON
  "${BINARY_PATH}" verify-profile "${pdir}" >/dev/null 2>&1 || {
    scenario_fail "verify-profile failed after writing profile.overrides.json post-sign"
    return
  }

  # Third pass: mutate the overrides file content (simulating a user edit)
  # and verify again — signature must still be valid.
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "ssh_port": 2200 }
EOJSON
  "${BINARY_PATH}" verify-profile "${pdir}" >/dev/null 2>&1 || {
    scenario_fail "verify-profile failed after editing profile.overrides.json post-sign"
    return
  }

  scenario_pass
}

# ── OV-3. overrides-explicit-flag-wins ──────────────────────────────────────
scenario_overrides_explicit_flag_wins() {
  scenario_start "overrides-explicit-flag-wins: --overrides-file path wins over auto-discovered file"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-flag.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-flag" "${dest}" "FlagWins=yes" "ssh_port")

  # Auto-discovered file contains a key that IS in allowed_overrides — would
  # pass on its own.
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "ssh_port": 2222 }
EOJSON

  # Explicit file contains a key that is NOT in allowed_overrides. If the
  # explicit flag is honored, verify MUST fail. If it were ignored in favor of
  # the auto-discovered file, verify would pass — which would be a bug.
  local explicit_path="${pdir}/explicit-overrides.json"
  cat > "${explicit_path}" <<'EOJSON'
{ "banned_key": "value" }
EOJSON

  local ec
  "${BINARY_PATH}" verify-profile "${pdir}" --overrides-file "${explicit_path}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted explicit overrides file containing a disallowed key (auto-discovery was not superseded)"
  fi
}

# ── OV-4. overrides-unknown-key-rejected ────────────────────────────────────
scenario_overrides_unknown_key_rejected() {
  scenario_start "overrides-unknown-key-rejected: keys outside allowed_overrides are rejected"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-bad-key.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-bad-key" "${dest}" "BadKey=test" "ssh_port")
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "smtp_port": 25 }
EOJSON

  local out ec
  out=$("${BINARY_PATH}" verify-profile "${pdir}" 2>&1) && ec=0 || ec=$?
  if [[ $ec -ne 0 ]] && echo "${out}" | grep -qi "does not allow overrides"; then
    scenario_pass
  else
    scenario_fail "expected disallowed-key rejection; ec=${ec}, output: ${out}"
  fi
}

# ── OV-5. overrides-invalid-json-rejected ───────────────────────────────────
scenario_overrides_invalid_json_rejected() {
  scenario_start "overrides-invalid-json-rejected: non-object/malformed overrides file is rejected"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-bad-json.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-bad-json" "${dest}" "BadJSON=yes" "ssh_port")

  # A JSON array is valid JSON but not a JSON object — must be rejected.
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
["ssh_port", 2222]
EOJSON

  local ec
  "${BINARY_PATH}" verify-profile "${pdir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted a non-object overrides file"
  fi
}

# ── OV-6. overrides-missing-flag-file ───────────────────────────────────────
scenario_overrides_missing_flag_file() {
  scenario_start "overrides-missing-flag-file: --overrides-file pointing at a missing path fails cleanly"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-missing.conf"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-missing" "${dest}" "MissingFlag=yes" "ssh_port")
  local ghost="${DYNAMIC_PROFILES_DIR}/does-not-exist/overrides.json"

  local out ec
  out=$("${BINARY_PATH}" verify-profile "${pdir}" --overrides-file "${ghost}" 2>&1) && ec=0 || ec=$?
  if [[ $ec -ne 0 ]] && echo "${out}" | grep -qi "overrides file"; then
    scenario_pass
  else
    scenario_fail "expected clean missing-overrides-file error; ec=${ec}, output: ${out}"
  fi
}

# ── OV-7. overrides-apply-auto ──────────────────────────────────────────────
scenario_overrides_apply_auto() {
  scenario_start "overrides-apply-auto: apply succeeds with auto-discovered profile.overrides.json"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-apply-auto.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-apply-auto" "${dest}" "AutoApply=ok" "ssh_port")
  cat > "${pdir}/profile.overrides.json" <<'EOJSON'
{ "ssh_port": 2222 }
EOJSON

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed with auto-discovered overrides (ec=${ec})"
    ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
    return
  fi

  if ssh_cmd "sudo test -f ${dest}" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "expected template file to exist after apply: ${dest}"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── OV-8. overrides-apply-flag ──────────────────────────────────────────────
scenario_overrides_apply_flag() {
  scenario_start "overrides-apply-flag: apply succeeds with --overrides-file pointing outside profile dir"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dest="/etc/hardline.d/99-hardline-overrides-apply-flag.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_with_allowed_overrides "ov-apply-flag" "${dest}" "FlagApply=ok" "ssh_port")
  # Explicit path lives OUTSIDE the profile directory and would never be
  # auto-discovered.
  local explicit="${DYNAMIC_PROFILES_DIR}/ov-apply-flag-external.json"
  cat > "${explicit}" <<'EOJSON'
{ "ssh_port": 2200 }
EOJSON

  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --overrides-file "${explicit}" >/dev/null 2>&1
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_fail "apply failed with --overrides-file (ec=${ec})"
    ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
    return
  fi

  if ssh_cmd "sudo test -f ${dest}" 2>/dev/null; then
    scenario_pass
  else
    scenario_fail "expected template file to exist after apply: ${dest}"
  fi
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

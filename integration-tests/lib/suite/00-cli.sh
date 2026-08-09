#!/usr/bin/env bash
# =============================================================================
# 00-cli.sh — CLI surface, profile verification, plan reports, plugin guard
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── cli-basics: version output + verify-profile/vp on a real signed profile ──
scenario_cli_basics() {
  local dir="${ARTIFACT_ROOT}/cli-basics"
  reset_dir "${dir}"
  scenario_start "cli-basics: version/-v output; verify-profile + vp pass on signed profile"

  run_hl "${dir}/version.txt" -- version || note_fail "version exited non-zero"
  run_hl "${dir}/version-short.txt" -- -v || note_fail "-v exited non-zero"
  grep -q "hardline version" "${dir}/version.txt" || note_fail "version missing 'hardline version'"
  grep -q "hardline version" "${dir}/version-short.txt" || note_fail "-v missing 'hardline version'"

  must_hl "${dir}/verify.log" "verify-profile on signed profile" -- verify-profile "${PROFILE_DIR}" --log-file "${dir}/verify-internal.log"
  must_hl "${dir}/vp.log" "vp alias on signed profile" -- vp "${PROFILE_DIR}" --debug --log-file "${dir}/vp-internal.log"
  grep -q "profile verification passed" "${dir}/verify.log" \
    || note_fail "verify-profile did not log 'profile verification passed'"

  scenario_end
}

# ── verify-rejections: every malformed/unauthorized profile is refused ───────
scenario_verify_rejections() {
  local dir="${ARTIFACT_ROOT}/verify-rejections"
  reset_dir "${dir}"
  scenario_start "verify-rejections: unsigned/tampered/malformed/unknown-plugin/missing-template/wrong-os/min-version/bad-format all refused"
  guard_can_sign || return

  local p

  # 1. Unsigned profile.
  p=$(make_raw_profile "vr-unsigned")
  expect_hl_fail "${dir}/unsigned.log" "unsigned profile accepted" -- verify-profile "${p}"

  # 2. Tampered after signing.
  p=$(make_profile_packages_install "vr-tampered" "tree")
  sed -i 's/Test: vr-tampered/HACKED/' "${p}/profile.json"
  expect_hl_fail "${dir}/tampered.log" "tampered profile accepted" -- verify-profile "${p}"
  grep -qi "signature" "${dir}/tampered.log" || note_fail "tampered failure not attributed to signature"

  # 3. Malformed JSON.
  p="${DYNAMIC_PROFILES_DIR}/vr-malformed"
  mkdir -p "${p}"
  echo "THIS IS NOT JSON {{{" > "${p}/profile.json"
  expect_hl_fail "${dir}/malformed.log" "malformed profile accepted" -- verify-profile "${p}"

  # 4. Unknown plugin.
  p="${DYNAMIC_PROFILES_DIR}/vr-unknown-plugin"
  mkdir -p "${p}/actions"
  cat > "${p}/profile.json" <<'EOJSON'
{
  "id": "vr-unknown-plugin", "display_name": "Unknown", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-custom.json"], "templates": []
}
EOJSON
  echo '{ "steps": [{ "id": "s1", "plugin": "nonexistent_plugin_xyz", "config": {} }] }' > "${p}/actions/00-custom.json"
  sign_profile "${p}" >/dev/null 2>&1 || true
  expect_hl_fail "${dir}/unknown-plugin.log" "unknown-plugin profile accepted" -- verify-profile "${p}"

  # 5. Missing template file on disk.
  p="${DYNAMIC_PROFILES_DIR}/vr-missing-template"
  mkdir -p "${p}/actions"
  cat > "${p}/profile.json" <<'EOJSON'
{
  "id": "vr-missing-template", "display_name": "Missing tmpl", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-tmpl.json"], "templates": ["templates/does-not-exist.tmpl"]
}
EOJSON
  echo '{ "steps": [{ "id": "s1", "plugin": "template", "config": { "src": "templates/does-not-exist.tmpl", "dest": "/etc/hardline.d/x.conf", "mode": "0644" } }] }' > "${p}/actions/00-tmpl.json"
  sign_profile "${p}" >/dev/null 2>&1 || true
  expect_hl_fail "${dir}/missing-template.log" "missing-template profile accepted" -- verify-profile "${p}"

  # 6. Wrong OS (gated at plan against the remote host).
  p=$(make_raw_profile "vr-wrong-os" "centos" "9")
  sign_profile "${p}" >/dev/null 2>&1 || true
  expect_hl_fail "${dir}/wrong-os.log" "wrong-OS profile accepted" -- plan "${p}" "${remote_args[@]}"

  # 7. min_hardline gate (999.0.0 is unsatisfiable).
  p=$(make_profile_min_version "vr-min-version" "999.0.0")
  expect_hl_fail "${dir}/min-version.log" "min_hardline=999 profile accepted" -- plan "${p}" "${remote_args[@]}"

  # 8. Invalid --report-format.
  expect_hl_fail "${dir}/bad-format.log" "invalid report format accepted" -- plan "${PROFILE_DIR}" "${remote_args[@]}" --report-format bogus

  scenario_end
}

# ── plan-reports: JSON/YAML/MD reports + plan is read-only on the host ───────
scenario_plan_reports() {
  local dir="${ARTIFACT_ROOT}/plan-reports"
  reset_dir "${dir}"
  scenario_start "plan-reports: JSON/YAML/MD (long+short flags) and plan does not mutate the host"
  guard_static_profiles || return
  guard_can_sign || return

  must_hl "${dir}/plan-long.log" "plan json (long flags)" -- \
    plan "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --report-file "${dir}/plan-auto.json"
  must_hl "${dir}/plan-short.log" "plan yaml (short flags)" -- \
    plan "${MULTI_SUCCESS_PROFILE}" "${short_remote_args[@]}" \
    --report-file "${dir}/plan.yaml" --report-format yaml -d
  must_hl "${dir}/plan-md.log" "plan md" -- \
    plan "${MULTI_SUCCESS_PROFILE}" "${remote_args[@]}" \
    --report-file "${dir}/plan.md" --report-format md

  jq -er '.kind == "hardline_plan" and .profile.id == "itest-multi-plugin-success"' \
    "${dir}/plan-auto.json" >/dev/null 2>&1 || note_fail "json plan report wrong kind/profile"
  jq -er '.steps | length > 0' "${dir}/plan-auto.json" >/dev/null 2>&1 || note_fail "json plan report has no steps"
  grep -q "kind: hardline_plan" "${dir}/plan.yaml" 2>/dev/null || note_fail "yaml plan report missing header"
  grep -q "^# Hardline Plan Report" "${dir}/plan.md" 2>/dev/null || note_fail "md plan report missing header"

  # Read-only proof: plan a managed file that does not exist, confirm plan never
  # created it on the host.
  local dest="/etc/hardline.d/99-hardline-plan-readonly.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local p; p=$(make_profile_template "plan-readonly" "${dest}" "PlanReadOnly=true")
  must_hl "${dir}/plan-readonly.log" "plan on unmanaged dest" -- plan "${p}" "${remote_args[@]}"
  must_remote "plan must not create the managed file" <<EOF
test ! -e ${dest}
EOF

  scenario_end
}

# ── plugin-dir-rejected: a world-writable plugin dir is refused ──────────────
scenario_plugin_dir_rejected() {
  local dir="${ARTIFACT_ROOT}/plugin-dir-rejected"
  reset_dir "${dir}"
  scenario_start "plugin-dir-rejected: world-writable plugins dir aborts the run"

  local plugin_dir; plugin_dir="$(dirname "${BINARY_PATH}")/plugins"
  mkdir -p "${plugin_dir}"
  chmod 0777 "${plugin_dir}"
  touch "${plugin_dir}/dummy.so"

  local ec=0
  run_hl "${dir}/plan.log" -- plan "${PROFILE_DIR}" "${remote_args[@]}" || ec=$?

  rm -f "${plugin_dir}/dummy.so"
  chmod 0755 "${plugin_dir}"

  [ "${ec}" -ne 0 ] || note_fail "plan accepted a world-writable plugin dir"
  grep -q "world-writable" "${dir}/plan.log" || note_fail "error did not mention 'world-writable'"

  scenario_end
}

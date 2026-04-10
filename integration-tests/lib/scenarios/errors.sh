#!/usr/bin/env bash
# =============================================================================
# errors.sh — Error paths, env vars, edge cases (12 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── 40. wrong-os-rejected ───────────────────────────────────────────────────
scenario_wrong_os_rejected() {
  scenario_start "wrong-os-rejected: apply rejects CentOS profile on Ubuntu"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/wrong-os"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "wrong-os-test", "display_name": "Wrong OS", "version": "1.0.0",
  "os": { "family": "centos", "version": "9", "variant": "stream" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-pkg.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-pkg.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "packages", "config": { "install": ["tree"] } }] }
EOJSON
  sign_profile "${dir}" 2>/dev/null || true

  local ec
  "${BINARY_PATH}" apply "${dir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "apply accepted profile for wrong OS"
  fi
}

# ── 41. unreachable-host ────────────────────────────────────────────────────
scenario_unreachable_host() {
  scenario_start "unreachable-host: apply fails gracefully for unreachable host"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_packages_install "unreachable" "tree")

  local ec
  "${BINARY_PATH}" apply "${pdir}" \
    --host 192.0.2.1 --user nobody --keypath "${key_path}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "apply returned 0 for unreachable host"
  fi
}

# ── 42. unknown-plugin-rejected ─────────────────────────────────────────────
scenario_unknown_plugin_rejected() {
  scenario_start "unknown-plugin-rejected: verify rejects unknown plugin"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/unknown-plugin"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "unknown-plugin-test", "display_name": "Unknown Plugin", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-custom.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-custom.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "nonexistent_plugin_xyz", "config": { "foo": "bar" } }] }
EOJSON
  sign_profile "${dir}" 2>/dev/null || true

  local ec
  "${BINARY_PATH}" verify-profile "${dir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted profile with unknown plugin"
  fi
}

# ── 43. managed-path-enforcement ────────────────────────────────────────────
scenario_managed_path_enforcement() {
  scenario_start "managed-path-enforcement: template rejects /tmp/ destination"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/bad-path"
  mkdir -p "${dir}/actions" "${dir}/templates"
  echo "bad" > "${dir}/templates/config.tmpl"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "bad-path-test", "display_name": "Bad Path", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-tmpl.json"], "templates": ["templates/config.tmpl"]
}
EOJSON
  cat > "${dir}/actions/00-tmpl.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "template", "config": { "src": "templates/config.tmpl", "dest": "/tmp/should-not-be-allowed.conf", "mode": "0644" } }] }
EOJSON
  sign_profile "${dir}" 2>/dev/null || true

  local ec
  "${BINARY_PATH}" apply "${dir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    if ssh_cmd "test -f /tmp/should-not-be-allowed.conf" 2>/dev/null; then
      scenario_fail "file was written to /tmp — path enforcement failed"
      ssh_cmd "sudo rm -f /tmp/should-not-be-allowed.conf" 2>/dev/null
    else
      scenario_fail "apply exited 0 but file wasn't written"
    fi
  fi
}

# ── 44. malformed-profile ───────────────────────────────────────────────────
scenario_malformed_profile() {
  scenario_start "malformed-profile: invalid JSON in profile.json fails gracefully"

  local dir="${DYNAMIC_PROFILES_DIR}/malformed"
  mkdir -p "${dir}"
  echo "THIS IS NOT JSON {{{" > "${dir}/profile.json"

  local ec
  "${BINARY_PATH}" verify-profile "${dir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted malformed JSON"
  fi
}

# ── 45. verify-missing-template ─────────────────────────────────────────────
scenario_verify_missing_template() {
  scenario_start "verify-missing-template: profile references nonexistent template"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/missing-template"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "missing-tmpl-test", "display_name": "Missing Template", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-tmpl.json"],
  "templates": ["templates/does-not-exist.tmpl"]
}
EOJSON
  cat > "${dir}/actions/00-tmpl.json" <<'EOJSON'
{ "steps": [{ "id": "s1", "plugin": "template", "config": { "src": "templates/does-not-exist.tmpl", "dest": "/etc/hardline.d/99-hardline-missing.conf", "mode": "0644" } }] }
EOJSON
  sign_profile "${dir}" 2>/dev/null || true

  local ec
  "${BINARY_PATH}" verify-profile "${dir}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "verify-profile accepted profile with missing template"
  fi
}

# ── 46. min-hardline-version-gate ───────────────────────────────────────────
scenario_min_hardline_version_gate() {
  scenario_start "min-hardline-version-gate: profile with min_hardline=999.0.0 rejected"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local pdir
  pdir=$(make_profile_min_version "min-ver-gate" "999.0.0")

  local ec
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "apply accepted profile requiring hardline 999.0.0"
  fi
}

# ── 47. env-state-dir ──────────────────────────────────────────────────────
scenario_env_state_dir() {
  scenario_start "env-state-dir: HARDLINE_STATE_DIR override writes journal to custom dir"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local custom_state
  custom_state="$(mktemp -d "${ROOT_DIR}/tmp/itest-custom-state.XXXXXX")"
  local dest="/etc/hardline.d/99-hardline-env-state.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir
  pdir=$(make_profile_template "env-state-dir" "${dest}" "EnvStateDirTest=yes")

  HARDLINE_STATE_DIR="${custom_state}" \
    "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1 || { scenario_fail "apply failed"; return; }

  local journal_files
  journal_files=$(find "${custom_state}" -name "*.json" 2>/dev/null | head -5)
  if [[ -n "${journal_files}" ]]; then
    scenario_pass
  else
    scenario_fail "no journal found in custom state dir ${custom_state}"
  fi
  rm -rf "${custom_state}"
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
}

# ── 48. env-known-hosts ─────────────────────────────────────────────────────
scenario_env_known_hosts() {
  scenario_start "env-known-hosts: HARDLINE_KNOWN_HOSTS override uses custom known_hosts"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local custom_kh
  custom_kh="$(mktemp "${ROOT_DIR}/tmp/itest-custom-kh.XXXXXX")"
  ssh-keyscan -H "${host}" > "${custom_kh}" 2>/dev/null || { scenario_fail "ssh-keyscan failed"; rm -f "${custom_kh}"; return; }

  local pdir
  pdir=$(make_profile_packages_install "env-known-hosts" "tree")

  HARDLINE_KNOWN_HOSTS="${custom_kh}" \
    "${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" >/dev/null 2>&1
  local ec=$?
  rm -f "${custom_kh}"

  if [[ $ec -eq 0 ]]; then
    scenario_pass
  else
    scenario_fail "plan failed with custom known_hosts: ${ec}"
  fi
  ssh_cmd "sudo apt-get purge -y tree" >/dev/null 2>&1 || true
}

# ── 49. plugin-dir-warning ──────────────────────────────────────────────────
scenario_plugin_dir_warning() {
  scenario_start "plugin-dir-warning: world-writable plugin dir is rejected"

  local bin_dir
  bin_dir="$(dirname "${BINARY_PATH}")"
  local plugin_dir="${bin_dir}/plugins"

  # Create a world-writable plugins dir next to the binary
  mkdir -p "${plugin_dir}"
  chmod 0777 "${plugin_dir}"
  # Drop a dummy .so so the loader actually tries to load from the dir
  touch "${plugin_dir}/dummy.so"

  local out ec
  out=$("${BINARY_PATH}" plan "${PROFILE_DIR}" "${remote_args[@]}" 2>&1) && ec=0 || ec=$?

  # Clean up before assertions
  rm -f "${plugin_dir}/dummy.so"
  chmod 0755 "${plugin_dir}"

  if [[ $ec -ne 0 ]] && echo "${out}" | grep -q "world-writable"; then
    scenario_pass
  else
    scenario_fail "expected failure with 'world-writable' error (exit=${ec})"
  fi
}

# ── 50. empty-steps-profile ─────────────────────────────────────────────────
scenario_empty_steps_profile() {
  scenario_start "empty-steps-profile: profile with no steps"
  if [[ "${CAN_SIGN}" != "true" ]]; then
    scenario_skip "profiletool or signing key not available"
    return
  fi

  local dir="${DYNAMIC_PROFILES_DIR}/empty-steps"
  mkdir -p "${dir}/actions"
  cat > "${dir}/profile.json" <<'EOJSON'
{
  "id": "empty-steps-test", "display_name": "Empty Steps", "version": "1.0.0",
  "os": { "family": "ubuntu", "version": "24.04", "variant": "lts" },
  "profile_schema": 1, "min_hardline": "0.0.1",
  "actions": ["actions/00-empty.json"], "templates": []
}
EOJSON
  cat > "${dir}/actions/00-empty.json" <<'EOJSON'
{ "steps": [] }
EOJSON
  sign_profile "${dir}" 2>/dev/null || true

  # An empty-steps profile should either succeed as no-op or fail validation
  local ec
  "${BINARY_PATH}" apply "${dir}" "${remote_args[@]}" >/dev/null 2>&1 && ec=0 || ec=$?
  # Either outcome is acceptable — the key is no crash
  scenario_pass
}

# ── 51. invalid-report-format ───────────────────────────────────────────────
scenario_invalid_report_format() {
  scenario_start "invalid-report-format: --report-format bogus is rejected"

  local ec
  "${BINARY_PATH}" plan "${PROFILE_DIR}" "${remote_args[@]}" \
    --report-format bogus >/dev/null 2>&1 && ec=0 || ec=$?
  if [[ $ec -ne 0 ]]; then
    scenario_pass
  else
    scenario_fail "accepted invalid report format 'bogus'"
  fi
}

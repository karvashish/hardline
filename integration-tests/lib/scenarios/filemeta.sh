#!/usr/bin/env bash
# =============================================================================
# filemeta.sh — file_meta plugin scenarios (12 scenarios)
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# file_meta re-stamps metadata on paths that already exist, so each scenario
# first prepares a target with known mode/owner/group/attrs over SSH, then
# applies a dynamically-generated single-step profile and inspects the result.

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Recreate a plain file with known metadata and no managed attrs.
_fm_reset_file() {
  local path="$1" mode="$2" owner="$3" group="$4"
  ssh_cmd "sudo bash -se" <<EOF
set -uo pipefail
chattr -ai -- '${path}' 2>/dev/null || true
printf 'itest file-meta\n' > '${path}'
chmod '${mode}' -- '${path}'
chown '${owner}:${group}' -- '${path}'
EOF
}

_fm_make_immutable() { ssh_cmd "sudo chattr +i -- '$1'"; }

# Clear managed attrs and remove the path(s) — safe to call on absent targets.
_fm_cleanup() {
  local p
  for p in "$@"; do
    ssh_cmd "sudo chattr -ai -- '${p}' 2>/dev/null; sudo rm -rf -- '${p}'" >/dev/null 2>&1 || true
  done
}

_fm_mode()  { ssh_cmd "sudo stat -c %a -- '$1'" 2>/dev/null | tr -d '\r\n'; }
_fm_owner() { ssh_cmd "sudo stat -c %U -- '$1'" 2>/dev/null | tr -d '\r\n'; }
_fm_group() { ssh_cmd "sudo stat -c %G -- '$1'" 2>/dev/null | tr -d '\r\n'; }
# Managed-attr flags field from lsattr (e.g. "----i---------e-------").
_fm_flags() { ssh_cmd "sudo lsattr -d -- '$1' 2>/dev/null | awk '{print \$1}'" 2>/dev/null | tr -d '\r\n'; }

# ── 60. file-meta-mode ───────────────────────────────────────────────────────
scenario_file_meta_mode() {
  scenario_start "file-meta-mode: chmod re-stamps an existing file (644 -> 600)"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-mode.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-mode" "${path}" "0600")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_mode "${path}")" == "600" ]]; then
    scenario_pass
  else
    scenario_fail "mode not 600 (got $(_fm_mode "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 61. file-meta-owner-group ────────────────────────────────────────────────
scenario_file_meta_owner_group() {
  scenario_start "file-meta-owner-group: chown re-stamps owner and group"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-owner.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-owner" "${path}" "" "daemon" "daemon")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_owner "${path}")" == "daemon" && "$(_fm_group "${path}")" == "daemon" ]]; then
    scenario_pass
  else
    scenario_fail "owner/group not daemon:daemon (got $(_fm_owner "${path}"):$(_fm_group "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 62. file-meta-immutable-set ──────────────────────────────────────────────
scenario_file_meta_immutable_set() {
  scenario_start "file-meta-immutable-set: sets the immutable attr"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-imm.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-imm-set" "${path}" "" "" "" "true")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_flags "${path}")" == *i* ]]; then
    scenario_pass
  else
    scenario_fail "immutable attr not set (flags $(_fm_flags "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 63. file-meta-immutable-clear ────────────────────────────────────────────
scenario_file_meta_immutable_clear() {
  scenario_start "file-meta-immutable-clear: clears a pre-existing immutable attr"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-immclr.conf"
  _fm_reset_file "${path}" 0644 root root
  _fm_make_immutable "${path}"
  if [[ "$(_fm_flags "${path}")" != *i* ]]; then scenario_fail "setup: immutable not set before test"; _fm_cleanup "${path}"; return; fi

  local pdir; pdir=$(make_profile_file_meta "fm-imm-clr" "${path}" "" "" "" "false")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_flags "${path}")" != *i* ]]; then
    scenario_pass
  else
    scenario_fail "immutable attr not cleared (flags $(_fm_flags "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 64. file-meta-append-only ────────────────────────────────────────────────
scenario_file_meta_append_only() {
  scenario_start "file-meta-append-only: sets the append-only attr"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-append.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-append" "${path}" "" "" "" "" "true")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_flags "${path}")" == *a* ]]; then
    scenario_pass
  else
    scenario_fail "append-only attr not set (flags $(_fm_flags "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 65. file-meta-mode-on-immutable ──────────────────────────────────────────
scenario_file_meta_mode_on_immutable() {
  scenario_start "file-meta-mode-on-immutable: lift -> chmod -> relock on an already-immutable file"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-immmode.conf"
  _fm_reset_file "${path}" 0644 root root
  _fm_make_immutable "${path}"

  # immutable=true keeps the lock; mode 600 must still apply via lift->chmod->relock.
  local pdir; pdir=$(make_profile_file_meta "fm-imm-mode" "${path}" "0600" "" "" "true")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_mode "${path}")" == "600" && "$(_fm_flags "${path}")" == *i* ]]; then
    scenario_pass
  else
    scenario_fail "expected mode 600 + immutable (got mode $(_fm_mode "${path}") flags $(_fm_flags "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 66. file-meta-directory ──────────────────────────────────────────────────
scenario_file_meta_directory() {
  scenario_start "file-meta-directory: stamps the directory itself, not its contents"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local dir="/etc/hardline.d/itest-fm-dir"
  local inner="${dir}/inner.conf"
  ssh_cmd "sudo bash -se" <<EOF
set -uo pipefail
chattr -ai -- '${dir}' 2>/dev/null || true
rm -rf -- '${dir}'
mkdir -p -- '${dir}'
printf 'inner\n' > '${inner}'
chmod 0755 -- '${dir}'
chmod 0644 -- '${inner}'
EOF

  local pdir; pdir=$(make_profile_file_meta "fm-dir" "${dir}" "0700")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "apply failed: ${ec}"; _fm_cleanup "${dir}"; return; fi

  if [[ "$(_fm_mode "${dir}")" == "700" && "$(_fm_mode "${inner}")" == "644" ]]; then
    scenario_pass
  else
    scenario_fail "dir should be 700 and inner unchanged 644 (got dir $(_fm_mode "${dir}") inner $(_fm_mode "${inner}"))"
  fi
  _fm_cleanup "${dir}"
}

# ── 67. file-meta-idempotent ─────────────────────────────────────────────────
scenario_file_meta_idempotent() {
  scenario_start "file-meta-idempotent: second run reports no change"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-idem.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-idem" "${path}" "0600" "root" "root")
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || { scenario_fail "first apply failed"; _fm_cleanup "${path}"; return; }

  local plan_out
  plan_out=$("${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" 2>&1) || true
  if echo "${plan_out}" | grep -qiE '(already|no change|matches|aligned)'; then
    scenario_pass
  else
    scenario_fail "second plan did not report no-change"
  fi
  _fm_cleanup "${path}"
}

# ── 68. file-meta-rollback ───────────────────────────────────────────────────
scenario_file_meta_rollback() {
  scenario_start "file-meta-rollback: restores mode/owner/group/attrs exactly (incl. after immutable-set)"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-rb.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-rb" "${path}" "0600" "daemon" "daemon" "true")
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1 || { scenario_fail "apply failed"; _fm_cleanup "${path}"; return; }

  # Sanity: apply changed everything as requested.
  if [[ "$(_fm_mode "${path}")" != "600" || "$(_fm_owner "${path}")" != "daemon" || "$(_fm_flags "${path}")" != *i* ]]; then
    scenario_fail "apply did not stamp expected metadata"
    _fm_cleanup "${path}"
    return
  fi

  local ec=0
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "rollback failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_mode "${path}")" == "644" && "$(_fm_owner "${path}")" == "root" && \
        "$(_fm_group "${path}")" == "root" && "$(_fm_flags "${path}")" != *i* && "$(_fm_flags "${path}")" != *a* ]]; then
    scenario_pass
  else
    scenario_fail "rollback did not restore 644 root:root no-attrs (got $(_fm_mode "${path}") $(_fm_owner "${path}"):$(_fm_group "${path}") $(_fm_flags "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 69. file-meta-conflict ───────────────────────────────────────────────────
scenario_file_meta_conflict() {
  scenario_start "file-meta-conflict: post-apply drift blocks rollback unless --force-rollback"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-conflict.conf"
  _fm_reset_file "${path}" 0644 root root

  local pdir; pdir=$(make_profile_file_meta "fm-conflict" "${path}" "0600")
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" --keep-local-rollback >/dev/null 2>&1 || { scenario_fail "apply failed"; _fm_cleanup "${path}"; return; }

  # Drift the metadata away from the recorded post-apply snapshot (600 -> 640).
  ssh_cmd "sudo chmod 0640 -- '${path}'"

  local ec=0
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -eq 0 ]]; then scenario_fail "rollback should have refused on drift"; _fm_cleanup "${path}"; return; fi

  ec=0
  "${BINARY_PATH}" rollback "${pdir}" "${remote_args[@]}" --force-rollback >/dev/null 2>&1 || ec=$?
  if [[ $ec -ne 0 ]]; then scenario_fail "force-rollback failed: ${ec}"; _fm_cleanup "${path}"; return; fi

  if [[ "$(_fm_mode "${path}")" == "644" ]]; then
    scenario_pass
  else
    scenario_fail "force-rollback did not restore 644 (got $(_fm_mode "${path}"))"
  fi
  _fm_cleanup "${path}"
}

# ── 70. file-meta-absent-target ──────────────────────────────────────────────
scenario_file_meta_absent_target() {
  scenario_start "file-meta-absent-target: apply fails on a missing path and never creates it"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local path="/etc/hardline.d/itest-fm-absent.conf"
  _fm_cleanup "${path}"   # ensure it does not exist

  local pdir; pdir=$(make_profile_file_meta "fm-absent" "${path}" "0600")
  local ec=0
  "${BINARY_PATH}" apply "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
  if [[ $ec -eq 0 ]]; then scenario_fail "apply should have failed on absent target"; _fm_cleanup "${path}"; return; fi

  if ssh_cmd "test -e '${path}'" 2>/dev/null; then
    scenario_fail "file_meta created a path it should never create"
    _fm_cleanup "${path}"
  else
    scenario_pass
  fi
}

# ── 71. file-meta-rejected-paths ─────────────────────────────────────────────
scenario_file_meta_rejected_paths() {
  scenario_start "file-meta-rejected-paths: plan hard-fails on relative/traversal/control-char/non-ASCII paths"
  if [[ "${CAN_SIGN}" != "true" ]]; then scenario_skip "profiletool or signing key not available"; return; fi

  local all_ok=true
  local -a names=( "fm-bad-rel" "fm-bad-trav" "fm-bad-ctrl" "fm-bad-nonascii" )
  local -a paths=(
    "etc/hardline.d/itest-fm.conf"
    "/etc/hardline.d/../../etc/itest-fm.conf"
    "/etc/hardline.d/itest\u0001fm.conf"
    "/etc/hardline.d/itest-café.conf"
  )

  local i pdir ec
  for i in "${!names[@]}"; do
    pdir=$(make_profile_file_meta_badpath "${names[$i]}" "${paths[$i]}")
    ec=0
    "${BINARY_PATH}" plan "${pdir}" "${remote_args[@]}" >/dev/null 2>&1 || ec=$?
    if [[ $ec -eq 0 ]]; then
      scenario_fail "plan accepted rejected path: ${paths[$i]}"
      all_ok=false
    fi
  done

  $all_ok && scenario_pass
}

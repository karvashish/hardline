#!/usr/bin/env bash
# =============================================================================
# 60-filemeta.sh — file_meta plugin: stamp mode/owner/group/attrs on existing
#                  paths, idempotency, rollback/conflict, and input guards.
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# file_meta re-stamps metadata on paths that already exist, so each case first
# prepares a target with known mode/owner/attrs over SSH, then applies a
# single-step profile and inspects the result.

# Recreate a plain file with known metadata and no managed attrs.
_fm_reset() {
  local path="$1" mode="$2" owner="$3" group="$4"
  ssh_cmd "sudo bash -seo pipefail" <<EOF
chattr -ai -- '${path}' 2>/dev/null || true
printf 'itest file-meta\n' > '${path}'
chmod '${mode}' -- '${path}'
chown '${owner}:${group}' -- '${path}'
EOF
}
_fm_cleanup() { ssh_cmd "sudo chattr -ai -- '$1' 2>/dev/null; sudo rm -rf -- '$1'" >/dev/null 2>&1 || true; }

# ── filemeta-stamp: mode/owner/group/immutable/append-only/dir, plus no-op ──
scenario_filemeta_stamp() {
  local dir="${ARTIFACT_ROOT}/filemeta-stamp"
  reset_dir "${dir}"
  scenario_start "filemeta-stamp: chmod/chown/immutable/append-only/mode-on-immutable/directory + idempotent re-apply"
  guard_can_sign || return

  # A — mode + owner + group + immutable on one file, then prove idempotency.
  local a="/etc/hardline.d/itest-fm-a.conf"
  _fm_reset "${a}" 0644 root root
  local p; p=$(make_profile_file_meta "fm-a" "${a}" "0600" "daemon" "daemon" "true")
  must_hl "${dir}/a.log" "stamp mode+owner+group+immutable" -- apply "${p}" "${remote_args[@]}"
  must_remote "file A is 600 daemon:daemon +immutable" <<EOF
test "\$(stat -c %a ${a})" = "600"
test "\$(stat -c %U ${a})" = "daemon"
test "\$(stat -c %G ${a})" = "daemon"
lsattr -d -- '${a}' | awk '{print \$1}' | grep -q i
EOF
  local fpa1 fpa2; fpa1="$(fp_path "${a}")"
  must_hl "${dir}/a2.log" "re-apply file A (idempotent)" -- apply "${p}" "${remote_args[@]}"
  fpa2="$(fp_path "${a}")"
  [ -n "${fpa1}" ] && [ "${fpa1}" = "${fpa2}" ] || note_fail "file_meta re-apply changed the file (fp ${fpa1} -> ${fpa2})"
  _fm_cleanup "${a}"

  # B — clear a pre-existing immutable attr.
  local b="/etc/hardline.d/itest-fm-b.conf"
  _fm_reset "${b}" 0644 root root
  ssh_cmd "sudo chattr +i -- '${b}'"
  p=$(make_profile_file_meta "fm-b" "${b}" "" "" "" "false")
  must_hl "${dir}/b.log" "clear immutable" -- apply "${p}" "${remote_args[@]}"
  must_remote "file B immutable cleared" <<EOF
if lsattr -d -- '${b}' | awk '{print \$1}' | grep -q i; then exit 1; fi
EOF
  _fm_cleanup "${b}"

  # C — set append-only.
  local c="/etc/hardline.d/itest-fm-c.conf"
  _fm_reset "${c}" 0644 root root
  p=$(make_profile_file_meta "fm-c" "${c}" "" "" "" "" "true")
  must_hl "${dir}/c.log" "set append-only" -- apply "${p}" "${remote_args[@]}"
  must_remote "file C append-only set" <<EOF
lsattr -d -- '${c}' | awk '{print \$1}' | grep -q a
EOF
  _fm_cleanup "${c}"

  # D — chmod on an already-immutable file (lift -> chmod -> relock).
  local d="/etc/hardline.d/itest-fm-d.conf"
  _fm_reset "${d}" 0644 root root
  ssh_cmd "sudo chattr +i -- '${d}'"
  p=$(make_profile_file_meta "fm-d" "${d}" "0600" "" "" "true")
  must_hl "${dir}/d.log" "chmod on immutable" -- apply "${p}" "${remote_args[@]}"
  must_remote "file D is 600 and still immutable" <<EOF
test "\$(stat -c %a ${d})" = "600"
lsattr -d -- '${d}' | awk '{print \$1}' | grep -q i
EOF
  _fm_cleanup "${d}"

  # E — stamp a directory itself, not its contents.
  local e="/etc/hardline.d/itest-fm-dir"
  local inner="${e}/inner.conf"
  ssh_cmd "sudo bash -seo pipefail" <<EOF
chattr -ai -- '${e}' 2>/dev/null || true
rm -rf -- '${e}'; mkdir -p -- '${e}'
printf 'inner\n' > '${inner}'
chmod 0755 -- '${e}'; chmod 0644 -- '${inner}'
EOF
  p=$(make_profile_file_meta "fm-e" "${e}" "0700")
  must_hl "${dir}/e.log" "stamp directory" -- apply "${p}" "${remote_args[@]}"
  must_remote "dir E is 700 and inner stays 644" <<EOF
test "\$(stat -c %a ${e})" = "700"
test "\$(stat -c %a ${inner})" = "644"
EOF
  _fm_cleanup "${e}"

  scenario_end
}

# ── filemeta-rollback-conflict: exact restore + drift needs --force-rollback ─
scenario_filemeta_rollback_conflict() {
  local dir="${ARTIFACT_ROOT}/filemeta-rollback"
  reset_dir "${dir}"
  scenario_start "filemeta-rollback-conflict: rollback restores 644 root:root no-attrs; drift needs --force-rollback"
  guard_can_sign || return

  local path="/etc/hardline.d/itest-fm-rb.conf"
  _fm_reset "${path}" 0644 root root
  local p; p=$(make_profile_file_meta "fm-rb" "${path}" "0600" "daemon" "daemon" "true")
  must_hl "${dir}/apply.log" "apply (600 daemon:daemon +i)" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { _fm_cleanup "${path}"; scenario_end; return; }
  must_remote "metadata stamped before rollback" <<EOF
test "\$(stat -c %a ${path})" = "600"
test "\$(stat -c %U ${path})" = "daemon"
lsattr -d -- '${path}' | awk '{print \$1}' | grep -q i
EOF
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${p}" "${remote_args[@]}"
  must_remote "rollback restored 644 root:root with no managed attrs" <<EOF
test "\$(stat -c %a ${path})" = "644"
test "\$(stat -c %U ${path})" = "root"
test "\$(stat -c %G ${path})" = "root"
if lsattr -d -- '${path}' | awk '{print \$1}' | grep -q i; then exit 1; fi
if lsattr -d -- '${path}' | awk '{print \$1}' | grep -q a; then exit 1; fi
EOF
  _fm_cleanup "${path}"

  # Conflict: drift the metadata after apply, rollback must refuse then force.
  _fm_reset "${path}" 0644 root root
  p=$(make_profile_file_meta "fm-conflict" "${path}" "0600")
  must_hl "${dir}/c-apply.log" "apply for conflict" -- apply "${p}" "${remote_args[@]}" --keep-local-rollback || { _fm_cleanup "${path}"; scenario_end; return; }
  ssh_cmd "sudo chmod 0640 -- '${path}'"
  expect_hl_fail "${dir}/c-refuse.log" "rollback refused on metadata drift" -- rollback "${p}" "${remote_args[@]}"
  must_hl "${dir}/c-force.log" "force-rollback after drift" -- rollback "${p}" "${remote_args[@]}" --force-rollback
  must_remote "force-rollback restored mode 644" <<EOF
test "\$(stat -c %a ${path})" = "644"
EOF
  _fm_cleanup "${path}"

  scenario_end
}

# ── filemeta-guards: absent target fails (never creates); bad paths rejected ─
scenario_filemeta_guards() {
  local dir="${ARTIFACT_ROOT}/filemeta-guards"
  reset_dir "${dir}"
  scenario_start "filemeta-guards: absent target fails+never created; relative/traversal/control/non-ASCII paths rejected at plan"
  guard_can_sign || return

  # Absent target: apply must fail and must not create the path.
  local path="/etc/hardline.d/itest-fm-absent.conf"
  _fm_cleanup "${path}"
  local p; p=$(make_profile_file_meta "fm-absent" "${path}" "0600")
  expect_hl_fail "${dir}/absent.log" "apply on absent target rejected" -- apply "${p}" "${remote_args[@]}"
  must_remote "absent target was not created" <<EOF
test ! -e '${path}'
EOF

  # Rejected path shapes: each must hard-fail at plan.
  local -a names=( fm-bad-rel fm-bad-trav fm-bad-ctrl fm-bad-nonascii )
  local -a paths=(
    "etc/hardline.d/itest-fm.conf"
    "/etc/hardline.d/../../etc/itest-fm.conf"
    "/etc/hardline.d/itest\\u0001fm.conf"
    "/etc/hardline.d/itest-café.conf"
  )
  local i pp
  for i in "${!names[@]}"; do
    pp=$(make_profile_file_meta_badpath "${names[$i]}" "${paths[$i]}")
    expect_hl_fail "${dir}/${names[$i]}.log" "plan rejected bad path ${paths[$i]}" -- plan "${pp}" "${remote_args[@]}"
  done

  scenario_end
}

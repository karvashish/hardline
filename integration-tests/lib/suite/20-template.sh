#!/usr/bin/env bash
# =============================================================================
# 20-template.sh — template plugin: apply, idempotency, rollback, conflicts,
#                  managed-path enforcement.
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── template-apply-idempotent-rollback ───────────────────────────────────────
#    Apply a managed file (content + mode), prove a second apply is a true no-op
#    (fingerprint unchanged), check the local+remote journals, then roll back.
scenario_template_apply_idempotent_rollback() {
  local dir="${ARTIFACT_ROOT}/template-apply"
  reset_dir "${dir}"
  rm -rf "${STATE_DIR}"; mkdir -p "${STATE_DIR}"
  scenario_start "template-apply-idempotent-rollback: deploy file (content+0600), no-op re-apply, journals, rollback"
  guard_can_sign || return

  local dest="/etc/hardline.d/99-hardline-tmpl-apply.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local content=$'# hardline itest template\nHardeningLevel=strict\nKey=value\n'
  local pdir; pdir=$(make_profile_template "tmpl-apply" "${dest}" "${content}" "0600")

  must_hl "${dir}/apply.log" "apply" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { scenario_end; return; }

  # Content + mode verification (real fetch + cmp).
  ssh_cmd "sudo cat ${dest}" > "${dir}/remote.conf" 2>/dev/null || note_fail "could not read ${dest}"
  cmp -s "${pdir}/templates/config.tmpl" "${dir}/remote.conf" || note_fail "deployed content does not match template"
  must_remote "deployed file mode is 0600" <<EOF
test "\$(stat -c %a ${dest})" = "600"
EOF

  # Journals (this apply recorded before=absent).
  local ljournal="${STATE_DIR}/${host}/tmpl-apply.json"
  if [ -f "${ljournal}" ]; then
    assert_journal "local journal" "$(cat "${ljournal}")" "tmpl-apply" "success"
  else
    note_fail "missing local rollback journal: ${ljournal}"
  fi
  local rjpath; rjpath="$(remote_journal_latest tmpl-apply)"
  assert_journal "remote journal" "$(ssh_cmd "sudo cat ${rjpath}")" "tmpl-apply" "success"

  # Rollback removes the file. Do this BEFORE any second apply: a re-apply would
  # record a new journal with before=present, which rollback would then restore.
  must_hl "${dir}/rollback.log" "rollback" -- rollback "${pdir}" "${short_remote_args[@]}" -d
  must_remote "file removed after rollback" <<EOF
test ! -e ${dest}
EOF

  # Idempotency on a fresh apply: a no-op re-apply must not rewrite the file
  # (inode/mtime/mode/owner fingerprint unchanged).
  local fp1 fp2
  must_hl "${dir}/apply-idem1.log" "apply for idempotency" -- apply "${pdir}" "${remote_args[@]}"
  fp1="$(fp_path "${dest}")"
  must_hl "${dir}/apply-idem2.log" "second apply (no-op)" -- apply "${pdir}" "${remote_args[@]}"
  fp2="$(fp_path "${dest}")"
  [ -n "${fp1}" ] && [ "${fp1}" = "${fp2}" ] || note_fail "no-op re-apply changed the file (fp ${fp1} -> ${fp2})"
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true

  scenario_end
}

# ── template-conflict-force: post-apply drift blocks rollback unless forced ──
scenario_template_conflict_force() {
  local dir="${ARTIFACT_ROOT}/template-conflict"
  reset_dir "${dir}"
  scenario_start "template-conflict-force: content drift blocks rollback; --force-rollback removes it"
  guard_can_sign || return

  local dest="/etc/hardline.d/99-hardline-tmpl-conflict.conf"
  ssh_cmd "sudo rm -f ${dest}"
  local pdir; pdir=$(make_profile_template "tmpl-conflict" "${dest}" "TemplateConflict=yes")

  must_hl "${dir}/apply.log" "apply" -- apply "${pdir}" "${remote_args[@]}" --keep-local-rollback || { ssh_cmd "sudo rm -f ${dest}"; scenario_end; return; }
  ssh_cmd "echo drifted | sudo tee ${dest} >/dev/null"

  expect_hl_fail "${dir}/rollback-refuse.log" "rollback refused on drift" -- rollback "${pdir}" "${remote_args[@]}"
  must_hl "${dir}/rollback-force.log" "force-rollback" -- rollback "${pdir}" "${remote_args[@]}" --force-rollback
  must_remote "drifted file removed by force-rollback" <<EOF
test ! -e ${dest}
EOF

  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  scenario_end
}

# ── managed-path-enforcement: template targeting /tmp is refused, never written
scenario_managed_path_enforcement() {
  local dir="${ARTIFACT_ROOT}/managed-path"
  reset_dir "${dir}"
  scenario_start "managed-path-enforcement: template to /tmp rejected and never created"
  guard_can_sign || return

  local dest="/tmp/should-not-be-allowed.conf"
  ssh_cmd "sudo rm -f ${dest}" 2>/dev/null || true
  local pdir; pdir=$(make_profile_template "bad-path" "${dest}" "bad")

  expect_hl_fail "${dir}/apply.log" "apply to /tmp rejected" -- apply "${pdir}" "${remote_args[@]}"
  must_remote "no file written under /tmp" <<EOF
test ! -e ${dest}
EOF

  scenario_end
}

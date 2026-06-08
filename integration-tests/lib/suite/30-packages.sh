#!/usr/bin/env bash
# =============================================================================
# 30-packages.sh — packages plugin: install/update/purge lifecycle + rollback.
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# Uses "tree" as the test package (small, no services).

_pkg_installed() { ssh_cmd "dpkg -s '$1' >/dev/null 2>&1"; }

# ── package-lifecycle: install -> idempotent -> update:always -> purge -> absent
scenario_package_lifecycle() {
  local dir="${ARTIFACT_ROOT}/package-lifecycle"
  reset_dir "${dir}"
  scenario_start "package-lifecycle: install, no-op re-apply, update:always, purge, purge-absent"
  guard_can_sign || return

  ssh_cmd "sudo apt-get purge -y tree >/dev/null 2>&1" || true

  local p_install p_update p_purge
  p_install=$(make_profile_packages_install "pkg-install" "tree")
  p_update=$(make_profile_packages_update_always "pkg-update" "tree")
  p_purge=$(make_profile_packages_purge "pkg-purge" "tree")

  must_hl "${dir}/install.log" "install apply" -- apply "${p_install}" "${remote_args[@]}"
  must_remote "tree installed after apply" <<'EOF'
dpkg -s tree | grep -q '^Status: install ok installed'
EOF

  # Idempotent: re-apply succeeds and tree stays installed.
  must_hl "${dir}/install2.log" "install re-apply (idempotent)" -- apply "${p_install}" "${remote_args[@]}"
  _pkg_installed tree || note_fail "tree missing after idempotent re-apply"

  # update:always exercises the apt-get update path without breaking install.
  must_hl "${dir}/update.log" "update:always apply" -- apply "${p_update}" "${remote_args[@]}"
  _pkg_installed tree || note_fail "tree missing after update:always apply"

  # Purge removes it.
  must_hl "${dir}/purge.log" "purge apply" -- apply "${p_purge}" "${remote_args[@]}"
  must_remote "tree absent after purge" <<'EOF'
if dpkg -s tree >/dev/null 2>&1; then exit 1; fi
EOF

  # Purging an already-absent package is a clean no-op.
  must_hl "${dir}/purge-absent.log" "purge-absent apply (idempotent)" -- apply "${p_purge}" "${remote_args[@]}"

  scenario_end
}

# ── package-rollback: static profile install+journal, rollback purges;
#    rollback reinstalls a purged package; drift conflict needs --force-rollback.
scenario_package_rollback() {
  local dir="${ARTIFACT_ROOT}/package-rollback"
  reset_dir "${dir}"
  scenario_start "package-rollback: install+rollback-purges (static), reinstall-on-rollback, conflict/force"
  guard_can_sign || return

  # Part A — static package-rollback profile: install tree + managed file, verify
  # journals, then rollback purges the package and removes the file.
  run_package_rollback_apply "${dir}/static-apply"
  must_hl "${dir}/static-rollback.log" "rollback static package profile" -- \
    rollback "${PACKAGE_ROLLBACK_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "static rollback purged package + removed file" <<EOF
if dpkg -s ${PACKAGE_ROLLBACK_PACKAGE} >/dev/null 2>&1; then exit 1; fi
test ! -e ${PACKAGE_ROLLBACK_TEMPLATE_DEST}
EOF

  # Part B — rollback reinstalls a package the apply purged.
  ssh_cmd "sudo apt-get install -y tree >/dev/null 2>&1" || true
  _pkg_installed tree || note_fail "setup: tree not installed before purge-rollback"
  local p_purge; p_purge=$(make_profile_packages_purge "pkg-rb-reinstall" "tree")
  must_hl "${dir}/purge.log" "purge apply (keep-local)" -- apply "${p_purge}" "${remote_args[@]}" --keep-local-rollback
  must_remote "tree purged by apply" <<'EOF'
if dpkg -s tree >/dev/null 2>&1; then exit 1; fi
EOF
  must_hl "${dir}/reinstall-rollback.log" "rollback reinstalls" -- rollback "${p_purge}" "${remote_args[@]}"
  must_remote "tree reinstalled after rollback" <<'EOF'
dpkg -s tree | grep -q '^Status: install ok installed'
EOF

  # Part C — post-apply drift blocks rollback unless forced.
  ssh_cmd "sudo apt-get purge -y tree >/dev/null 2>&1" || true
  local p_install; p_install=$(make_profile_packages_install "pkg-conflict" "tree")
  must_hl "${dir}/conflict-install.log" "install for conflict (keep-local)" -- apply "${p_install}" "${remote_args[@]}" --keep-local-rollback
  _pkg_installed tree || note_fail "setup: tree not installed before conflict drift"
  ssh_cmd "sudo apt-get purge -y tree >/dev/null 2>&1" || true   # drift away from journal
  expect_hl_fail "${dir}/conflict-refuse.log" "rollback refused on package drift" -- rollback "${p_install}" "${remote_args[@]}"
  must_hl "${dir}/conflict-force.log" "force-rollback after drift" -- rollback "${p_install}" "${remote_args[@]}" --force-rollback

  ssh_cmd "sudo apt-get purge -y tree >/dev/null 2>&1" || true
  scenario_end
}

#!/usr/bin/env bash
# =============================================================================
# 30-packages.sh — packages plugin: install/update/purge lifecycle + rollback.
# =============================================================================
# Sourced by itest.sh. Do not run directly.
# Uses "tree" as the test package (small, no services).

# ── package-lifecycle: install -> idempotent -> update:always -> purge -> absent
scenario_package_lifecycle() {
  local dir="${ARTIFACT_ROOT}/package-lifecycle"
  reset_dir "${dir}"
  scenario_start "package-lifecycle: install, no-op re-apply, update:always, purge, purge-absent"
  guard_can_sign || return

  pkg_purge tree || true

  local p_install p_update p_purge
  p_install=$(make_profile_packages_install "pkg-install" "tree")
  p_update=$(make_profile_packages_update_always "pkg-update" "tree")
  p_purge=$(make_profile_packages_purge "pkg-purge" "tree")

  must_hl "${dir}/install.log" "install apply" -- apply "${p_install}" "${remote_args[@]}"
  must_remote "tree installed after apply" <<EOF
$(pkg_installed_test tree)
EOF

  # Idempotent: re-apply succeeds and tree stays installed.
  must_hl "${dir}/install2.log" "install re-apply (idempotent)" -- apply "${p_install}" "${remote_args[@]}"
  pkg_installed tree || note_fail "tree missing after idempotent re-apply"

  # update:always exercises the package index refresh without breaking install.
  must_hl "${dir}/update.log" "update:always apply" -- apply "${p_update}" "${remote_args[@]}"
  pkg_installed tree || note_fail "tree missing after update:always apply"

  # Purge removes it.
  must_hl "${dir}/purge.log" "purge apply" -- apply "${p_purge}" "${remote_args[@]}"
  must_remote "tree absent after purge" <<EOF
$(pkg_absent_test tree)
EOF

  # Purging an already-absent package is a clean no-op.
  must_hl "${dir}/purge-absent.log" "purge-absent apply (idempotent)" -- apply "${p_purge}" "${remote_args[@]}"

  scenario_end
}

# ── package-collateral: an undeclared collateral removal is refused with the
#    host untouched; declaring it lets the purge run and rollback restore both.
scenario_package_collateral() {
  local dir="${ARTIFACT_ROOT}/package-collateral"
  reset_dir "${dir}"
  scenario_start "package-collateral: undeclared purge collateral refused, declared collateral journalled"
  guard_can_sign || return

  # Installing ${COLLATERAL_PARENT} pulls ${COLLATERAL_CHILD}, so purging the
  # child drags the parent out. How much else comes with it is a property of the
  # image (dnf also collects dependencies the removal leaves unused), so the set
  # is read from the package manager rather than hard-coded.
  pkg_install "${COLLATERAL_PARENT}" || true
  must_remote "collateral pair installed for setup" <<EOF
$(pkg_installed_test "${COLLATERAL_PARENT}")
$(pkg_installed_test "${COLLATERAL_CHILD}")
EOF

  local collateral; collateral="$(pkg_collateral_of "${COLLATERAL_CHILD}")"
  collateral="$(echo "${collateral}" | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  case " ${collateral} " in
    *" ${COLLATERAL_PARENT} "*) ;;
    *)
      note_fail "fixture assumption broken: purging ${COLLATERAL_CHILD} removes '${collateral}', expected it to include ${COLLATERAL_PARENT}"
      pkg_purge "${COLLATERAL_PARENT}" || true
      scenario_end
      return
      ;;
  esac
  echo "  collateral of ${COLLATERAL_CHILD}: ${collateral}"

  local present_test="" absent_test=""
  for c in ${COLLATERAL_CHILD} ${collateral}; do
    present_test="${present_test}$(pkg_installed_test "${c}")"$'\n'
    absent_test="${absent_test}$(pkg_absent_test "${c}")"$'\n'
  done

  # Undeclared: apply must refuse, and nothing may be removed.
  local p_bare; p_bare=$(make_profile_packages_purge "pkg-collateral-bare" "${COLLATERAL_CHILD}")
  expect_hl_fail "${dir}/undeclared.log" "purge refused with undeclared collateral" -- \
    apply "${p_bare}" "${remote_args[@]}"
  must_remote "nothing removed by the refused purge" <<EOF
${present_test}
EOF

  # Declared: apply proceeds and the whole transaction goes.
  local p_declared
  p_declared=$(make_profile_packages_purge_collateral \
    "pkg-collateral-declared" "${COLLATERAL_CHILD}" "${collateral}")
  must_hl "${dir}/declared.log" "purge with declared collateral (keep-local)" -- \
    apply "${p_declared}" "${remote_args[@]}" --keep-local-rollback
  must_remote "purge and declared collateral absent" <<EOF
${absent_test}
EOF

  # The collateral is journalled like an explicit purge, so rollback restores it.
  must_hl "${dir}/rollback.log" "rollback restores purge and collateral" -- \
    rollback "${p_declared}" "${remote_args[@]}"
  must_remote "purge and declared collateral reinstalled after rollback" <<EOF
${present_test}
EOF

  pkg_purge "${COLLATERAL_PARENT}" || true
  scenario_end
}

# ── package-rollback: static profile install+journal, rollback purges;
#    rollback reinstalls a purged package; drift conflict needs --force-rollback.
scenario_package_rollback() {
  local dir="${ARTIFACT_ROOT}/package-rollback"
  reset_dir "${dir}"
  scenario_start "package-rollback: install+rollback-purges, reinstall-on-rollback, conflict/force"
  guard_can_sign || return

  # Part A — package + managed file in one profile: verify journals, then roll
  # back and confirm it purges the package and removes the file.
  run_package_rollback_apply "${dir}/combined-apply"
  must_hl "${dir}/combined-rollback.log" "rollback package+template profile" -- \
    rollback "${PACKAGE_ROLLBACK_PROFILE}" "${short_remote_args[@]}" -d
  must_remote "rollback purged package + removed file" <<EOF
$(pkg_absent_test "${PACKAGE_ROLLBACK_PACKAGE}")
test ! -e ${PACKAGE_ROLLBACK_TEMPLATE_DEST}
EOF

  # Part B — rollback reinstalls a package the apply purged.
  pkg_install tree || true
  pkg_installed tree || note_fail "setup: tree not installed before purge-rollback"
  local p_purge; p_purge=$(make_profile_packages_purge "pkg-rb-reinstall" "tree")
  must_hl "${dir}/purge.log" "purge apply (keep-local)" -- apply "${p_purge}" "${remote_args[@]}" --keep-local-rollback
  must_remote "tree purged by apply" <<EOF
$(pkg_absent_test tree)
EOF
  must_hl "${dir}/reinstall-rollback.log" "rollback reinstalls" -- rollback "${p_purge}" "${remote_args[@]}"
  must_remote "tree reinstalled after rollback" <<EOF
$(pkg_installed_test tree)
EOF

  # Part C — post-apply drift blocks rollback unless forced.
  pkg_purge tree || true
  local p_install; p_install=$(make_profile_packages_install "pkg-conflict" "tree")
  must_hl "${dir}/conflict-install.log" "install for conflict (keep-local)" -- apply "${p_install}" "${remote_args[@]}" --keep-local-rollback
  pkg_installed tree || note_fail "setup: tree not installed before conflict drift"
  pkg_purge tree || true   # drift away from journal
  expect_hl_fail "${dir}/conflict-refuse.log" "rollback refused on package drift" -- rollback "${p_install}" "${remote_args[@]}"
  must_hl "${dir}/conflict-force.log" "force-rollback after drift" -- rollback "${p_install}" "${remote_args[@]}" --force-rollback

  pkg_purge tree || true
  scenario_end
}

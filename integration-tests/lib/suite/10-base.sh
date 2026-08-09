#!/usr/bin/env bash
# =============================================================================
# 10-base.sh — apply the real starter profile and verify the hardened state
# =============================================================================
# Sourced by itest.sh. Do not run directly.

# ── base-profile: apply this target's starter profile, then verify every ────
#    dropped file (mode + content), all sysctls, services, and nftables. This
#    is the real "did the product do its job" check and the bootstrap that the
#    firewall/multi-plugin scenarios build on. ensure_base_bootstrap (runners.sh)
#    does the heavy lifting; it aborts via fail() on any mismatch, so run it in
#    a subshell to convert a hard failure into a scenario verdict.
scenario_base_profile() {
  scenario_start "base-profile: apply starter profile + exhaustive hardened-state verification"
  guard_base_profile || return

  if ( ensure_base_bootstrap ); then
    scenario_pass
  else
    note_fail "base profile apply/verification failed (see output above)"
    scenario_end
  fi
}

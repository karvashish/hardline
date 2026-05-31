#!/usr/bin/env bash
# =============================================================================
# wait-host-ready.sh — block until a freshly-provisioned itest host is usable
# =============================================================================
# Usage: wait-host-ready.sh <TERRAFORM_OUTPUTS_JSON>
#
# `terraform apply` returns as soon as the VM resource exists, but the GCP
# startup script is still installing packages (openssh-server, sudo, nftables)
# and cloud-init / unattended-upgrades may hold the apt/dpkg lock for another
# minute or more. Running scenarios into that window fails with errors like
# "apt/dpkg lock is held by another process". This script polls over SSH until
# the host is settled, so `itest-gcp-up` only returns on a ready host.
#
# Readiness predicate (tuned to integration-tests/terraform, whose startup
# script installs nftables): the nftables userspace tool is present (boot
# install finished) AND no apt/dpkg lock is held. The predicate must hold for
# several consecutive checks to ride out gaps between background apt steps.
#
# Env knobs:
#   ITEST_READY_TIMEOUT  total seconds to wait        (default 720)
#   ITEST_READY_STABLE   consecutive clean checks     (default 3)
#   ITEST_READY_INTERVAL seconds between checks        (default 10)
set -uo pipefail

OUTPUTS_JSON="${1:?usage: wait-host-ready.sh <terraform-outputs-json>}"
MAX_WAIT="${ITEST_READY_TIMEOUT:-720}"
STABLE_CHECKS="${ITEST_READY_STABLE:-3}"
INTERVAL="${ITEST_READY_INTERVAL:-10}"

command -v jq >/dev/null 2>&1 || { echo "wait-host-ready: jq not found" >&2; exit 1; }
test -f "${OUTPUTS_JSON}" || { echo "wait-host-ready: missing outputs json: ${OUTPUTS_JSON}" >&2; exit 1; }

host="$(jq -er '.external_ip.value' "${OUTPUTS_JSON}")"           || { echo "wait-host-ready: no external_ip in ${OUTPUTS_JSON}" >&2; exit 1; }
user="$(jq -er '.ssh_user.value' "${OUTPUTS_JSON}")"             || { echo "wait-host-ready: no ssh_user in ${OUTPUTS_JSON}" >&2; exit 1; }
key="$(jq -er '.ssh_private_key_path_hint.value' "${OUTPUTS_JSON}")" || { echo "wait-host-ready: no ssh key hint in ${OUTPUTS_JSON}" >&2; exit 1; }

ssh_opts=( -i "${key}" -o BatchMode=yes -o StrictHostKeyChecking=no
           -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o LogLevel=ERROR )

# nft present (startup install done) AND no apt/dpkg lock held.
remote_check='command -v nft >/dev/null 2>&1 && ! sudo fuser \
  /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
  /var/cache/apt/archives/lock /var/lib/apt/lists/lock >/dev/null 2>&1'

echo "wait-host-ready: polling ${user}@${host} (timeout ${MAX_WAIT}s, need ${STABLE_CHECKS} stable checks ${INTERVAL}s apart)"
ok=0
elapsed=0
while [ "${elapsed}" -lt "${MAX_WAIT}" ]; do
  if ssh "${ssh_opts[@]}" "${user}@${host}" "${remote_check}" 2>/dev/null; then
    ok=$((ok + 1))
    echo "  ready check ${ok}/${STABLE_CHECKS} at ${elapsed}s"
    if [ "${ok}" -ge "${STABLE_CHECKS}" ]; then
      echo "wait-host-ready: ${user}@${host} ready after ~${elapsed}s"
      exit 0
    fi
  else
    if [ "${ok}" -ne 0 ]; then echo "  host busy again at ${elapsed}s; resetting"; fi
    ok=0
  fi
  sleep "${INTERVAL}"
  elapsed=$((elapsed + INTERVAL))
done

echo "wait-host-ready: ${user}@${host} did not become ready within ${MAX_WAIT}s" >&2
exit 1

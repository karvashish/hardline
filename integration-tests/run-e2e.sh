#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUTS_JSON="${ITEST_OUTPUTS_JSON:-${ROOT_DIR}/tmp/itest-gcp.outputs.json}"
TFVARS_PATH="${ITEST_TFVARS:-${ROOT_DIR}/integration-tests/terraform/terraform.tfvars}"
PROFILE_DIR="${ITEST_PROFILE:-base-secure-ubuntu-24.04-lts}"
BINARY_PATH="${ITEST_BINARY_PATH:-${ROOT_DIR}/tmp/hardline}"
SSH_KEY_PATH="${ITEST_SSH_KEYPATH:-}"
SSH_WAIT_ATTEMPTS="${ITEST_SSH_WAIT_ATTEMPTS:-40}"
SSH_WAIT_SECONDS="${ITEST_SSH_WAIT_SECONDS:-5}"
KNOWN_HOSTS_FILE=""

cleanup_known_hosts() {
  if [[ -n "${KNOWN_HOSTS_FILE:-}" ]]; then
    rm -f "${KNOWN_HOSTS_FILE}"
  fi
}

require_cmd() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || {
    echo "missing command: ${cmd}" >&2
    exit 1
  }
}

read_tfvar() {
  local key="$1"
  awk -F= -v key="${key}" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      val=$2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      gsub(/"/, "", val)
      print val
      exit
    }
  ' "${TFVARS_PATH}"
}

expand_tilde_path() {
  local p="$1"
  if [[ "${p}" == "~/"* ]]; then
    echo "${HOME}/${p:2}"
    return
  fi
  echo "${p}"
}

wait_for_ssh() {
  local host="$1"
  local user="$2"
  local key_path="$3"
  local known_hosts="$4"
  local i

  for ((i=1; i<=SSH_WAIT_ATTEMPTS; i++)); do
    ssh-keyscan -T 5 "${host}" >"${known_hosts}" 2>/dev/null || true
    if ssh -i "${key_path}" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile="${known_hosts}" \
      "${user}@${host}" \
      "echo ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${SSH_WAIT_SECONDS}"
  done

  echo "ssh readiness check failed for ${user}@${host}" >&2
  return 1
}

main() {
  require_cmd jq
  require_cmd ssh
  require_cmd ssh-keyscan
  require_cmd make

  [[ -f "${OUTPUTS_JSON}" ]] || {
    echo "missing terraform outputs json: ${OUTPUTS_JSON}" >&2
    exit 1
  }
  [[ -f "${TFVARS_PATH}" ]] || {
    echo "missing tfvars file: ${TFVARS_PATH}" >&2
    exit 1
  }

  local host user
  host="$(jq -r '.external_ip.value // empty' "${OUTPUTS_JSON}")"
  user="$(jq -r '.ssh_user.value // empty' "${OUTPUTS_JSON}")"
  [[ -n "${host}" ]] || {
    echo "external_ip missing in terraform outputs" >&2
    exit 1
  }
  [[ -n "${user}" ]] || {
    echo "ssh_user missing in terraform outputs" >&2
    exit 1
  }

  if [[ -z "${SSH_KEY_PATH}" ]]; then
    SSH_KEY_PATH="$(read_tfvar ssh_private_key_path_hint)"
  fi
  SSH_KEY_PATH="$(expand_tilde_path "${SSH_KEY_PATH}")"
  [[ -f "${SSH_KEY_PATH}" ]] || {
    echo "ssh private key not found: ${SSH_KEY_PATH}" >&2
    exit 1
  }

  mkdir -p "${ROOT_DIR}/tmp"
  KNOWN_HOSTS_FILE="$(mktemp "${ROOT_DIR}/tmp/itest-known-hosts.XXXXXX")"
  chmod 600 "${KNOWN_HOSTS_FILE}"
  trap cleanup_known_hosts EXIT

  echo "== building hardline binary =="
  make -C "${ROOT_DIR}" build
  [[ -x "${BINARY_PATH}" ]] || {
    echo "hardline binary missing: ${BINARY_PATH}" >&2
    exit 1
  }

  echo "== waiting for ssh (${user}@${host}) =="
  wait_for_ssh "${host}" "${user}" "${SSH_KEY_PATH}" "${KNOWN_HOSTS_FILE}"

  export HARDLINE_KNOWN_HOSTS="${KNOWN_HOSTS_FILE}"
  export HARDLINE_STATE_DIR="${ROOT_DIR}/tmp/itest-state"
  mkdir -p "${HARDLINE_STATE_DIR}"

  local remote_args
  remote_args=(--host "${host}" --user "${user}" --keypath "${SSH_KEY_PATH}")

  echo "== e2e: version =="
  "${BINARY_PATH}" version

  echo "== e2e: verify-profile =="
  "${BINARY_PATH}" verify-profile "${PROFILE_DIR}"

  echo "== e2e: plan =="
  "${BINARY_PATH}" plan "${PROFILE_DIR}" "${remote_args[@]}"

  echo "== e2e: apply =="
  "${BINARY_PATH}" apply "${PROFILE_DIR}" "${remote_args[@]}"

  echo "== e2e: rollback =="
  "${BINARY_PATH}" rollback last "${remote_args[@]}"

  echo "== e2e complete =="
}

main "$@"

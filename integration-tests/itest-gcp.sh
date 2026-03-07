#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  make -C "${ROOT_DIR}" itest-gcp-down || true
}

trap cleanup EXIT INT TERM

make -C "${ROOT_DIR}" itest-gcp-up

if [ "$#" -eq 0 ]; then
  echo "GCP integration VM created. Pass a command to run before teardown, for example:"
  echo "  integration-tests/itest-gcp.sh 'go test ./internals/...' "
  exit 0
fi

bash -lc "$*"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

make -C "${ROOT_DIR}" itest-gcp-up

if [ "$#" -eq 0 ]; then
  echo "GCP integration VM created and left running."
  echo "Pass a command to run against it, for example:"
  echo "  integration-tests/itest-gcp.sh 'go test ./internals/...' "
  echo "Destroy it manually when finished:"
  echo "  make -C \"${ROOT_DIR}\" itest-gcp-down"
  exit 0
fi

bash -lc "$*"

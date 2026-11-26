#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./scripts/recover.sh" >&2
  exit 1
fi
exec anonctl recover

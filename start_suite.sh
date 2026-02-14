#!/bin/bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/arksher/ml-redteam}"

# Prefer the maintained launcher that sets integrated suite defaults.
if [[ -x "${ROOT_DIR}/launch_suite.sh" ]]; then
  cd "${ROOT_DIR}"
  exec "${ROOT_DIR}/launch_suite.sh"
fi

# Fallback to legacy orchestrator if launcher is unavailable.
cd "${ROOT_DIR}"
exec python3 suite_orchestrator.py

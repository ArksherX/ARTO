#!/usr/bin/env bash
# One-command VerityFlux quickstart. Builds VerityFlux, runs the crescendo
# attack against the sample agent, and exits with the demo's result.
set -euo pipefail
cd "$(dirname "$0")"
exec docker compose up --build --abort-on-container-exit --exit-code-from demo

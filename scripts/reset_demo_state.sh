#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_DIR="run/demo_state_archives/$STAMP"

printf 'Resetting local demo state. Archive: %s\n' "$ARCHIVE_DIR"

if [ -x ./stop_suite.sh ]; then
  ./stop_suite.sh >/dev/null 2>&1 || true
fi

mkdir -p "$ARCHIVE_DIR"

archive_path() {
  local path="$1"
  if [ -e "$path" ]; then
    mkdir -p "$ARCHIVE_DIR/$(dirname "$path")"
    mv "$path" "$ARCHIVE_DIR/$path"
    printf 'Archived %s\n' "$path"
  fi
}

# Runtime evidence and mutable local state. Source files are intentionally untouched.
archive_path "shared_state"
archive_path "vestigia/data"
archive_path "vestigia/logs"
archive_path "vestigia/web_ui/data"
archive_path "vestigia/vestigia/data"
archive_path "tessera/logs"
archive_path "tessera/data/revoked_tokens.json"
archive_path "tessera/data/tenant_test_registry_fallback.json"
archive_path "tessera/data/tessera_registry.json"
archive_path "tessera/data/witness.hash"
archive_path "verityflux-v2/data/approvals.json"
archive_path "verityflux-v2/data/scan_results.json"
archive_path "verityflux-v2/data/skill_assessments.json"
archive_path "verityflux-v2/data/soc_agents.json"

mkdir -p shared_state vestigia/data vestigia/logs tessera/data tessera/logs verityflux-v2/data

# Preserve static/dev keys if they exist in the archive so services can relaunch without re-bootstrap surprises.
for f in tessera/data/tessera_root_key.json verityflux-v2/data/api_keys.json verityflux-v2/data/attestation_key.json; do
  archived="$ARCHIVE_DIR/$f"
  if [ -f "$archived" ] && [ ! -f "$f" ]; then
    mkdir -p "$(dirname "$f")"
    cp "$archived" "$f"
  fi
done

printf 'Demo state reset complete. Relaunch with ./launch_suite.sh\n'

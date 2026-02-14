#!/usr/bin/env bash
set -euo pipefail

BACKUP_ARCHIVE="${1:-}"
RESTORE_DIR="${2:-/tmp/vestigia_restore}"

if [[ -z "$BACKUP_ARCHIVE" ]]; then
  echo "Usage: restore_from_backup.sh <backup.tar.gz> [restore_dir]"
  exit 1
fi

mkdir -p "$RESTORE_DIR"
tar -xzf "$BACKUP_ARCHIVE" -C "$RESTORE_DIR"

echo "Restored to: $RESTORE_DIR"
echo "Ledger: $RESTORE_DIR/vestigia_ledger.json"
echo "Postgres dump: $RESTORE_DIR/postgres_dump.sql"
echo "Next: psql < postgres_dump.sql (if restoring DB)"

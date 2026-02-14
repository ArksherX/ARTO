#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Vestigia Backup Script
# Backs up PostgreSQL database and JSON ledger files
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/backups"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_PATH="$BACKUP_DIR/vestigia_backup_${TIMESTAMP}"

# Check for docker compose
if docker compose version &>/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    DC=""
fi

echo "============================================================"
echo "  Vestigia Backup — $TIMESTAMP"
echo "============================================================"

mkdir -p "$BACKUP_PATH"

# ------------------------------------------------------------------
# 1. PostgreSQL dump
# ------------------------------------------------------------------
echo "[1/4] Backing up PostgreSQL..."
if [ -n "$DC" ] && $DC ps vestigia-db 2>/dev/null | grep -q "running"; then
    $DC exec -T vestigia-db pg_dump -U vestigia vestigia > "$BACKUP_PATH/vestigia_db.sql" 2>/dev/null
    echo "  Database dump: $(du -h "$BACKUP_PATH/vestigia_db.sql" | cut -f1)"
else
    echo "  Skipped (PostgreSQL container not running)"
fi

# ------------------------------------------------------------------
# 2. JSON ledger files
# ------------------------------------------------------------------
echo "[2/4] Backing up ledger files..."
if [ -d "$SCRIPT_DIR/data" ]; then
    cp -r "$SCRIPT_DIR/data" "$BACKUP_PATH/data"
    echo "  Ledger data: $(du -sh "$BACKUP_PATH/data" | cut -f1)"
else
    echo "  Skipped (no data directory)"
fi

# ------------------------------------------------------------------
# 3. Compress
# ------------------------------------------------------------------
echo "[3/4] Compressing..."
tar -czf "${BACKUP_PATH}.tar.gz" -C "$BACKUP_DIR" "vestigia_backup_${TIMESTAMP}"
rm -rf "$BACKUP_PATH"
SIZE="$(du -h "${BACKUP_PATH}.tar.gz" | cut -f1)"
echo "  Archive: ${BACKUP_PATH}.tar.gz ($SIZE)"

# ------------------------------------------------------------------
# 4. Rotation
# ------------------------------------------------------------------
echo "[4/4] Rotating old backups..."

# Keep last 30 daily backups
DAILY_COUNT=$(ls -1 "$BACKUP_DIR"/vestigia_backup_*.tar.gz 2>/dev/null | wc -l)
if [ "$DAILY_COUNT" -gt 30 ]; then
    REMOVE=$((DAILY_COUNT - 30))
    ls -1t "$BACKUP_DIR"/vestigia_backup_*.tar.gz | tail -n "$REMOVE" | xargs rm -f
    echo "  Removed $REMOVE old backup(s)"
else
    echo "  $DAILY_COUNT backup(s) retained (max 30)"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Backup complete: ${BACKUP_PATH}.tar.gz"
echo "  Size: $SIZE"
echo "  Retained backups: $(ls -1 "$BACKUP_DIR"/vestigia_backup_*.tar.gz 2>/dev/null | wc -l)"
echo "============================================================"

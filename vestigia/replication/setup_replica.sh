#!/usr/bin/env bash
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PRIMARY_HOST="${PRIMARY_HOST:-primary-db}"
REPL_USER="${REPL_USER:-replicator}"
REPL_PASSWORD="${REPL_PASSWORD:-replica_password}"
REPL_SLOT="${REPL_SLOT:-vestigia_slot}"

echo "Setting up replica from primary ${PRIMARY_HOST}..."

rm -rf "$PGDATA"/*
export PGPASSWORD="$REPL_PASSWORD"

pg_basebackup -h "$PRIMARY_HOST" -D "$PGDATA" -U "$REPL_USER" -Fp -Xs -P -R -C -S "$REPL_SLOT"

cat >> "$PGDATA/postgresql.conf" <<EOF
hot_standby = on
primary_conninfo = 'host=$PRIMARY_HOST user=$REPL_USER password=$REPL_PASSWORD'
EOF

touch "$PGDATA/standby.signal"

pg_ctl -D "$PGDATA" start
echo "Replica started."

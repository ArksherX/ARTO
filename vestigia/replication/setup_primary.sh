#!/usr/bin/env bash
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PRIMARY_HOST="${PRIMARY_HOST:-localhost}"
REPL_USER="${REPL_USER:-replicator}"
REPL_PASSWORD="${REPL_PASSWORD:-replica_password}"

echo "Configuring primary for streaming replication..."

cat >> "$PGDATA/postgresql.conf" <<EOF
wal_level = replica
max_wal_senders = 10
wal_keep_size = 256MB
hot_standby = on
EOF

echo "host replication $REPL_USER 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"

psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$REPL_USER') THEN
      CREATE ROLE $REPL_USER WITH REPLICATION LOGIN PASSWORD '$REPL_PASSWORD';
   END IF;
END
\$\$;
SQL

pg_ctl -D "$PGDATA" restart
echo "Primary configured."

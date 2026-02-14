#!/usr/bin/env bash
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"

echo "Promoting standby to primary..."
pg_ctl -D "$PGDATA" promote
echo "Standby promoted."

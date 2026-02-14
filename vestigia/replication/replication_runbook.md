# Vestigia Multi-Region Replication Runbook

## Objective
Maintain a primary PostgreSQL instance with one or more read-only replicas and an automated/manual failover procedure.

## Prerequisites
- PostgreSQL 14+
- Network connectivity between primary and replica
- Replication user credentials

## Primary Setup
1. Set environment variables:
```
export PRIMARY_HOST=localhost
export REPL_USER=replicator
export REPL_PASSWORD=replica_password
```
2. Run:
```
./replication/setup_primary.sh
```

## Replica Setup
1. Set environment variables:
```
export PRIMARY_HOST=<primary-host>
export REPL_USER=replicator
export REPL_PASSWORD=replica_password
export REPL_SLOT=vestigia_slot
```
2. Run:
```
./replication/setup_replica.sh
```

## Failover Procedure
1. Confirm primary is unavailable.
2. Promote replica:
```
./replication/failover.sh
```
3. Update application DB DSN to point to new primary.

## RPO / RTO Targets
- RPO: < 5 minutes
- RTO: < 1 hour

## Verification
```
psql -c "SELECT pg_is_in_recovery();"
```
Expect `false` on primary, `true` on replica.

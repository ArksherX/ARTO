#!/usr/bin/env python3
"""
Vestigia PostgreSQL-backed Ledger Engine

Production-grade immutable audit ledger that stores events in PostgreSQL
instead of flat JSON files.  Provides the same public interface as
VestigiaLedger (core.ledger_engine) so callers can swap backends with a
single configuration change.

Features:
  - Connection pooling via psycopg2.pool
  - Hash-chain integrity matching ledger_engine.py exactly
  - Transaction-safe append / query / verify operations
  - Automatic fallback to VestigiaLedger (JSON) when PostgreSQL is unavailable
"""

import csv
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, UTC
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.ledger_engine import (
    ActionType,
    EventStatus,
    StructuredEvidence,
    VestigiaEvent,
    VestigiaLedger,
)
from core.ledger_engine import MerkleWitness
from core.blockchain_anchor import BlockchainAnchor
from core.hsm_client import get_hsm_from_env

logger = logging.getLogger("vestigia.postgres_ledger")


class PostgresLedger:
    """
    PostgreSQL-backed immutable audit ledger.

    Drop-in replacement for ``VestigiaLedger`` that persists events to a
    ``vestigia_events`` table and relies on the database trigger for
    append-only enforcement.

    If PostgreSQL is unreachable at construction time the instance
    transparently falls back to the JSON-file ``VestigiaLedger``.
    """

    # ------------------------------------------------------------------
    # Construction / connection
    # ------------------------------------------------------------------

    def __init__(
        self,
        dsn: str,
        secret_salt: Optional[str] = None,
        pool_min: int = 1,
        pool_max: int = 10,
        fallback_ledger_path: str = "data/vestigia_ledger.json",
    ):
        """
        Parameters
        ----------
        dsn : str
            PostgreSQL connection string
            (e.g. ``"host=localhost dbname=vestigia user=vestigia"``).
        secret_salt : str, optional
            HMAC secret for integrity hashes.  Falls back to the
            ``VESTIGIA_SECRET_SALT`` environment variable.
        pool_min / pool_max : int
            psycopg2 ``SimpleConnectionPool`` bounds.
        fallback_ledger_path : str
            Path handed to ``VestigiaLedger`` when PostgreSQL is not
            available.
        """
        self.dsn = dsn
        self.secret_salt = secret_salt or os.getenv("VESTIGIA_SECRET_SALT")
        self._pool = None
        self._fallback: Optional[VestigiaLedger] = None
        self._witness = None
        self._blockchain_anchor = None
        self._anchor_every = int(os.getenv("VESTIGIA_BLOCKCHAIN_ANCHOR_EVERY", "300"))
        self._witness_every = int(os.getenv("VESTIGIA_MERKLE_WITNESS_EVERY", "100"))

        try:
            import psycopg2
            import psycopg2.pool
            import psycopg2.extras

            self._pool = psycopg2.pool.SimpleConnectionPool(
                pool_min, pool_max, dsn
            )
            # Quick connectivity check
            conn = self._pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            finally:
                self._pool.putconn(conn)
            logger.info("PostgreSQL connection pool established (%s)", dsn)
            hsm = get_hsm_from_env()
            self._witness = MerkleWitness(hsm_client=hsm)
            if os.getenv("VESTIGIA_BLOCKCHAIN_ANCHORING", "false").lower() == "true":
                provider = os.getenv("VESTIGIA_BLOCKCHAIN_PROVIDER", "file")
                self._blockchain_anchor = BlockchainAnchor(provider=provider)
        except Exception as exc:
            logger.warning(
                "PostgreSQL unavailable (%s) -- falling back to JSON ledger: %s",
                dsn,
                exc,
            )
            self._pool = None
            self._fallback = VestigiaLedger(
                ledger_path=fallback_ledger_path,
                secret_salt=self.secret_salt,
                enable_merkle_witness=True,
                enable_external_anchor=False,
            )

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    @property
    def is_postgres(self) -> bool:
        """Return ``True`` when backed by PostgreSQL, ``False`` for fallback."""
        return self._pool is not None

    def _get_conn(self):
        """Obtain a connection from the pool."""
        if self._pool is None:
            raise RuntimeError("No PostgreSQL pool available")
        return self._pool.getconn()

    def _put_conn(self, conn):
        """Return a connection to the pool."""
        if self._pool is not None:
            self._pool.putconn(conn)

    def close(self):
        """Tear down the connection pool."""
        if self._pool is not None:
            self._pool.closeall()
            self._pool = None

    # ------------------------------------------------------------------
    # Hash generation -- mirrors ledger_engine.py exactly
    # ------------------------------------------------------------------

    def _generate_integrity_hash(
        self,
        timestamp: str,
        tenant_id: Optional[str],
        actor_id: str,
        action_type: str,
        status: str,
        evidence: Any,
        previous_hash: str,
    ) -> str:
        """
        Produce a SHA-256 (or HMAC-SHA-256) digest identical to the one
        generated by ``VestigiaLedger._generate_integrity_hash``.

        The payload is the concatenation of each field as a string, with
        evidence serialised as canonical JSON (``sort_keys=True``,
        ``separators=(',', ':')``).
        """
        evidence_str = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        if tenant_id:
            payload = f"{timestamp}{tenant_id}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
        else:
            payload = f"{timestamp}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"

        if self.secret_salt:
            return hmac.new(
                self.secret_salt.encode(),
                payload.encode(),
                hashlib.sha256,
            ).hexdigest()
        return hashlib.sha256(payload.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def append_event(
        self,
        actor_id: str,
        action_type: Union[str, ActionType],
        status: Union[str, EventStatus],
        evidence: Union[str, StructuredEvidence, Dict],
        event_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> VestigiaEvent:
        """Append an immutable event to the ledger and return it."""

        # --- fallback path ---
        if self._fallback is not None:
            return self._fallback.append_event(
                actor_id=actor_id,
                action_type=action_type,
                status=status,
                evidence=evidence,
                event_id=event_id,
                tenant_id=tenant_id,
            )

        # --- normalise inputs ---
        if isinstance(action_type, ActionType):
            action_type = action_type.value
        if isinstance(status, EventStatus):
            status = status.value

        if isinstance(evidence, StructuredEvidence):
            evidence_data = evidence.to_dict()
        elif isinstance(evidence, dict):
            evidence_data = evidence
        else:
            evidence_data = StructuredEvidence.from_string(str(evidence)).to_dict()

        if event_id is None:
            event_id = str(uuid.uuid4())

        timestamp = datetime.now(UTC).isoformat()

        conn = self._get_conn()
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                # Fetch the most recent integrity_hash (row-level lock on the
                # latest entry to serialise concurrent appends).
                cur.execute(
                    """
                    SELECT integrity_hash
                    FROM   vestigia_events
                    ORDER  BY event_sequence DESC
                    LIMIT  1
                    FOR UPDATE
                    """
                )
                row = cur.fetchone()
                previous_hash = row[0] if row else "GENESIS"

                integrity_hash = self._generate_integrity_hash(
                    timestamp=timestamp,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    action_type=action_type,
                    status=status,
                    evidence=evidence_data,
                    previous_hash=previous_hash,
                )

                import psycopg2.extras  # noqa: F811 (re-import is safe)

                cur.execute(
                    """
                    INSERT INTO vestigia_events (
                        event_id, timestamp, tenant_id, actor_id, action_type,
                        status, evidence, integrity_hash, previous_hash,
                        trace_id, span_id
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s
                    )
                    """,
                    (
                        event_id,
                        timestamp,
                        tenant_id,
                        actor_id,
                        action_type,
                        status,
                        psycopg2.extras.Json(evidence_data),
                        integrity_hash,
                        previous_hash,
                        trace_id,
                        span_id,
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

        # Merkle witness anchoring (use event_sequence count)
        if self._witness or self._blockchain_anchor:
            try:
                conn = self._get_conn()
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vestigia_events")
                    entry_count = int(cur.fetchone()[0])
            finally:
                self._put_conn(conn)

            if self._witness:
                try:
                    if status == EventStatus.CRITICAL.value or (entry_count % self._witness_every == 0):
                        self._witness.anchor_hash(integrity_hash, entry_count)
                except Exception:
                    logger.exception("Failed to anchor Merkle witness")

            if self._blockchain_anchor:
                try:
                    if status == EventStatus.CRITICAL.value or (entry_count % self._anchor_every == 0):
                        # Fetch last N hashes for batch
                        conn = self._get_conn()
                        try:
                            with conn.cursor() as cur:
                                cur.execute(
                                    """
                                    SELECT integrity_hash
                                    FROM vestigia_events
                                    ORDER BY event_sequence DESC
                                    LIMIT %s
                                    """,
                                    (self._anchor_every,),
                                )
                                hashes = [r[0] for r in cur.fetchall()]
                        finally:
                            self._put_conn(conn)
                        if hashes:
                            self._blockchain_anchor.anchor(list(reversed(hashes)))
                except Exception:
                    logger.exception("Failed to anchor blockchain batch")

        return VestigiaEvent(
            timestamp=timestamp,
            tenant_id=tenant_id,
            actor_id=actor_id,
            action_type=action_type,
            status=status,
            evidence=evidence_data,
            integrity_hash=integrity_hash,
            event_id=event_id,
            previous_hash=previous_hash,
        )

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    def verify_integrity(self) -> tuple:
        """
        Walk the hash chain and verify every link.

        Returns
        -------
        (bool, Optional[int])
            ``(True, None)`` when the chain is intact, or
            ``(False, sequence_number)`` at the first break.
        """
        if self._fallback is not None:
            return self._fallback.verify_integrity()

        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_sequence,
                           timestamp,
                           tenant_id,
                           actor_id,
                           action_type,
                           status,
                           evidence,
                           integrity_hash,
                           previous_hash
                    FROM   vestigia_events
                    ORDER  BY event_sequence ASC
                    """
                )
                rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        if not rows:
            return True, None

        prev_hash = None
        for idx, row in enumerate(rows):
            (
                seq,
                ts,
                tenant,
                actor,
                action,
                st,
                ev,
                stored_hash,
                stored_prev,
            ) = row

            if idx == 0:
                # Genesis -- nothing to compare previous_hash against.
                prev_hash = stored_hash
                continue

            if stored_prev != prev_hash:
                return False, int(seq)

            expected = self._generate_integrity_hash(
                timestamp=ts if isinstance(ts, str) else ts.isoformat(),
                tenant_id=tenant,
                actor_id=actor,
                action_type=action,
                status=st,
                evidence=ev,
                previous_hash=prev_hash,
            )

            if stored_hash != expected:
                return False, int(seq)

            prev_hash = stored_hash

        return True, None

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query_events(
        self,
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        action_type: Optional[Union[str, ActionType]] = None,
        status: Optional[Union[str, EventStatus]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[VestigiaEvent]:
        """Query events with optional filters, newest first."""

        if self._fallback is not None:
            return self._fallback.query_events(
                actor_id=actor_id,
                action_type=action_type,
                status=status,
                start_date=start_date,
                end_date=end_date,
                limit=limit,
            )

        clauses: List[str] = []
        params: List[Any] = []

        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)

        if actor_id is not None:
            clauses.append("actor_id ILIKE %s")
            params.append(f"%{actor_id}%")

        if action_type is not None:
            if isinstance(action_type, ActionType):
                action_type = action_type.value
            clauses.append("action_type = %s")
            params.append(action_type)

        if status is not None:
            if isinstance(status, EventStatus):
                status = status.value
            clauses.append("status = %s")
            params.append(status)

        if severity is not None:
            clauses.append("severity = %s")
            params.append(severity)

        if start_date is not None:
            clauses.append("timestamp >= %s")
            params.append(start_date)

        if end_date is not None:
            clauses.append("timestamp <= %s")
            params.append(end_date)

        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)

        query = f"""
            SELECT timestamp, tenant_id, actor_id, action_type, status,
                   evidence, integrity_hash, event_id, previous_hash
            FROM   vestigia_events
            {where}
            ORDER  BY event_sequence DESC
            LIMIT  %s
        """
        params.append(limit)

        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        results: List[VestigiaEvent] = []
        for row in rows:
            ts, tenant, actor, action, st, ev, ihash, eid, phash = row
            results.append(
                VestigiaEvent(
                    timestamp=ts if isinstance(ts, str) else ts.isoformat(),
                    tenant_id=tenant,
                    actor_id=actor,
                    action_type=action,
                    status=st,
                    evidence=ev,
                    integrity_hash=ihash,
                    event_id=str(eid),
                    previous_hash=phash,
                )
            )
        return results

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self, tenant_id: Optional[str] = None) -> dict:
        """Return aggregate statistics about the ledger."""

        if self._fallback is not None:
            return self._fallback.get_statistics(tenant_id=tenant_id)

        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                if tenant_id:
                    cur.execute("SELECT count(*) FROM vestigia_events WHERE tenant_id = %s", (tenant_id,))
                else:
                    cur.execute("SELECT count(*) FROM vestigia_events")
                total = cur.fetchone()[0]

                if tenant_id:
                    cur.execute(
                        """
                        SELECT status, count(*)
                        FROM   vestigia_events
                        WHERE  tenant_id = %s
                        GROUP  BY status
                        """,
                        (tenant_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT status, count(*)
                        FROM   vestigia_events
                        GROUP  BY status
                        """
                    )
                status_breakdown = dict(cur.fetchall())

                if tenant_id:
                    cur.execute(
                        """
                        SELECT action_type, count(*)
                        FROM   vestigia_events
                        WHERE  tenant_id = %s
                        GROUP  BY action_type
                        """,
                        (tenant_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT action_type, count(*)
                        FROM   vestigia_events
                        GROUP  BY action_type
                        """
                    )
                action_breakdown = dict(cur.fetchall())

                if tenant_id:
                    cur.execute(
                        """
                        SELECT min(timestamp), max(timestamp)
                        FROM   vestigia_events
                        WHERE  tenant_id = %s
                        """,
                        (tenant_id,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT min(timestamp), max(timestamp)
                        FROM   vestigia_events
                        """
                    )
                first, last = cur.fetchone()
        finally:
            self._put_conn(conn)

        return {
            "total_events": total,
            "status_breakdown": status_breakdown,
            "action_breakdown": action_breakdown,
            "first_entry": first.isoformat() if first else None,
            "last_entry": last.isoformat() if last else None,
        }

    # ------------------------------------------------------------------
    # Witness anchoring
    # ------------------------------------------------------------------

    def anchor_witness(
        self, merkle_root: str, entry_count: int
    ) -> str:
        """
        Persist a Merkle-root snapshot in the ``witness_anchors`` table.

        Returns the generated ``anchor_id`` as a string.
        """
        if self._fallback is not None:
            # Fallback uses the MerkleWitness file-based approach.
            from core.ledger_engine import MerkleWitness

            witness = MerkleWitness()
            return witness.anchor_hash(merkle_root, entry_count)

        anchor_id = str(uuid.uuid4())
        anchor_hash = hashlib.sha256(
            f"{merkle_root}{entry_count}".encode()
        ).hexdigest()

        conn = self._get_conn()
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO witness_anchors (
                        anchor_id, merkle_root, entry_count,
                        anchor_hash, anchor_type
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (anchor_id, merkle_root, entry_count, anchor_hash, "merkle"),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

        logger.info(
            "Witness anchor created: id=%s root=%s entries=%d",
            anchor_id,
            merkle_root[:16],
            entry_count,
        )
        return anchor_id

    # ------------------------------------------------------------------
    # Compliance reporting
    # ------------------------------------------------------------------

    def export_compliance_report(
        self,
        output_path: str,
        format: str = "json",
    ) -> str:
        """
        Export the full ledger with statistics into a compliance report.

        Parameters
        ----------
        output_path : str
            Destination file path.
        format : str
            ``'json'`` or ``'csv'``.

        Returns
        -------
        str
            The resolved output path.
        """
        if self._fallback is not None:
            return self._fallback.export_compliance_report(
                output_path=output_path, format=format
            )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT timestamp, actor_id, action_type, status,
                           evidence, integrity_hash, event_id, previous_hash
                    FROM   vestigia_events
                    ORDER  BY event_sequence ASC
                    """
                )
                rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        columns = [
            "timestamp",
            "actor_id",
            "action_type",
            "status",
            "evidence",
            "integrity_hash",
            "event_id",
            "previous_hash",
        ]

        events = []
        for row in rows:
            entry: Dict[str, Any] = {}
            for i, col in enumerate(columns):
                val = row[i]
                if col == "timestamp" and not isinstance(val, str):
                    val = val.isoformat()
                if col == "event_id":
                    val = str(val)
                entry[col] = val
            events.append(entry)

        if format == "json":
            report = {
                "ledger": events,
                "statistics": self.get_statistics(),
                "export_timestamp": datetime.now(UTC).isoformat(),
            }
            with open(out, "w") as fh:
                json.dump(report, fh, indent=2, default=str)

        elif format == "csv":
            with open(out, "w", newline="") as fh:
                if not events:
                    fh.write("")
                else:
                    for ev in events:
                        if isinstance(ev.get("evidence"), dict):
                            ev["evidence"] = ev["evidence"].get(
                                "summary", json.dumps(ev["evidence"])
                            )
                    writer = csv.DictWriter(fh, fieldnames=columns)
                    writer.writeheader()
                    writer.writerows(events)

        return str(out)

#!/usr/bin/env python3
"""
Access audit logging for audit-of-audit requirements.
Logs access to ledger query endpoints with anomaly detection.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional


class AccessAuditLogger:
    def __init__(self, dsn: Optional[str] = None, fallback_path: str = "logs/access_audit.jsonl"):
        self.dsn = dsn or os.getenv("VESTIGIA_DB_DSN")
        self.fallback_path = Path(fallback_path)
        self.fallback_path.parent.mkdir(parents=True, exist_ok=True)

    def log_access(
        self,
        user_id: str,
        query_text: str,
        rows_accessed: int,
        ip_address: str,
        user_agent: str,
        alert_triggered: bool = False,
    ):
        if self.dsn:
            try:
                import psycopg2
                with psycopg2.connect(self.dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO access_log (timestamp, user_id, query_text, rows_accessed, ip_address, user_agent, alert_triggered)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                datetime.now(UTC),
                                user_id,
                                query_text,
                                rows_accessed,
                                ip_address,
                                user_agent,
                                alert_triggered,
                            ),
                        )
                        conn.commit()
                        return
            except Exception:
                pass

        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "user_id": user_id,
            "query_text": query_text,
            "rows_accessed": rows_accessed,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "alert_triggered": alert_triggered,
        }
        with open(self.fallback_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    @staticmethod
    def is_suspicious(rows_accessed: int, now_utc: Optional[datetime] = None) -> bool:
        now_utc = now_utc or datetime.now(UTC)
        off_hours = now_utc.hour < 6 or now_utc.hour > 22
        return rows_accessed > 1000 or off_hours

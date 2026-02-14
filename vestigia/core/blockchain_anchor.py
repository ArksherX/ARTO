#!/usr/bin/env python3
"""
Blockchain anchoring integration.
Default provider writes anchors to local file.
Optional OpenTimestamps support if installed.
"""

from __future__ import annotations

import json
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from core.merkle_tree import merkle_root


class BlockchainAnchor:
    def __init__(self, provider: str = "file", anchor_path: str = "data/blockchain_anchors.json"):
        self.provider = provider
        self.anchor_path = Path(anchor_path)
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.anchor_path.exists():
            self.anchor_path.write_text(json.dumps({"anchors": []}, indent=2))
        self.dsn = os.getenv("VESTIGIA_DB_DSN")

    def anchor(self, hashes: list[str]) -> Dict[str, Any]:
        root = merkle_root(hashes)
        if self.provider == "file":
            return self._anchor_file(root, len(hashes))
        if self.provider == "opentimestamps":
            return self._anchor_opentimestamps(root, len(hashes))
        raise ValueError(f"Unsupported anchor provider: {self.provider}")

    def _anchor_file(self, root: str, batch_size: int) -> Dict[str, Any]:
        anchor_id = hashlib.sha256(f"{root}{time.time()}".encode()).hexdigest()
        record = {
            "anchor_id": anchor_id,
            "timestamp": time.time(),
            "merkle_root": root,
            "batch_size": batch_size,
            "provider": "file",
            "external_ref": None
        }
        data = json.loads(self.anchor_path.read_text())
        data["anchors"].append(record)
        self.anchor_path.write_text(json.dumps(data, indent=2))
        self._persist_db(record)
        return record

    def _anchor_opentimestamps(self, root: str, batch_size: int) -> Dict[str, Any]:
        try:
            import opentimestamps
            from opentimestamps.core.timestamp import Timestamp
            from opentimestamps.ops import OpSHA256
            from opentimestamps import client as ots_client
        except Exception as exc:
            raise RuntimeError(f"OpenTimestamps library not available: {exc}")

        ts = Timestamp(root.encode())
        ts.ops.append(OpSHA256())
        ots_client.stamp(ts)
        record = {
            "anchor_id": hashlib.sha256(f"{root}{time.time()}".encode()).hexdigest(),
            "timestamp": time.time(),
            "merkle_root": root,
            "batch_size": batch_size,
            "provider": "opentimestamps",
            "external_ref": ts.to_json()
        }
        data = json.loads(self.anchor_path.read_text())
        data["anchors"].append(record)
        self.anchor_path.write_text(json.dumps(data, indent=2))
        self._persist_db(record)
        return record

    def list_anchors(self) -> Dict[str, Any]:
        return json.loads(self.anchor_path.read_text())

    def verify_anchor(self, anchor_id: str) -> Optional[Dict[str, Any]]:
        data = json.loads(self.anchor_path.read_text())
        for record in data.get("anchors", []):
            if record.get("anchor_id") == anchor_id:
                return record
        return None

    def _persist_db(self, record: Dict[str, Any]):
        if not self.dsn:
            return
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO blockchain_anchors (timestamp, merkle_root, batch_size, provider, external_ref)
                        VALUES (to_timestamp(%s), %s, %s, %s, %s)
                        """,
                        (
                            record["timestamp"],
                            record["merkle_root"],
                            record["batch_size"],
                            record["provider"],
                            json.dumps(record.get("external_ref")) if record.get("external_ref") else None,
                        ),
                    )
                    conn.commit()
        except Exception:
            pass

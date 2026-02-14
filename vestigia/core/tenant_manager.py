#!/usr/bin/env python3
"""
Phase 6: Multi-tenant SaaS core (tenants, users, API keys, RBAC).
Supports JSON fallback when Postgres is not configured.
"""

from __future__ import annotations

import json
import os
import secrets
import hashlib
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Any, Optional, List


ROLE_PERMISSIONS = {
    "admin": {"*"},
    "security": {"events:write", "events:read", "playbooks:execute", "risk:forecast", "anomalies:feedback"},
    "ops": {"events:read", "risk:forecast", "metrics:read"},
    "analyst": {"events:read", "nl:query", "risk:forecast"},
    "viewer": {"events:read"},
}

PLAN_LIMITS = {
    "free": {"events_per_day": 1000, "users": 5},
    "pro": {"events_per_day": 10000, "users": 50},
    "enterprise": {"events_per_day": 100000, "users": 500},
}


@dataclass
class TenantContext:
    tenant_id: str
    user_id: str
    role: str
    api_key_id: str

    def can(self, permission: str) -> bool:
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return "*" in perms or permission in perms


class TenantStore:
    def __init__(self, path: str = "data/tenants.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dsn = os.getenv("VESTIGIA_DB_DSN")
        if not self.path.exists():
            self.path.write_text(json.dumps({"tenants": {}, "users": {}, "keys": {}, "usage": {}}, indent=2))

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def _hash_key(self, raw: str) -> str:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _load(self) -> Dict[str, Any]:
        if self.dsn:
            return self._load_db()
        return json.loads(self.path.read_text())

    def _save(self, data: Dict[str, Any]):
        if self.dsn:
            self._save_db(data)
            return
        self.path.write_text(json.dumps(data, indent=2))

    def create_tenant(self, name: str, plan: str = "free") -> Dict[str, Any]:
        if plan not in PLAN_LIMITS:
            plan = "free"
        tenant_id = f"t_{secrets.token_hex(8)}"
        tenant = {
            "tenant_id": tenant_id,
            "name": name,
            "plan": plan,
            "status": "active",
            "created_at": self._now(),
        }
        data = self._load()
        data["tenants"][tenant_id] = tenant
        self._save(data)
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        data = self._load()
        return data.get("tenants", {}).get(tenant_id)

    def create_user(self, tenant_id: str, email: str, role: str = "admin") -> Dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            role = "viewer"
        user_id = f"u_{secrets.token_hex(8)}"
        user = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "email": email,
            "role": role,
            "status": "active",
            "created_at": self._now(),
        }
        data = self._load()
        data["users"][user_id] = user
        self._save(data)
        return user

    def create_api_key(self, tenant_id: str, user_id: str, label: str = "default") -> Dict[str, Any]:
        raw = f"vk_{secrets.token_urlsafe(32)}"
        key_id = f"k_{secrets.token_hex(8)}"
        record = {
            "key_id": key_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "label": label,
            "key_hash": self._hash_key(raw),
            "status": "active",
            "created_at": self._now(),
            "last_used": None,
        }
        data = self._load()
        data["keys"][key_id] = record
        self._save(data)
        return {"key_id": key_id, "api_key": raw, "label": label}

    def get_plan_limits(self, tenant_id: str) -> Dict[str, int]:
        tenant = self.get_tenant(tenant_id) or {}
        plan = tenant.get("plan", "free")
        return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])

    def record_usage(self, tenant_id: str, events: int = 1) -> int:
        day_key = datetime.now(UTC).strftime("%Y-%m-%d")
        if self.dsn:
            return self._record_usage_db(tenant_id, day_key, events)
        data = self._load()
        usage = data.setdefault("usage", {})
        tenant_usage = usage.setdefault(tenant_id, {})
        tenant_usage[day_key] = int(tenant_usage.get(day_key, 0)) + int(events)
        self._save(data)
        return tenant_usage[day_key]

    def get_usage(self, tenant_id: str) -> int:
        day_key = datetime.now(UTC).strftime("%Y-%m-%d")
        if self.dsn:
            return self._get_usage_db(tenant_id, day_key)
        data = self._load()
        return int(data.get("usage", {}).get(tenant_id, {}).get(day_key, 0))

    def authenticate(self, raw_key: str) -> Optional[TenantContext]:
        key_hash = self._hash_key(raw_key)
        if self.dsn:
            return self._authenticate_db(key_hash)
        data = self._load()
        for key_id, record in data.get("keys", {}).items():
            if record.get("status") != "active":
                continue
            if record.get("key_hash") == key_hash:
                user = data.get("users", {}).get(record["user_id"])
                if not user or user.get("status") != "active":
                    return None
                record["last_used"] = self._now()
                data["keys"][key_id] = record
                self._save(data)
                return TenantContext(
                    tenant_id=record["tenant_id"],
                    user_id=record["user_id"],
                    role=user.get("role", "viewer"),
                    api_key_id=key_id,
                )
        return None

    # ----------------------- Postgres backing -----------------------
    def _load_db(self) -> Dict[str, Any]:
        data = {"tenants": {}, "users": {}, "keys": {}}
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT tenant_id, name, plan, status, created_at FROM tenants")
                    for row in cur.fetchall():
                        data["tenants"][row[0]] = {
                            "tenant_id": row[0],
                            "name": row[1],
                            "plan": row[2],
                            "status": row[3],
                            "created_at": row[4].isoformat() if row[4] else None,
                        }
                    cur.execute("SELECT user_id, tenant_id, email, role, status, created_at FROM tenant_users")
                    for row in cur.fetchall():
                        data["users"][row[0]] = {
                            "user_id": row[0],
                            "tenant_id": row[1],
                            "email": row[2],
                            "role": row[3],
                            "status": row[4],
                            "created_at": row[5].isoformat() if row[5] else None,
                        }
                    cur.execute(
                        "SELECT key_id, tenant_id, user_id, label, key_hash, status, created_at, last_used FROM api_keys"
                    )
                    for row in cur.fetchall():
                        data["keys"][row[0]] = {
                            "key_id": row[0],
                            "tenant_id": row[1],
                            "user_id": row[2],
                            "label": row[3],
                            "key_hash": row[4],
                            "status": row[5],
                            "created_at": row[6].isoformat() if row[6] else None,
                            "last_used": row[7].isoformat() if row[7] else None,
                        }
        except Exception:
            pass
            cur.execute("SELECT tenant_id, day, events_count FROM tenant_usage")
            for row in cur.fetchall():
                data.setdefault("usage", {}).setdefault(row[0], {})[row[1].isoformat()] = row[2]
        return data

    def _save_db(self, data: Dict[str, Any]):
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    for tenant_id, tenant in data.get("tenants", {}).items():
                        cur.execute(
                            """
                            INSERT INTO tenants (tenant_id, name, plan, status, created_at)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (tenant_id) DO UPDATE SET
                              name = EXCLUDED.name,
                              plan = EXCLUDED.plan,
                              status = EXCLUDED.status
                            """,
                            (tenant_id, tenant["name"], tenant["plan"], tenant["status"], tenant["created_at"]),
                        )
                    for user_id, user in data.get("users", {}).items():
                        cur.execute(
                            """
                            INSERT INTO tenant_users (user_id, tenant_id, email, role, status, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (user_id) DO UPDATE SET
                              email = EXCLUDED.email,
                              role = EXCLUDED.role,
                              status = EXCLUDED.status
                            """,
                            (user_id, user["tenant_id"], user["email"], user["role"], user["status"], user["created_at"]),
                        )
                    for key_id, key in data.get("keys", {}).items():
                        cur.execute(
                            """
                            INSERT INTO api_keys (key_id, tenant_id, user_id, label, key_hash, status, created_at, last_used)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (key_id) DO UPDATE SET
                              label = EXCLUDED.label,
                              status = EXCLUDED.status,
                              last_used = EXCLUDED.last_used
                            """,
                            (
                                key_id,
                                key["tenant_id"],
                                key["user_id"],
                                key["label"],
                                key["key_hash"],
                                key["status"],
                                key["created_at"],
                                key.get("last_used"),
                            ),
                        )
                conn.commit()
        except Exception:
            pass

    def _record_usage_db(self, tenant_id: str, day_key: str, events: int) -> int:
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tenant_usage (tenant_id, day, events_count)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (tenant_id, day) DO UPDATE
                        SET events_count = tenant_usage.events_count + EXCLUDED.events_count
                        RETURNING events_count
                        """,
                        (tenant_id, day_key, events),
                    )
                    count = cur.fetchone()[0]
                conn.commit()
            return int(count)
        except Exception:
            return 0

    def _get_usage_db(self, tenant_id: str, day_key: str) -> int:
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT events_count FROM tenant_usage WHERE tenant_id = %s AND day = %s",
                        (tenant_id, day_key),
                    )
                    row = cur.fetchone()
                    return int(row[0]) if row else 0
        except Exception:
            return 0

    def _authenticate_db(self, key_hash: str) -> Optional[TenantContext]:
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT k.key_id, k.tenant_id, k.user_id, u.role
                        FROM api_keys k
                        JOIN tenant_users u ON u.user_id = k.user_id
                        WHERE k.key_hash = %s AND k.status = 'active' AND u.status = 'active'
                        """,
                        (key_hash,),
                    )
                    row = cur.fetchone()
                    if not row:
                        return None
                    key_id, tenant_id, user_id, role = row
                    cur.execute("UPDATE api_keys SET last_used = now() WHERE key_id = %s", (key_id,))
                conn.commit()
            return TenantContext(tenant_id=tenant_id, user_id=user_id, role=role, api_key_id=key_id)
        except Exception:
            return None

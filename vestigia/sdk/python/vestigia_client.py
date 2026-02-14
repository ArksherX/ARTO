#!/usr/bin/env python3
"""
Vestigia Python SDK (Phase 6 developer ecosystem).
Lightweight client for the Vestigia API.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, List
import httpx


class VestigiaClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, platform_admin_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.platform_admin_key = platform_admin_key

    def _headers(self) -> Dict[str, str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _platform_headers(self) -> Dict[str, str]:
        headers = {}
        if self.platform_admin_key:
            headers["X-Platform-Admin"] = self.platform_admin_key
        return headers

    def create_event(self, actor_id: str, action_type: str, status: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "actor_id": actor_id,
            "action_type": action_type,
            "status": status,
            "evidence": evidence,
        }
        return self._post("/events", payload)

    def batch_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self._post("/events/batch", {"events": events})

    def query_events(self, **params) -> Dict[str, Any]:
        return self._get("/events", params=params)

    def nl_query(self, query: str, limit: int = 200) -> Dict[str, Any]:
        return self._post("/nl/query", {"query": query, "limit": limit})

    def risk_forecast(self, actor_id: str, horizon_hours: int = 24) -> Dict[str, Any]:
        return self._get("/risk/forecast", params={"actor_id": actor_id, "horizon_hours": horizon_hours})

    def execute_playbook(self, name: str, actor_id: str, action_type: str, status: str, risk_score: float) -> Dict[str, Any]:
        payload = {
            "name": name,
            "actor_id": actor_id,
            "action_type": action_type,
            "status": status,
            "risk_score": risk_score,
        }
        return self._post("/playbooks/execute", payload)

    def create_tenant(self, name: str, plan: str, admin_email: str) -> Dict[str, Any]:
        payload = {"name": name, "plan": plan, "admin_email": admin_email}
        return self._post("/tenants", payload, platform_admin=True)

    def create_user(self, tenant_id: str, email: str, role: str = "viewer") -> Dict[str, Any]:
        payload = {"email": email, "role": role}
        return self._post(f"/tenants/{tenant_id}/users", payload)

    def create_api_key(self, tenant_id: str, user_id: str, label: str = "default") -> Dict[str, Any]:
        payload = {"user_id": user_id, "label": label}
        return self._post(f"/tenants/{tenant_id}/apikeys", payload)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
            resp.raise_for_status()
            return resp.json()

    def _post(self, path: str, payload: Dict[str, Any], platform_admin: bool = False) -> Dict[str, Any]:
        headers = self._platform_headers() if platform_admin else self._headers()
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{self.base_url}{path}", headers=headers, json=payload)
            resp.raise_for_status()
            return resp.json()

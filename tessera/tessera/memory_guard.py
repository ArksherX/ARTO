#!/usr/bin/env python3
"""
Session-Isolated Memory Guard Middleware
Validates JWT memory_hash against current session state.
"""

from __future__ import annotations

from typing import Optional, Iterable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from tessera.session_store import SessionStateStore
from tessera.token_generator import TokenGenerator


class SessionMemoryGuard(BaseHTTPMiddleware):
    """Middleware enforcing memory hash binding per session."""

    def __init__(
        self,
        app,
        token_generator: TokenGenerator,
        session_store: SessionStateStore,
        skip_paths: Optional[Iterable[str]] = None
    ):
        super().__init__(app)
        self.token_generator = token_generator
        self.session_store = session_store
        self.skip_paths = set(skip_paths or [])

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.skip_paths or request.method == "OPTIONS" or any(path.startswith(sp) for sp in self.skip_paths):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"detail": "Missing bearer token"}, status_code=401)

        token = auth.replace("Bearer ", "", 1).strip()
        payload = self.token_generator.validate_token(token)
        if not payload:
            return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

        agent_id = payload.get("sub")
        session_id = payload.get("session_id")
        token_memory_hash = payload.get("memory_hash")

        if not agent_id or not session_id or not token_memory_hash:
            return JSONResponse({"detail": "Missing session binding in token"}, status_code=403)

        current_hash = self.session_store.get_memory_hash(agent_id, session_id)
        if not current_hash:
            return JSONResponse({"detail": "Session state not found"}, status_code=403)

        if current_hash != token_memory_hash:
            return JSONResponse({"detail": "Session memory hash mismatch"}, status_code=403)

        return await call_next(request)

"""Route-level authentication audit (Pattern A regression guard).

Securing endpoints one at a time let several slip (score/track were fixed, but
/sessions, /state and ~12 core security endpoints were missed). This test
asserts the property systematically: every route MUST require authentication
unless it is on an explicit, reviewed public allowlist. A newly-added
unauthenticated route fails this test immediately.

Static introspection (checks each route's dependency tree for get_current_user)
rather than calling endpoints, so it is fast and free of body/path-param noise.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from verityflux_enterprise.api.v2 import app
import api.v2.main as m

# Routes that are legitimately reachable without a bearer credential.
# Each entry is a deliberate decision, not an oversight.
PUBLIC_ROUTES = {
    # Service infrastructure
    "/", "/health", "/ready", "/metrics",
    "/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc",
    # Pre-authentication (issue credentials; cannot themselves require one)
    "/api/v1/auth/login", "/api/v1/auth/refresh",
    # Intentionally public data
    "/api/v2/attestation/public_key",  # a public key is meant to be public
    "/api/v2/mcp/status",              # status probe, no sensitive data
    # Webhooks: authenticated by provider SIGNATURE verification, not by a
    # bearer token, so they correctly do NOT use get_current_user. Their
    # signature checks are a separate concern (tracked for phase 2), not an
    # auth-dependency gap this test can assert on.
    "/api/v1/webhooks/jira",
    "/api/v1/webhooks/pagerduty",
    "/api/v1/webhooks/slack/events",
    "/api/v1/webhooks/slack/interactive",
    "/api/v1/webhooks/stripe",
}

_HTTP = {"GET", "POST", "PUT", "DELETE", "PATCH"}


def _requires_auth(route) -> bool:
    seen = set()

    def walk(dep) -> bool:
        if dep is None or id(dep) in seen:
            return False
        seen.add(id(dep))
        if getattr(dep, "call", None) is m.get_current_user:
            return True
        return any(walk(d) for d in getattr(dep, "dependencies", []))

    return walk(getattr(route, "dependant", None))


def _api_routes():
    for r in app.routes:
        methods = getattr(r, "methods", None)
        path = getattr(r, "path", None)
        if path and methods and (methods & _HTTP):
            yield r


def test_no_unauthenticated_routes_outside_the_allowlist():
    offenders = sorted(
        r.path for r in _api_routes()
        if r.path not in PUBLIC_ROUTES and not _requires_auth(r)
    )
    assert not offenders, (
        "Routes reachable without authentication and not on the public "
        f"allowlist: {offenders}. Add Depends(get_current_user), or, if the "
        "route is genuinely public, add it to PUBLIC_ROUTES with a reason."
    )


def test_public_allowlist_has_no_stale_entries():
    """Keep the allowlist honest: every public entry must still be a real route."""
    real = {r.path for r in _api_routes()}
    stale = sorted(p for p in PUBLIC_ROUTES if p not in real)
    assert not stale, f"PUBLIC_ROUTES lists routes that no longer exist: {stale}"

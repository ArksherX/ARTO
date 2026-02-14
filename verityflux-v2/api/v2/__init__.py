"""
VerityFlux Enterprise - API v2

FastAPI-based REST API with:
- Authentication (JWT + API Keys)
- Agent management
- HITL approval workflows
- SOC event ingestion
- Vulnerability scanning
- Metrics & health endpoints
"""

# Import will be from main.py or app.py depending on which exists
try:
    from .main import app
except ImportError:
    try:
        from .app import app
    except ImportError:
        app = None

__all__ = ["app"]

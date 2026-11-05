# VerityFlux runtime API.
#
# This service had no Dockerfile at all: the suite compose file ran a bare
# python:3.11-slim against mounted source, which is a development harness and
# cannot be pushed to a registry or deployed.
#
# Build from the verityflux-v2 directory:
#   docker build -t verityflux-api .
#
# Configuration comes from the environment, never from the image. For a
# deployed environment set at least:
#   VERITYFLUX_DB_DSN         PostgreSQL, so stores outlive the container
#   VERITYFLUX_STORE_STRICT   true, so an unreachable database fails loudly
#   VERITYFLUX_SCORER_API_KEY NVIDIA NIM credentials
# See ops/internal/secrets_env.md for the full list.

FROM python:3.11-slim AS base

# curl is here because the HEALTHCHECK below uses it. python:3.11-slim does
# not ship curl, so a healthcheck that calls it without this can only fail.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# First-party packages that api/v2/main.py and its imports actually need.
COPY api/ ./api/
COPY core/ ./core/
COPY cognitive_firewall/ ./cognitive_firewall/
COPY detectors/ ./detectors/
COPY integrations/ ./integrations/
COPY intent_analysis/ ./intent_analysis/
COPY verityflux_enterprise/ ./verityflux_enterprise/
COPY config/ ./config/

# Writable scratch for anything that still touches disk. Deliberately empty:
# the stores it used to hold now live in PostgreSQL, and a container that
# starts with seeded state would serve stale API keys.
RUN mkdir -p /app/data /app/logs

# Run unprivileged. A security tool running as root in its own container is
# the first thing a reviewer will ask about.
RUN useradd --create-home --uid 10001 verityflux \
    && chown -R verityflux:verityflux /app
USER verityflux

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VERITYFLUX_PORT=8003

EXPOSE 8003

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://localhost:${VERITYFLUX_PORT}/health" || exit 1

# Shell form so VERITYFLUX_PORT is honoured. With the exec form the port was
# hardcoded while ENV and HEALTHCHECK used the variable, so setting it moved
# the health check off the port the app was actually listening on.
CMD exec python -m uvicorn api.v2.main:app --host 0.0.0.0 --port "${VERITYFLUX_PORT:-8003}"

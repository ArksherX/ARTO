# VerityFlux Enterprise - Production Dockerfile
# Optimized for air-gapped deployments

# =============================================================================
# STAGE 1: Builder
# =============================================================================
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# STAGE 2: Production Image
# =============================================================================
FROM python:3.12-slim as production

# Security: Run as non-root user
RUN groupadd -r verityflux && useradd -r -g verityflux verityflux

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create application directories
RUN mkdir -p /app/data/vulndb \
             /app/data/updates \
             /app/data/scans \
             /app/data/audit \
             /app/data/backups \
             /app/logs \
    && chown -R verityflux:verityflux /app

WORKDIR /app

# Copy application code
COPY --chown=verityflux:verityflux . /app/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    AIR_GAPPED_MODE=true \
    DEPLOYMENT_MODE=air_gapped \
    DATA_DIR=/app/data \
    VULN_DB_PATH=/app/data/vulndb \
    OFFLINE_UPDATES_PATH=/app/data/updates \
    SCAN_RESULTS_PATH=/app/data/scans \
    AUDIT_LOG_PATH=/app/data/audit \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    API_WORKERS=4 \
    LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

USER verityflux
EXPOSE 8000
CMD ["uvicorn", "api.v2.main:app", "--host", "0.0.0.0", "--port", "8000"]

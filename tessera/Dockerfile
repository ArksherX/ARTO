FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY tessera/ ./tessera/
COPY integration/ ./integration/
COPY api_server.py .
# .env is deliberately NOT copied: it is gitignored, so this failed any build
# from a clean checkout, and baking secrets into an image is wrong regardless.
# Supply configuration at runtime via environment variables or a mounted
# Secret -- see ops/internal/secrets_env.md for the required variables.

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run API server
CMD ["python", "api_server.py"]

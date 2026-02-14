#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Vestigia Production Deployment Script
# One-command deployment of the full 15-service stack
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  Vestigia Production Deployment"
echo "============================================================"
echo ""

# ------------------------------------------------------------------
# 1. Prerequisites
# ------------------------------------------------------------------
echo "[1/7] Checking prerequisites..."

for cmd in docker; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "  ERROR: $cmd is not installed"
        exit 1
    fi
done

# Check for docker compose (v2 plugin or standalone)
if docker compose version &>/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    echo "  ERROR: docker compose is not available"
    exit 1
fi
echo "  Using: $DC"

# ------------------------------------------------------------------
# 2. Generate SSL certificates (self-signed for testing)
# ------------------------------------------------------------------
echo "[2/7] Setting up TLS certificates..."

SSL_DIR="$SCRIPT_DIR/config/nginx/ssl"
mkdir -p "$SSL_DIR"

if [ ! -f "$SSL_DIR/vestigia.crt" ]; then
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$SSL_DIR/vestigia.key" \
        -out "$SSL_DIR/vestigia.crt" \
        -subj "/CN=vestigia.local/O=Vestigia/C=US" \
        2>/dev/null
    echo "  Generated self-signed certificate"
else
    echo "  Certificate already exists"
fi

# ------------------------------------------------------------------
# 3. Generate secrets / .env
# ------------------------------------------------------------------
echo "[3/7] Generating secrets..."

gen_secret() { python3 -c "import secrets; print(secrets.token_urlsafe(32))"; }

if [ ! -f "$SCRIPT_DIR/.env" ] || ! grep -q "DB_PASSWORD" "$SCRIPT_DIR/.env" 2>/dev/null; then
    DB_PASSWORD="$(gen_secret)"
    GRAFANA_PASSWORD="$(gen_secret)"
    API_KEY="$(gen_secret)"
    SALT="$(gen_secret)"

    cat > "$SCRIPT_DIR/.env" <<EOF
# Vestigia Production Secrets — AUTO-GENERATED $(date -Iseconds)
VESTIGIA_MODE=production
DB_PASSWORD=${DB_PASSWORD}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}
VESTIGIA_API_KEY=${API_KEY}
VESTIGIA_SECRET_SALT=${SALT}
VESTIGIA_DB_DSN=postgresql://vestigia:${DB_PASSWORD}@vestigia-db:5432/vestigia
EOF

    cat > "$SCRIPT_DIR/.credentials" <<EOF
# Vestigia Credentials — KEEP SAFE
# Generated: $(date -Iseconds)
DB_PASSWORD=${DB_PASSWORD}
GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
VESTIGIA_API_KEY=${API_KEY}
VESTIGIA_SECRET_SALT=${SALT}
EOF
    chmod 600 "$SCRIPT_DIR/.credentials"
    echo "  Generated new secrets (see .credentials)"
else
    echo "  Using existing .env"
fi

# ------------------------------------------------------------------
# 4. Create directories
# ------------------------------------------------------------------
echo "[4/7] Creating directories..."
mkdir -p data backups logs config/nginx/ssl

# ------------------------------------------------------------------
# 5. Build & start services
# ------------------------------------------------------------------
echo "[5/7] Building and starting services..."
$DC up -d --build 2>&1 | tail -5

# ------------------------------------------------------------------
# 6. Wait for health checks
# ------------------------------------------------------------------
echo "[6/7] Waiting for services to become healthy..."

wait_for() {
    local name="$1" url="$2" max=60 i=0
    printf "  Waiting for %-20s" "$name..."
    while [ $i -lt $max ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            echo " ready"
            return 0
        fi
        sleep 2
        i=$((i+2))
    done
    echo " TIMEOUT"
    return 1
}

wait_for "vestigia-api" "http://localhost:8000/health" || true
wait_for "vestigia-dashboard" "http://localhost:8503" || true
wait_for "grafana" "http://localhost:3000/api/health" || true
wait_for "prometheus" "http://localhost:9090/-/ready" || true

# ------------------------------------------------------------------
# 7. Run database migrations
# ------------------------------------------------------------------
echo "[7/7] Running database migrations..."
$DC exec -T vestigia-db psql -U vestigia -d vestigia < sql/schema.sql 2>/dev/null || echo "  Schema may already exist"
$DC exec -T vestigia-db psql -U vestigia -d vestigia < sql/phase2-migrations.sql 2>/dev/null || echo "  Migrations may already exist"

# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Vestigia Deployment Complete!"
echo "============================================================"
echo ""
echo "  Service URLs:"
echo "    Dashboard:    https://localhost (or http://localhost:8503)"
echo "    API Docs:     http://localhost:8000/docs"
echo "    Grafana:      http://localhost:3000  (admin / see .credentials)"
echo "    Prometheus:   http://localhost:9090"
echo "    Jaeger:       http://localhost:16686"
echo "    AlertManager: http://localhost:9093"
echo ""
echo "  API Key:        see .credentials file"
echo "  Quick test:"
echo '    curl -s http://localhost:8000/health | python3 -m json.tool'
echo ""
echo "============================================================"

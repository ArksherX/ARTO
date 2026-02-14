#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Activate venv if present
if [[ -f "/home/arksher/venv/bin/activate" ]]; then
  source "/home/arksher/venv/bin/activate"
elif [[ -f "$ROOT_DIR/venv/bin/activate" ]]; then
  source "$ROOT_DIR/venv/bin/activate"
fi

if [[ -z "${TESSERA_SECRET_KEY:-}" ]]; then
  export TESSERA_SECRET_KEY="$(python - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
)"
  echo "Generated TESSERA_SECRET_KEY"
fi

API_MODE="${TESSERA_MODE:-dev}"
API_PORT="${TESSERA_PORT:-8001}"
export TESSERA_PORT="$API_PORT"

echo "Starting Tessera ($API_MODE)..."

if [[ "$API_MODE" == "prod" ]]; then
  python api_server_production.py &
else
  python api_server.py &
fi

API_PID=$!

echo "Starting dashboard..."
export STREAMLIT_BROWSER_GATHER_USAGE_STATS="false"
export STREAMLIT_TELEMETRY_OPTOUT="true"
python -m streamlit run web_ui/tessera_dashboard.py --server.headless true --server.address 0.0.0.0 --server.port 8501 &
UI_PID=$!

echo ""
echo "Tessera API: http://localhost:${API_PORT}/docs"
echo "Health:      http://localhost:${API_PORT}/health"
echo "Dashboard:   http://localhost:8501"
echo ""
echo "Press Ctrl+C to stop"

trap 'echo "Stopping..."; kill $API_PID $UI_PID' INT TERM
wait

#!/bin/bash
set -euo pipefail

# --- CONFIGURATION ---
RUN_MODE=${MODE:-"prod"}
ROOT_DIR="${ROOT_DIR:-/home/arksher/ml-redteam}"
SHARED_LOG="${ROOT_DIR}/shared_state/shared_audit.log"

ENV_FILE="${ROOT_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

export TESSERA_PORT="${TESSERA_PORT:-8001}"
export VESTIGIA_PORT="${VESTIGIA_PORT:-8002}"
export VERITYFLUX_PORT="${VERITYFLUX_PORT:-8003}"
export SUITE_AUDIT_LOG="${SUITE_AUDIT_LOG:-$SHARED_LOG}"
export TESSERA_API_BASE="${TESSERA_API_BASE:-http://localhost:${TESSERA_PORT}}"
export VESTIGIA_API_BASE="${VESTIGIA_API_BASE:-http://localhost:${VESTIGIA_PORT}}"
export MLRT_INTEGRATION_ENABLED="${MLRT_INTEGRATION_ENABLED:-true}"
export MLRT_VESTIGIA_INGEST_URL="${MLRT_VESTIGIA_INGEST_URL:-http://localhost:${VESTIGIA_PORT}/events}"
export MLRT_VESTIGIA_API_KEY="${MLRT_VESTIGIA_API_KEY:-${VESTIGIA_API_KEY:-}}"
export TESSERA_SECRET_KEY="${TESSERA_SECRET_KEY:-168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06}"
export VERITYFLUX_POLICY_PATH="${VERITYFLUX_POLICY_PATH:-${ROOT_DIR}/verityflux-v2/config/policy.json}"
export VERITYFLUX_API_BASE="${VERITYFLUX_API_BASE:-http://localhost:${VERITYFLUX_PORT}}"
export VERITYFLUX_API_KEY="${VERITYFLUX_API_KEY:-vf_admin_demo_key}"

mkdir -p "$(dirname "$SUITE_AUDIT_LOG")"

if [[ -f "${ROOT_DIR}/preflight_check.py" ]]; then
    python3 "${ROOT_DIR}/preflight_check.py"
fi

echo "🚀 Launching Suite in [$RUN_MODE] mode..."

if [ "$RUN_MODE" == "demo" ]; then
    echo "🧹 DEMO MODE: Clearing old audit logs for a fresh start..."
    : > "$SUITE_AUDIT_LOG"
else
    echo "🛡️  PROD MODE: Preserving existing audit trail."
    touch "$SUITE_AUDIT_LOG"
fi

source_venv() {
    if [[ -f "/home/arksher/venv/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "/home/arksher/venv/bin/activate"
    elif [[ -f "$1/venv/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "$1/venv/bin/activate"
    fi
}

start_api() {
    local name="$1" dir="$2" cmd="$3" log="$4"
    cd "$dir"
    source_venv "$dir"
    eval "$cmd" > "$log" 2>&1 &
    echo $!
}

start_ui() {
    local name="$1" dir="$2" cmd="$3" log="$4"
    cd "$dir"
    source_venv "$dir"
    eval "$cmd" > "$log" 2>&1 &
    echo $!
}

echo "Starting Tessera API..."
TESSERA_API_PID=$(start_api "Tessera" "${ROOT_DIR}/tessera" "python api_server.py" "${ROOT_DIR}/logs_tessera_api.log")
echo "Starting Vestigia API..."
VESTIGIA_API_PID=$(start_api "Vestigia" "${ROOT_DIR}/vestigia" "python api_server.py" "${ROOT_DIR}/logs_vestigia.log")
echo "Starting VerityFlux API..."
VERITYFLUX_API_PID=$(start_api "VerityFlux" "${ROOT_DIR}/verityflux-v2" "PYTHONPATH=${ROOT_DIR}/verityflux-v2 python api/v2/main.py" "${ROOT_DIR}/logs_verityflux.log")

echo "Starting Tessera UI..."
TESSERA_UI_PID=$(start_ui "Tessera" "${ROOT_DIR}/tessera" "streamlit run web_ui/tessera_dashboard.py --server.headless true" "${ROOT_DIR}/logs_tessera_ui.log")
echo "Starting Vestigia UI..."
VESTIGIA_UI_PID=$(start_ui "Vestigia" "${ROOT_DIR}/vestigia" "streamlit run dashboard.py --server.headless true" "${ROOT_DIR}/logs_vestigia_ui.log")
echo "Starting VerityFlux UI..."
VERITYFLUX_UI_PID=$(start_ui "VerityFlux" "${ROOT_DIR}/verityflux-v2" "streamlit run ui/streamlit/app.py --server.headless true" "${ROOT_DIR}/logs_verityflux_ui.log")

echo "------------------------------------------------"
echo "✅ Tessera UI:    http://localhost:8501"
echo "✅ Vestigia UI:   http://localhost:8502"
echo "✅ VerityFlux UI: http://localhost:8503"
echo "✅ Tessera API:   http://localhost:${TESSERA_PORT}"
echo "✅ Vestigia API:  http://localhost:${VESTIGIA_PORT}"
echo "✅ VerityFlux API:http://localhost:${VERITYFLUX_PORT}"
echo "✅ Integration:   ${MLRT_INTEGRATION_ENABLED} -> ${MLRT_VESTIGIA_INGEST_URL}"
echo "✅ Shared Audit:  ${SUITE_AUDIT_LOG}"
echo "------------------------------------------------"

trap 'echo "Stopping all services..."; kill '"$TESSERA_API_PID"' '"$VESTIGIA_API_PID"' '"$VERITYFLUX_API_PID"' '"$TESSERA_UI_PID"' '"$VESTIGIA_UI_PID"' '"$VERITYFLUX_UI_PID"' 2>/dev/null || true; exit' INT TERM
wait

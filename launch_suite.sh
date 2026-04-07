#!/bin/bash
set -euo pipefail

# --- CONFIGURATION ---
RUN_MODE=${MODE:-"prod"}
ROOT_DIR="${ROOT_DIR:-/home/arksher/ml-redteam}"
SHARED_LOG="${ROOT_DIR}/shared_state/shared_audit.log"
STRICT_MODE="${SUITE_STRICT_MODE:-false}"
RUN_DIR="${ROOT_DIR}/run"

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
export VERITYFLUX_POLICY_PATH="${VERITYFLUX_POLICY_PATH:-${ROOT_DIR}/verityflux-v2/config/policy.json}"
export VERITYFLUX_API_BASE="${VERITYFLUX_API_BASE:-http://localhost:${VERITYFLUX_PORT}}"

if [[ "${STRICT_MODE,,}" == "true" || "${STRICT_MODE}" == "1" || "${STRICT_MODE,,}" == "yes" ]]; then
    export TESSERA_SECRET_KEY="${TESSERA_SECRET_KEY:-}"
    export TESSERA_ADMIN_KEY="${TESSERA_ADMIN_KEY:-}"
    export VERITYFLUX_API_KEY="${VERITYFLUX_API_KEY:-}"
    export VERITYFLUX_MCP_TOOL_SECRET="${VERITYFLUX_MCP_TOOL_SECRET:-}"
    export VERITYFLUX_MANIFEST_KEY="${VERITYFLUX_MANIFEST_KEY:-}"
    export VESTIGIA_SECRET_SALT="${VESTIGIA_SECRET_SALT:-}"
else
    export TESSERA_SECRET_KEY="${TESSERA_SECRET_KEY:-168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06}"
    export TESSERA_ADMIN_KEY="${TESSERA_ADMIN_KEY:-tessera-demo-key-change-in-production}"
    export VERITYFLUX_API_KEY="${VERITYFLUX_API_KEY:-vf_admin_demo_key}"
    export VERITYFLUX_MCP_TOOL_SECRET="${VERITYFLUX_MCP_TOOL_SECRET:-verityflux-mcp-dev-secret-change-in-production}"
    export VERITYFLUX_MANIFEST_KEY="${VERITYFLUX_MANIFEST_KEY:-default-manifest-signing-key}"
fi

mkdir -p "$(dirname "$SUITE_AUDIT_LOG")"
mkdir -p "${RUN_DIR}"

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

resolve_bin() {
    local dir="$1" bin_name="$2"
    if [[ -x "/home/arksher/venv/bin/${bin_name}" ]]; then
        echo "/home/arksher/venv/bin/${bin_name}"
    elif [[ -x "${dir}/venv/bin/${bin_name}" ]]; then
        echo "${dir}/venv/bin/${bin_name}"
    else
        command -v "${bin_name}"
    fi
}

start_detached() {
    local name="$1" dir="$2" log="$3" pidfile="$4"
    shift 4
    (
        cd "$dir"
        setsid "$@" >> "$log" 2>&1 < /dev/null &
        echo $! > "$pidfile"
    )
}

wait_for_port() {
    local port="$1" label="$2"
    for _ in $(seq 1 30); do
        if lsof -i :"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
            echo "✅ ${label}"
            return 0
        fi
        sleep 1
    done
    echo "❌ ${label} failed to start"
    return 1
}

TESSERA_DIR="${ROOT_DIR}/tessera"
VESTIGIA_DIR="${ROOT_DIR}/vestigia"
VERITYFLUX_DIR="${ROOT_DIR}/verityflux-v2"
TESSERA_PYTHON="$(resolve_bin "${TESSERA_DIR}" python)"
VESTIGIA_PYTHON="$(resolve_bin "${VESTIGIA_DIR}" python)"
VERITYFLUX_PYTHON="$(resolve_bin "${VERITYFLUX_DIR}" python)"
TESSERA_STREAMLIT="$(resolve_bin "${TESSERA_DIR}" streamlit)"
VESTIGIA_STREAMLIT="$(resolve_bin "${VESTIGIA_DIR}" streamlit)"
VERITYFLUX_STREAMLIT="$(resolve_bin "${VERITYFLUX_DIR}" streamlit)"

echo "Starting Tessera API..."
start_detached "Tessera API" "${TESSERA_DIR}" "${ROOT_DIR}/logs_tessera_api.log" "${RUN_DIR}/tessera_api.pid" "${TESSERA_PYTHON}" api_server.py
echo "Starting Vestigia API..."
start_detached "Vestigia API" "${VESTIGIA_DIR}" "${ROOT_DIR}/logs_vestigia.log" "${RUN_DIR}/vestigia_api.pid" "${VESTIGIA_PYTHON}" api_server.py
echo "Starting VerityFlux API..."
start_detached "VerityFlux API" "${VERITYFLUX_DIR}" "${ROOT_DIR}/logs_verityflux.log" "${RUN_DIR}/verityflux_api.pid" env "PYTHONPATH=${ROOT_DIR}/verityflux-v2" "${VERITYFLUX_PYTHON}" api/v2/main.py

echo "Starting Tessera UI..."
start_detached "Tessera UI" "${TESSERA_DIR}" "${ROOT_DIR}/logs_tessera_ui.log" "${RUN_DIR}/tessera_ui.pid" "${TESSERA_STREAMLIT}" run web_ui/tessera_dashboard.py --server.headless true
echo "Starting Vestigia UI..."
start_detached "Vestigia UI" "${VESTIGIA_DIR}" "${ROOT_DIR}/logs_vestigia_ui.log" "${RUN_DIR}/vestigia_ui.pid" "${VESTIGIA_STREAMLIT}" run dashboard.py --server.headless true
echo "Starting VerityFlux UI..."
start_detached "VerityFlux UI" "${VERITYFLUX_DIR}" "${ROOT_DIR}/logs_verityflux_ui.log" "${RUN_DIR}/verityflux_ui.pid" "${VERITYFLUX_STREAMLIT}" run ui/streamlit/app.py --server.headless true

echo "Waiting for services..."
wait_for_port "${TESSERA_PORT}" "Tessera API listening on ${TESSERA_PORT}" || exit 1
wait_for_port "${VESTIGIA_PORT}" "Vestigia API listening on ${VESTIGIA_PORT}" || exit 1
wait_for_port "${VERITYFLUX_PORT}" "VerityFlux API listening on ${VERITYFLUX_PORT}" || exit 1
wait_for_port 8501 "Tessera UI listening on 8501" || exit 1
wait_for_port 8502 "Vestigia UI listening on 8502" || exit 1
wait_for_port 8503 "VerityFlux UI listening on 8503" || exit 1

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

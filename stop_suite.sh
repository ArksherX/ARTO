#!/bin/bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/arksher/ml-redteam}"
RUN_DIR="${ROOT_DIR}/run"

# Ports used by suite (defaults)
PORTS=(8001 8002 8003 8501 8502 8503)

# Stop using PID files first (set by launch_suite.sh).
if [[ -d "${RUN_DIR}" ]]; then
  for pidfile in "${RUN_DIR}"/*.pid; do
    [[ -e "$pidfile" ]] || continue
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "Stopping $(basename "$pidfile" .pid) via pidfile..."
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  done
fi

sleep 1

# Kill by known ports (covers backgrounded launch_suite.sh)
if command -v lsof >/dev/null 2>&1; then
  PIDS=$(lsof -t -i TCP:8001 -i TCP:8002 -i TCP:8003 -i TCP:8501 -i TCP:8502 -i TCP:8503 2>/dev/null | sort -u || true)
  if [[ -n "${PIDS:-}" ]]; then
    echo "Stopping suite processes by port..."
    echo "$PIDS" | xargs -r kill
  fi
fi

# Fallback: kill common process patterns
pkill -f "python api_server.py" 2>/dev/null || true
pkill -f "python api/v2/main.py" 2>/dev/null || true
pkill -f "streamlit run web_ui/tessera_dashboard.py" 2>/dev/null || true
pkill -f "streamlit run dashboard.py" 2>/dev/null || true
pkill -f "streamlit run ui/streamlit/app.py" 2>/dev/null || true

# If any still running, show status
if command -v lsof >/dev/null 2>&1; then
  echo "Remaining listeners (if any):"
  lsof -n -P -iTCP -sTCP:LISTEN | grep -E "(8001|8002|8003|8501|8502|8503)" || true
fi

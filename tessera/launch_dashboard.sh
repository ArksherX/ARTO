#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
streamlit run web_ui/tessera_dashboard.py --server.port 8501 --server.address localhost

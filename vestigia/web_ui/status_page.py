#!/usr/bin/env python3
"""
Simple operator status page for Vestigia.
"""

import os
import streamlit as st
import httpx

API_BASE = os.getenv("VESTIGIA_API_BASE", "http://localhost:8000")

st.set_page_config(page_title="Vestigia Status", page_icon="🛰️", layout="wide")
st.title("🛰️ Vestigia Status")
st.caption(f"API: {API_BASE}")

try:
    resp = httpx.get(f"{API_BASE}/status", timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
except Exception as exc:
    st.error(f"Failed to fetch status: {exc}")
    st.stop()

st.subheader(f"Overall Status: {data.get('status','unknown').upper()}")
st.write(f"Version: {data.get('version')}")
st.write(f"Timestamp: {data.get('timestamp')}")

st.markdown("### Components")
for comp in data.get("components", []):
    st.write(f"**{comp['component']}** — {comp['status']}")
    st.json({k: v for k, v in comp.items() if k not in ("component", "status")})

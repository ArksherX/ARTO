#!/bin/bash

echo "Testing VerityFlux 2.0 API Endpoints"
echo "===================================="

# Test 1: Health check
echo ""
echo "[TEST 1] Health Check"
curl -s http://localhost:5000/api/health | python3 -m json.tool

# Test 2: Security scan
echo ""
echo "[TEST 2] Security Scan"
curl -s -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "mock",
    "model": "mock",
    "is_agent": true
  }' | python3 -m json.tool | head -30

# Test 3: Cognitive Firewall
echo ""
echo "[TEST 3] Cognitive Firewall"
curl -s -X POST http://localhost:5000/api/firewall \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_001",
    "tool_name": "delete_database",
    "parameters": {"table": "users"},
    "reasoning_chain": ["Database slow", "Delete to optimize"],
    "original_goal": "Optimize database"
  }' | python3 -m json.tool

# Test 4: Complete Stack
echo ""
echo "[TEST 4] Complete Stack (MCP + Firewall + Sandbox)"
curl -s -X POST http://localhost:5000/api/complete \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_002",
    "tool_name": "read_file",
    "parameters": {"path": "/data/report.pdf"},
    "reasoning_chain": ["User requested report"],
    "original_goal": "Get report",
    "code_to_execute": "print(2 + 2)"
  }' | python3 -m json.tool

# Test 5: Statistics
echo ""
echo "[TEST 5] Statistics"
curl -s http://localhost:5000/api/stats | python3 -m json.tool


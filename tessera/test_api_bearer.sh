#!/bin/bash

# Load API key from .env
export $(grep TESSERA_API_KEY .env | xargs)

echo "🧪 Testing Tessera API with Bearer Authentication"
echo "=================================================="
echo ""

# Test 1: Health check
echo "Test 1: Health Check"
curl -s http://localhost:8000/health | jq .
echo ""

# Test 2: List agents
echo "Test 2: List Agents"
curl -s -H "Authorization: Bearer $TESSERA_API_KEY" \
  http://localhost:8000/agents/list | jq .
echo ""

# Prepare DPoP public key (PEM -> single-line with \n escapes)
PUBLIC_KEY=$(awk 'NF {sub(/\r/,""); printf "%s\\n",$0;}' keys/public_key.pem)

# Test 3: Request token (authorized)
echo "Test 3: Request Token (Authorized - read_csv)"
curl -s -X POST http://localhost:8000/tokens/request \
  -H "Authorization: Bearer $TESSERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_financial_bot_01",
    "tool": "read_csv",
    "duration_minutes": 60,
    "session_id": "test_session_api",
    "memory_state": "initial_memory_state",
    "client_public_key": "'"$PUBLIC_KEY"'"
  }' | jq .
echo ""

# Test 4: Request token (unauthorized tool)
echo "Test 4: Request Token (Unauthorized - terminal_exec)"
curl -s -X POST http://localhost:8000/tokens/request \
  -H "Authorization: Bearer $TESSERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_financial_bot_01",
    "tool": "terminal_exec",
    "duration_minutes": 60,
    "session_id": "test_session_api",
    "memory_state": "initial_memory_state",
    "client_public_key": "'"$PUBLIC_KEY"'"
  }' | jq .
echo ""

echo "✅ Tests complete!"

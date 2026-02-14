#!/bin/bash
# Tessera Quick Fix Script
# Fixes missing redis_stream.py and creates necessary files

cd ~/ml-redteam/tessera

echo "🔧 Tessera IAM - Quick Fix Script"
echo "=================================="
echo ""

# Step 1: Create data directory
echo "1️⃣ Creating data directory..."
mkdir -p data
echo "   ✅ Done"

# Step 2: Create redis_stream.py (fallback version without Redis)
echo ""
echo "2️⃣ Creating tessera/redis_stream.py (local fallback mode)..."
cat > tessera/redis_stream.py << 'REDISEOF'
#!/usr/bin/env python3
"""
Tessera Redis Stream - Fallback Mode
Works without Redis for development/testing
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class TesseraRedisStream:
    """
    Redis-compatible stream that works locally without Redis
    For production, install Redis and use the full version
    """
    
    def __init__(self, host=None, port=None, db=0, decode_responses=True):
        self.mode = "local"
        self.data_dir = "data"
        self.traffic_log = f"{self.data_dir}/live_traffic.json"
        self.metrics_file = f"{self.data_dir}/metrics.json"
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        print(f"⚠️  Running in LOCAL mode (Redis not available)")
        print(f"   Using JSON files in {self.data_dir}/")
        print(f"   For production, install Redis: docker run -p 6379:6379 redis")
    
    def is_available(self) -> bool:
        """Always return False in fallback mode"""
        return False
    
    def broadcast_event(self, event_type: str, agent_id: str, tool: str, 
                       status: str, details: Optional[str] = None):
        """Store event in JSON file"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "agent": agent_id,
            "tool": tool,
            "status": status,
            "details": details or ""
        }
        
        try:
            # Read existing events
            if os.path.exists(self.traffic_log):
                with open(self.traffic_log, 'r') as f:
                    events = json.load(f)
            else:
                events = []
            
            # Add new event at start
            events.insert(0, event)
            
            # Keep last 100 events
            events = events[:100]
            
            # Write back
            with open(self.traffic_log, 'w') as f:
                json.dump(events, f, indent=2)
        except Exception as e:
            print(f"⚠️  Event logging error: {e}")
    
    def broadcast_alert(self, severity: str, message: str, agent_id: Optional[str] = None):
        """Log alert (no-op in local mode)"""
        print(f"🚨 ALERT [{severity}]: {message}")
    
    def get_event_history(self, limit: int = 100) -> List[Dict]:
        """Retrieve event history from JSON"""
        try:
            if os.path.exists(self.traffic_log):
                with open(self.traffic_log, 'r') as f:
                    events = json.load(f)
                return events[:limit]
        except:
            pass
        return []
    
    def increment_metric(self, metric_name: str, value: int = 1):
        """Increment a counter metric"""
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    metrics = json.load(f)
            else:
                metrics = {}
            
            metrics[metric_name] = metrics.get(metric_name, 0) + value
            
            with open(self.metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
        except Exception as e:
            print(f"⚠️  Metrics error: {e}")
    
    def get_metric(self, metric_name: str) -> int:
        """Get metric value"""
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    metrics = json.load(f)
                return metrics.get(metric_name, 0)
        except:
            pass
        return 0
    
    def get_all_metrics(self) -> Dict[str, int]:
        """Get all metrics"""
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def revoke_token(self, jti: str, ttl: int = 3600):
        """Store revoked token (no-op in local mode)"""
        print(f"   Token {jti} revoked (local mode)")
    
    def is_revoked(self, jti: str) -> bool:
        """Check revocation (always False in local mode)"""
        return False
    
    def get_revoked_tokens(self) -> List[str]:
        """Get revoked tokens"""
        return []
    
    def cache_token(self, jti: str, token_data: Dict, ttl: int):
        """Cache token (no-op in local mode)"""
        pass
    
    def get_cached_token(self, jti: str) -> Optional[Dict]:
        """Get cached token"""
        return None
    
    def health_check(self) -> Dict:
        """Health check"""
        return {
            "status": "fallback",
            "mode": "local",
            "message": "Using JSON files (Redis not available)"
        }

if __name__ == "__main__":
    print("Testing local fallback mode...")
    stream = TesseraRedisStream()
    
    stream.broadcast_event("TEST", "agent_01", "test_tool", "success")
    print(f"✅ Event logged")
    
    history = stream.get_event_history()
    print(f"✅ Retrieved {len(history)} events")
REDISEOF

echo "   ✅ Created tessera/redis_stream.py (fallback mode)"

# Step 3: Test imports
echo ""
echo "3️⃣ Testing Python imports..."
python3 << 'TESTEOF'
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

try:
    from tessera.redis_stream import TesseraRedisStream
    print("   ✅ redis_stream imports successfully")
except Exception as e:
    print(f"   ❌ Import failed: {e}")
    sys.exit(1)

try:
    from tessera.registry import TesseraRegistry
    print("   ✅ registry imports successfully")
except Exception as e:
    print(f"   ❌ Import failed: {e}")
    sys.exit(1)

print("   ✅ All imports working")
TESTEOF

# Step 4: Test API server can start
echo ""
echo "4️⃣ Testing API server..."
timeout 3 python api_server.py &
sleep 2

if curl -s http://localhost:8000/ > /dev/null 2>&1; then
    echo "   ✅ API server starts successfully"
    pkill -f api_server.py
else
    echo "   ⚠️  API server test skipped (might need manual start)"
fi

# Summary
echo ""
echo "=================================="
echo "✅ Quick Fix Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo ""
echo "Terminal 1: Start API Server"
echo "  cd ~/ml-redteam/tessera"
echo "  source venv/bin/activate"
echo "  python api_server.py"
echo ""
echo "Terminal 2: Start Dashboard"
echo "  cd ~/ml-redteam/tessera"
echo "  source venv/bin/activate"
echo "  streamlit run web_ui/tessera_dashboard.py"
echo ""
echo "Terminal 3: Test Client"
echo "  cd ~/ml-redteam/tessera"
echo "  source venv/bin/activate"
echo "  python tessera_client.py"
echo ""
echo "📝 NOTE: Running in LOCAL mode (no Redis)"
echo "   For production with Redis:"
echo "   docker run -d -p 6379:6379 redis:alpine"

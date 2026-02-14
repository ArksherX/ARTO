#!/usr/bin/env python3
"""
Tessera Redis Stream - Production Version
Real-time event streaming with Redis
"""

import redis
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class TesseraRedisStream:
    """Production-grade event streaming for Tessera"""
    
    CHANNEL_TRAFFIC = "tessera:traffic"
    CHANNEL_ALERTS = "tessera:alerts"
    KEY_HISTORY = "tessera:history"
    KEY_METRICS = "tessera:metrics"
    KEY_REVOKED = "tessera:revoked"
    KEY_TOKEN_CACHE = "tessera:tokens"
    
    def __init__(self, host=None, port=None, db=0, decode_responses=True):
        """Initialize Redis connection"""
        self.host = host or os.getenv('REDIS_HOST', 'localhost')
        self.port = int(port or os.getenv('REDIS_PORT', 6379))
        self.db = db
        
        try:
            self.redis = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=decode_responses,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            # Test connection
            self.redis.ping()
            self.available = True
            print(f"✅ Connected to Redis at {self.host}:{self.port}")
        except (redis.ConnectionError, redis.TimeoutError) as e:
            print(f"⚠️  Redis not available: {e}")
            print(f"   Falling back to local mode")
            self.redis = None
            self.available = False
            self._init_fallback()
    
    def _init_fallback(self):
        """Initialize fallback mode with JSON files"""
        self.data_dir = "data"
        self.traffic_log = f"{self.data_dir}/live_traffic.json"
        self.metrics_file = f"{self.data_dir}/metrics.json"
        os.makedirs(self.data_dir, exist_ok=True)
    
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self.available
    
    def broadcast_event(self, event_type: str, agent_id: str, tool: str, 
                       status: str, details: Optional[str] = None):
        """Broadcast event to real-time channel"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "agent": agent_id,
            "tool": tool,
            "status": status,
            "details": details or ""
        }
        
        if self.available:
            try:
                event_json = json.dumps(event)
                self.redis.publish(self.CHANNEL_TRAFFIC, event_json)
                self.redis.lpush(self.KEY_HISTORY, event_json)
                self.redis.ltrim(self.KEY_HISTORY, 0, 999)
            except Exception as e:
                print(f"⚠️  Redis broadcast error: {e}")
        else:
            # Fallback to JSON file
            self._save_to_file(event)
    
    def _save_to_file(self, event: Dict):
        """Fallback: Save event to JSON file"""
        try:
            if os.path.exists(self.traffic_log):
                with open(self.traffic_log, 'r') as f:
                    events = json.load(f)
            else:
                events = []
            
            events.insert(0, event)
            events = events[:100]
            
            with open(self.traffic_log, 'w') as f:
                json.dump(events, f, indent=2)
        except Exception as e:
            print(f"⚠️  File logging error: {e}")
    
    def broadcast_alert(self, severity: str, message: str, agent_id: Optional[str] = None):
        """Broadcast security alert"""
        if self.available:
            try:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "message": message,
                    "agent": agent_id or "system"
                }
                self.redis.publish(self.CHANNEL_ALERTS, json.dumps(alert))
            except:
                pass
        print(f"🚨 ALERT [{severity}]: {message}")
    
    def get_event_history(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent event history"""
        if self.available:
            try:
                raw_events = self.redis.lrange(self.KEY_HISTORY, 0, limit - 1)
                return [json.loads(event) for event in raw_events]
            except:
                pass
        
        # Fallback to file
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
        if self.available:
            try:
                key = f"{self.KEY_METRICS}:{metric_name}"
                self.redis.incrby(key, value)
                return
            except:
                pass
        
        # Fallback
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    metrics = json.load(f)
            else:
                metrics = {}
            
            metrics[metric_name] = metrics.get(metric_name, 0) + value
            
            with open(self.metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
        except:
            pass
    
    def get_metric(self, metric_name: str) -> int:
        """Get metric value"""
        if self.available:
            try:
                key = f"{self.KEY_METRICS}:{metric_name}"
                value = self.redis.get(key)
                return int(value) if value else 0
            except:
                pass
        
        # Fallback
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
        if self.available:
            try:
                keys = self.redis.keys(f"{self.KEY_METRICS}:*")
                metrics = {}
                for key in keys:
                    # Keys look like "tessera:metrics:<name>".
                    metric_name = key.split(":", 2)[2] if key.count(":") >= 2 else key
                    metrics[metric_name] = int(self.redis.get(key) or 0)
                return metrics
            except:
                pass
        
        # Fallback
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def revoke_token(self, jti: str, ttl: int = 3600):
        """Add token to distributed revocation list"""
        if self.available:
            try:
                self.redis.setex(f"{self.KEY_REVOKED}:{jti}", ttl, "1")
            except:
                pass
        print(f"   Token {jti} revoked")
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        if self.available:
            try:
                return self.redis.exists(f"{self.KEY_REVOKED}:{jti}") > 0
            except:
                pass
        return False
    
    def get_revoked_tokens(self) -> List[str]:
        """Get all currently revoked tokens"""
        if self.available:
            try:
                keys = self.redis.keys(f"{self.KEY_REVOKED}:*")
                return [key.split(":", 2)[2] for key in keys]
            except:
                pass
        return []
    
    def cache_token(self, jti: str, token_data: Dict, ttl: int):
        """Cache token for validation performance"""
        if self.available:
            try:
                key = f"{self.KEY_TOKEN_CACHE}:{jti}"
                self.redis.setex(key, ttl, json.dumps(token_data))
            except:
                pass
    
    def get_cached_token(self, jti: str) -> Optional[Dict]:
        """Retrieve cached token data"""
        if self.available:
            try:
                key = f"{self.KEY_TOKEN_CACHE}:{jti}"
                data = self.redis.get(key)
                return json.loads(data) if data else None
            except:
                pass
        return None
    
    def health_check(self) -> Dict:
        """Get Redis health status"""
        if self.available:
            try:
                info = self.redis.info()
                return {
                    "status": "healthy",
                    "mode": "redis",
                    "uptime_seconds": info.get('uptime_in_seconds'),
                    "connected_clients": info.get('connected_clients'),
                    "used_memory_human": info.get('used_memory_human')
                }
            except:
                return {"status": "error", "mode": "redis"}
        
        return {
            "status": "fallback",
            "mode": "local",
            "message": "Using JSON files (Redis not available)"
        }

if __name__ == "__main__":
    print("Testing Redis connection...")
    stream = TesseraRedisStream()
    
    if stream.is_available():
        print("✅ Redis mode active")
        stream.broadcast_event("TEST", "agent_01", "test_tool", "success")
        print(f"✅ Event logged to Redis")
        
        history = stream.get_event_history()
        print(f"✅ Retrieved {len(history)} events from Redis")
    else:
        print("⚠️  Running in fallback mode")

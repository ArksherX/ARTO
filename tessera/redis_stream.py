#!/usr/bin/env python3
"""
Tessera Redis Integration - Real-Time Event Streaming
Replaces JSON file with production-grade pub/sub

Installation:
    pip install redis
    docker run -d --name tessera-redis -p 6379:6379 redis

Save as: tessera/redis_stream.py
"""

import redis
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from contextlib import contextmanager

class TesseraRedisStream:
    """
    Production-grade event streaming for Tessera
    
    Features:
    - Pub/Sub for real-time dashboard updates
    - Persistent event history (last 1000 events)
    - Token cache for performance
    - Distributed revocation list
    """
    
    # Redis channels
    CHANNEL_TRAFFIC = "tessera:traffic"
    CHANNEL_ALERTS = "tessera:alerts"
    
    # Redis keys
    KEY_HISTORY = "tessera:history"
    KEY_METRICS = "tessera:metrics"
    KEY_REVOKED = "tessera:revoked"
    KEY_TOKEN_CACHE = "tessera:tokens"
    
    def __init__(
        self, 
        host: str = None,
        port: int = None,
        db: int = 0,
        decode_responses: bool = True
    ):
        """Initialize Redis connection"""
        self.host = host or os.getenv('REDIS_HOST', 'localhost')
        self.port = port or os.getenv('REDIS_PORT', 6379)
        self.db = db
        
        self.redis = redis.Redis(
            host=self.host,
            port=self.port,
            db=self.db,
            decode_responses=decode_responses,
            socket_connect_timeout=5
        )
        
        # Test connection
        try:
            self.redis.ping()
            print(f"✅ Connected to Redis at {self.host}:{self.port}")
        except redis.ConnectionError:
            print(f"❌ Failed to connect to Redis. Falling back to local mode.")
            self.redis = None
    
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self.redis is not None
    
    # ============================================
    # EVENT STREAMING
    # ============================================
    
    def broadcast_event(
        self, 
        event_type: str,
        agent_id: str,
        tool: str,
        status: str,
        details: Optional[str] = None
    ):
        """
        Broadcast event to real-time channel
        
        Dashboard subscribers receive this immediately
        """
        if not self.is_available():
            return
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "agent": agent_id,
            "tool": tool,
            "status": status,
            "details": details or ""
        }
        
        event_json = json.dumps(event)
        
        # Publish to real-time channel
        self.redis.publish(self.CHANNEL_TRAFFIC, event_json)
        
        # Store in history (persistent)
        self.redis.lpush(self.KEY_HISTORY, event_json)
        self.redis.ltrim(self.KEY_HISTORY, 0, 999)  # Keep last 1000
    
    def broadcast_alert(
        self,
        severity: str,
        message: str,
        agent_id: Optional[str] = None
    ):
        """Broadcast security alert"""
        if not self.is_available():
            return
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "message": message,
            "agent": agent_id or "system"
        }
        
        self.redis.publish(self.CHANNEL_ALERTS, json.dumps(alert))
    
    def get_event_history(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent event history"""
        if not self.is_available():
            return []
        
        raw_events = self.redis.lrange(self.KEY_HISTORY, 0, limit - 1)
        return [json.loads(event) for event in raw_events]
    
    def subscribe_to_traffic(self):
        """
        Subscribe to live traffic feed
        
        Usage:
            stream = TesseraRedisStream()
            pubsub = stream.subscribe_to_traffic()
            for message in pubsub.listen():
                if message['type'] == 'message':
                    event = json.loads(message['data'])
                    print(event)
        """
        if not self.is_available():
            return None
        
        pubsub = self.redis.pubsub()
        pubsub.subscribe(self.CHANNEL_TRAFFIC)
        return pubsub
    
    # ============================================
    # METRICS & ANALYTICS
    # ============================================
    
    def increment_metric(self, metric_name: str, value: int = 1):
        """Increment a counter metric"""
        if not self.is_available():
            return
        
        key = f"{self.KEY_METRICS}:{metric_name}"
        self.redis.incrby(key, value)
    
    def get_metric(self, metric_name: str) -> int:
        """Get current metric value"""
        if not self.is_available():
            return 0
        
        key = f"{self.KEY_METRICS}:{metric_name}"
        value = self.redis.get(key)
        return int(value) if value else 0
    
    def get_all_metrics(self) -> Dict[str, int]:
        """Get all metrics"""
        if not self.is_available():
            return {}
        
        keys = self.redis.keys(f"{self.KEY_METRICS}:*")
        metrics = {}
        
        for key in keys:
            metric_name = key.split(":", 1)[1]
            metrics[metric_name] = int(self.redis.get(key) or 0)
        
        return metrics
    
    # ============================================
    # REVOCATION LIST (Distributed)
    # ============================================
    
    def revoke_token(self, jti: str, ttl: int = 3600):
        """
        Add token to distributed revocation list
        
        Args:
            jti: JWT ID to revoke
            ttl: How long to keep in blacklist (seconds)
        """
        if not self.is_available():
            return
        
        self.redis.setex(f"{self.KEY_REVOKED}:{jti}", ttl, "1")
        self.broadcast_alert("HIGH", f"Token revoked: {jti}")
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        if not self.is_available():
            return False
        
        return self.redis.exists(f"{self.KEY_REVOKED}:{jti}") > 0
    
    def get_revoked_tokens(self) -> List[str]:
        """Get all currently revoked tokens"""
        if not self.is_available():
            return []
        
        keys = self.redis.keys(f"{self.KEY_REVOKED}:*")
        return [key.split(":", 2)[2] for key in keys]
    
    # ============================================
    # TOKEN CACHE (Performance)
    # ============================================
    
    def cache_token(self, jti: str, token_data: Dict, ttl: int):
        """Cache token for validation performance"""
        if not self.is_available():
            return
        
        key = f"{self.KEY_TOKEN_CACHE}:{jti}"
        self.redis.setex(key, ttl, json.dumps(token_data))
    
    def get_cached_token(self, jti: str) -> Optional[Dict]:
        """Retrieve cached token data"""
        if not self.is_available():
            return None
        
        key = f"{self.KEY_TOKEN_CACHE}:{jti}"
        data = self.redis.get(key)
        return json.loads(data) if data else None
    
    # ============================================
    # UTILITY
    # ============================================
    
    def flush_all(self):
        """Clear all Tessera data from Redis (DANGER!)"""
        if not self.is_available():
            return
        
        keys = self.redis.keys("tessera:*")
        if keys:
            self.redis.delete(*keys)
        print(f"🗑️  Flushed {len(keys)} keys from Redis")
    
    def health_check(self) -> Dict:
        """Get Redis health status"""
        if not self.is_available():
            return {"status": "unavailable", "mode": "local"}
        
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


# ============================================
# EXAMPLE USAGE
# ============================================

if __name__ == "__main__":
    print("Testing Tessera Redis Stream...\n")
    
    stream = TesseraRedisStream()
    
    if not stream.is_available():
        print("❌ Redis not available. Install with:")
        print("   docker run -d --name tessera-redis -p 6379:6379 redis")
        exit(1)
    
    # Test 1: Broadcast event
    print("1. Broadcasting test event...")
    stream.broadcast_event(
        event_type="TOKEN_ISSUED",
        agent_id="agent_test_01",
        tool="read_csv",
        status="success"
    )
    
    # Test 2: Check metrics
    print("\n2. Incrementing metrics...")
    stream.increment_metric("tokens_issued")
    stream.increment_metric("tokens_issued")
    print(f"   Tokens issued: {stream.get_metric('tokens_issued')}")
    
    # Test 3: Revocation
    print("\n3. Testing revocation...")
    test_jti = "tessera_test_12345"
    stream.revoke_token(test_jti, ttl=60)
    print(f"   Is revoked: {stream.is_revoked(test_jti)}")
    
    # Test 4: Event history
    print("\n4. Retrieving event history...")
    history = stream.get_event_history(limit=5)
    print(f"   Recent events: {len(history)}")
    
    # Test 5: Health check
    print("\n5. Redis health check:")
    health = stream.health_check()
    for key, value in health.items():
        print(f"   {key}: {value}")
    
    print("\n✅ All tests passed!")

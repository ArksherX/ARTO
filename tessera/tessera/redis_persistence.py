#!/usr/bin/env python3
"""
Redis-backed persistence for production deployments
Falls back to in-memory storage if Redis unavailable
"""

import redis
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import os

class RedisPersistence:
    """Redis-backed persistence with fallback to in-memory"""
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379')
        self.redis_client = None
        self._in_memory_store = {}
        
        try:
            self.redis_client = redis.from_url(
                self.redis_url, 
                decode_responses=True,
                socket_connect_timeout=2
            )
            self.redis_client.ping()
            print("✅ Redis connected")
        except Exception as e:
            print(f"⚠️  Redis unavailable, using in-memory storage: {e}")
            self.redis_client = None
    
    def log_audit(self, event: Dict[str, Any]):
        """Store audit event"""
        key = f"audit:{datetime.now().isoformat()}"
        value = json.dumps(event)
        
        if self.redis_client:
            try:
                self.redis_client.setex(key, 2592000, value)  # 30 days
            except:
                self._in_memory_store[key] = value
        else:
            self._in_memory_store[key] = value
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent audit logs"""
        if self.redis_client:
            try:
                keys = self.redis_client.keys("audit:*")
                keys.sort(reverse=True)
                return [
                    json.loads(self.redis_client.get(k)) 
                    for k in keys[:limit] 
                    if self.redis_client.get(k)
                ]
            except:
                pass
        
        # Fallback to in-memory
        keys = [k for k in self._in_memory_store.keys() if k.startswith('audit:')]
        keys.sort(reverse=True)
        return [json.loads(self._in_memory_store[k]) for k in keys[:limit]]
    
    def revoke_token(self, jti: str, ttl: int = 3600):
        """Add token to revocation list"""
        key = f"revoked:{jti}"
        
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, "1")
                return
            except:
                pass
        
        self._in_memory_store[key] = "1"
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        key = f"revoked:{jti}"
        
        if self.redis_client:
            try:
                return self.redis_client.exists(key) > 0
            except:
                pass
        
        return key in self._in_memory_store

# Singleton instance
_persistence = None

def get_persistence() -> RedisPersistence:
    """Get or create persistence instance"""
    global _persistence
    if _persistence is None:
        _persistence = RedisPersistence()
    return _persistence

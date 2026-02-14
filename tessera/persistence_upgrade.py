"""
Upgrade Tessera to use Redis for persistence

Adds:
- Audit log persistence
- Token cache
- Revocation list (distributed)
"""

redis_code = '''
# Add to requirements.txt
redis==5.0.1

# New file: tessera/redis_persistence.py
import redis
import json
from datetime import datetime
from typing import List, Optional

class RedisPersistence:
    """Redis-backed persistence for production"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis = redis.from_url(redis_url, decode_responses=True)
    
    def log_audit(self, event: dict):
        """Store audit event"""
        key = f"audit:{datetime.now().isoformat()}"
        self.redis.setex(key, 2592000, json.dumps(event))  # 30 days
    
    def get_audit_logs(self, limit: int = 100) -> List[dict]:
        """Retrieve recent audit logs"""
        keys = self.redis.keys("audit:*")
        keys.sort(reverse=True)
        return [json.loads(self.redis.get(k)) for k in keys[:limit]]
    
    def revoke_token(self, jti: str, ttl: int = 3600):
        """Add token to revocation list"""
        self.redis.setex(f"revoked:{jti}", ttl, "1")
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        return self.redis.exists(f"revoked:{jti}") > 0
'''

print(redis_code)
print("\n✅ Copy this code to implement Redis persistence")

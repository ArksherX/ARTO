#!/usr/bin/env python3
"""
Rate Limiting

Prevents abuse and DoS attacks
"""

from typing import Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import threading


class RateLimiter:
    """
    Token bucket rate limiter
    """
    
    def __init__(self, 
                 requests_per_minute: int = 100,
                 burst_size: int = 20):
        """
        Args:
            requests_per_minute: Sustained rate limit
            burst_size: Allow bursts up to this size
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.buckets: Dict[str, Dict] = defaultdict(self._new_bucket)
        self.lock = threading.Lock()
    
    def _new_bucket(self) -> Dict:
        """Create new token bucket"""
        return {
            'tokens': self.burst_size,
            'last_update': datetime.now()
        }
    
    def allow(self, key: str) -> bool:
        """
        Check if request is allowed
        
        Args:
            key: Identifier (agent_id, tenant_id, IP, etc.)
        
        Returns:
            True if allowed, False if rate limited
        """
        with self.lock:
            bucket = self.buckets[key]
            now = datetime.now()
            
            # Refill tokens based on time elapsed
            time_elapsed = (now - bucket['last_update']).total_seconds()
            tokens_to_add = time_elapsed * (self.requests_per_minute / 60.0)
            
            bucket['tokens'] = min(
                self.burst_size,
                bucket['tokens'] + tokens_to_add
            )
            bucket['last_update'] = now
            
            # Check if request can be allowed
            if bucket['tokens'] >= 1.0:
                bucket['tokens'] -= 1.0
                return True
            else:
                return False
    
    def get_stats(self, key: str) -> Dict:
        """Get rate limit stats for key"""
        bucket = self.buckets.get(key)
        if not bucket:
            return {
                'tokens_remaining': self.burst_size,
                'limit': self.requests_per_minute
            }
        
        return {
            'tokens_remaining': int(bucket['tokens']),
            'limit': self.requests_per_minute,
            'burst_size': self.burst_size
        }


class TenantRateLimiter:
    """
    Multi-tier rate limiting
    
    Different limits for different tenant tiers
    """
    
    def __init__(self):
        self.limiters = {
            'free': RateLimiter(requests_per_minute=10, burst_size=5),
            'startup': RateLimiter(requests_per_minute=100, burst_size=20),
            'professional': RateLimiter(requests_per_minute=1000, burst_size=100),
            'enterprise': RateLimiter(requests_per_minute=10000, burst_size=1000),
        }
    
    def allow(self, tenant_id: str, tier: str = 'free') -> bool:
        """Check if request allowed for tenant"""
        limiter = self.limiters.get(tier, self.limiters['free'])
        return limiter.allow(tenant_id)

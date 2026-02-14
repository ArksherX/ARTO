#!/usr/bin/env python3
"""
Cache Manager for Performance Optimization

Speeds up repeated operations with intelligent caching
"""

import redis
from typing import Optional, Dict, Any
import json
import hashlib
from functools import wraps
import time


class CacheManager:
    """
    Redis-based caching for VerityFlux
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """
        Initialize cache manager
        
        Args:
            redis_url: Redis connection URL
        """
        try:
            self.redis_client = redis.from_url(redis_url)
            self.redis_client.ping()
            self.enabled = True
            print("✅ Redis cache connected")
        except:
            self.redis_client = None
            self.enabled = False
            print("⚠️  Redis not available, caching disabled")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.enabled:
            return None
        
        try:
            value = self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except:
            return None
    
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (default: 5 minutes)
        """
        if not self.enabled:
            return False
        
        try:
            self.redis_client.setex(
                key,
                ttl,
                json.dumps(value)
            )
            return True
        except:
            return False
    
    def delete(self, key: str) -> bool:
        """Delete from cache"""
        if not self.enabled:
            return False
        
        try:
            self.redis_client.delete(key)
            return True
        except:
            return False
    
    def cache_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = json.dumps({
            'args': args,
            'kwargs': kwargs
        }, sort_keys=True)
        
        return hashlib.sha256(key_data.encode()).hexdigest()


def cached(ttl: int = 300):
    """
    Decorator to cache function results
    
    Args:
        ttl: Cache time-to-live in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Check if caching is enabled
            if not hasattr(self, 'cache') or not self.cache.enabled:
                return func(self, *args, **kwargs)
            
            # Generate cache key
            cache_key = f"{func.__name__}:{self.cache.cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = func(self, *args, **kwargs)
            
            # Store in cache
            self.cache.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator

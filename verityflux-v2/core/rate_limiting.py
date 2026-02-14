#!/usr/bin/env python3
"""
VerityFlux Enterprise - Rate Limiting Module
Protects API endpoints from abuse and ensures fair usage

Features:
- Token bucket algorithm for smooth rate limiting
- Per-user, per-IP, and per-endpoint limits
- Configurable limits via environment variables
- Redis-backed for distributed deployments
- In-memory fallback for air-gapped deployments
"""

import time
import logging
import hashlib
from typing import Dict, Optional, Tuple, Callable
from dataclasses import dataclass
from collections import defaultdict
import threading
import os

logger = logging.getLogger("verityflux.ratelimit")


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    # Default limits (requests per window)
    default_requests_per_minute: int = 60
    default_requests_per_hour: int = 1000
    
    # Endpoint-specific limits
    auth_requests_per_minute: int = 10
    scan_requests_per_hour: int = 50
    approval_requests_per_minute: int = 30
    
    # Burst allowance (multiplier)
    burst_multiplier: float = 1.5
    
    # Window sizes in seconds
    minute_window: int = 60
    hour_window: int = 3600
    
    # Redis configuration
    redis_url: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        """Load configuration from environment variables."""
        return cls(
            default_requests_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
            default_requests_per_hour=int(os.getenv("RATE_LIMIT_PER_HOUR", "1000")),
            auth_requests_per_minute=int(os.getenv("RATE_LIMIT_AUTH_PER_MINUTE", "10")),
            scan_requests_per_hour=int(os.getenv("RATE_LIMIT_SCAN_PER_HOUR", "50")),
            approval_requests_per_minute=int(os.getenv("RATE_LIMIT_APPROVAL_PER_MINUTE", "30")),
            burst_multiplier=float(os.getenv("RATE_LIMIT_BURST_MULTIPLIER", "1.5")),
            redis_url=os.getenv("REDIS_URL"),
        )


# =============================================================================
# TOKEN BUCKET ALGORITHM
# =============================================================================

@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: float  # Maximum tokens
    tokens: float  # Current tokens
    refill_rate: float  # Tokens per second
    last_refill: float  # Timestamp of last refill
    
    def consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Attempt to consume tokens.
        
        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()
        
        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, 0
        else:
            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.refill_rate
            return False, wait_time


# =============================================================================
# IN-MEMORY RATE LIMITER
# =============================================================================

class InMemoryRateLimiter:
    """
    In-memory rate limiter using token bucket algorithm.
    Suitable for single-instance deployments and air-gapped environments.
    """
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig.from_env()
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
    
    def _get_bucket_key(self, identifier: str, endpoint: str = None) -> str:
        """Generate a unique key for the rate limit bucket."""
        if endpoint:
            return f"{identifier}:{endpoint}"
        return identifier
    
    def _get_limits(self, endpoint: str = None) -> Tuple[int, int]:
        """Get rate limits for an endpoint (requests_per_minute, window_seconds)."""
        if endpoint:
            # Endpoint-specific limits
            if "/auth/" in endpoint or endpoint.endswith("/login"):
                return self.config.auth_requests_per_minute, self.config.minute_window
            elif "/scans" in endpoint:
                return self.config.scan_requests_per_hour, self.config.hour_window
            elif "/approvals" in endpoint:
                return self.config.approval_requests_per_minute, self.config.minute_window
        
        return self.config.default_requests_per_minute, self.config.minute_window
    
    def _get_or_create_bucket(self, key: str, limit: int, window: int) -> TokenBucket:
        """Get existing bucket or create new one."""
        with self._lock:
            if key not in self._buckets:
                capacity = limit * self.config.burst_multiplier
                refill_rate = limit / window
                self._buckets[key] = TokenBucket(
                    capacity=capacity,
                    tokens=capacity,
                    refill_rate=refill_rate,
                    last_refill=time.time(),
                )
            return self._buckets[key]
    
    def is_allowed(
        self,
        identifier: str,
        endpoint: str = None,
        tokens: int = 1
    ) -> Tuple[bool, Dict[str, any]]:
        """
        Check if request is allowed.
        
        Args:
            identifier: User ID, API key, or IP address
            endpoint: Optional endpoint path for endpoint-specific limits
            tokens: Number of tokens to consume
        
        Returns:
            (allowed, headers_dict)
        """
        # Periodic cleanup
        self._maybe_cleanup()
        
        # Get limits
        limit, window = self._get_limits(endpoint)
        
        # Get or create bucket
        key = self._get_bucket_key(identifier, endpoint)
        bucket = self._get_or_create_bucket(key, limit, window)
        
        # Try to consume
        allowed, retry_after = bucket.consume(tokens)
        
        # Build response headers
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, int(bucket.tokens))),
            "X-RateLimit-Reset": str(int(bucket.last_refill + window)),
        }
        
        if not allowed:
            headers["Retry-After"] = str(int(retry_after) + 1)
        
        return allowed, headers
    
    def _maybe_cleanup(self):
        """Clean up old buckets periodically."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._lock:
            self._last_cleanup = now
            # Remove buckets that haven't been used in a while
            stale_keys = [
                key for key, bucket in self._buckets.items()
                if now - bucket.last_refill > self._cleanup_interval * 2
            ]
            for key in stale_keys:
                del self._buckets[key]
            
            if stale_keys:
                logger.debug(f"Cleaned up {len(stale_keys)} stale rate limit buckets")


# =============================================================================
# REDIS RATE LIMITER
# =============================================================================

class RedisRateLimiter:
    """
    Redis-backed rate limiter for distributed deployments.
    Falls back to in-memory if Redis is unavailable.
    """
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig.from_env()
        self._redis = None
        self._fallback = InMemoryRateLimiter(config)
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis if available."""
        if not self.config.redis_url:
            logger.info("No Redis URL configured, using in-memory rate limiting")
            return
        
        try:
            import redis
            self._redis = redis.from_url(self.config.redis_url)
            self._redis.ping()
            logger.info("Connected to Redis for rate limiting")
        except Exception as e:
            logger.warning(f"Redis connection failed, falling back to in-memory: {e}")
            self._redis = None
    
    def is_allowed(
        self,
        identifier: str,
        endpoint: str = None,
        tokens: int = 1
    ) -> Tuple[bool, Dict[str, any]]:
        """Check if request is allowed."""
        if not self._redis:
            return self._fallback.is_allowed(identifier, endpoint, tokens)
        
        try:
            return self._redis_check(identifier, endpoint, tokens)
        except Exception as e:
            logger.warning(f"Redis rate limit check failed: {e}")
            return self._fallback.is_allowed(identifier, endpoint, tokens)
    
    def _redis_check(
        self,
        identifier: str,
        endpoint: str,
        tokens: int
    ) -> Tuple[bool, Dict[str, any]]:
        """Perform rate limit check using Redis."""
        # Get limits
        if endpoint and "/auth/" in endpoint:
            limit = self.config.auth_requests_per_minute
            window = self.config.minute_window
        elif endpoint and "/scans" in endpoint:
            limit = self.config.scan_requests_per_hour
            window = self.config.hour_window
        else:
            limit = self.config.default_requests_per_minute
            window = self.config.minute_window
        
        # Build key
        key = f"ratelimit:{identifier}"
        if endpoint:
            key += f":{hashlib.md5(endpoint.encode()).hexdigest()[:8]}"
        
        # Sliding window counter using Redis
        now = time.time()
        window_start = now - window
        
        pipe = self._redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count current entries
        pipe.zcard(key)
        
        # Add new entry
        pipe.zadd(key, {f"{now}:{tokens}": now})
        
        # Set expiry
        pipe.expire(key, window + 60)
        
        results = pipe.execute()
        current_count = results[1]
        
        allowed = current_count < limit
        remaining = max(0, limit - current_count - tokens)
        
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(now + window)),
        }
        
        if not allowed:
            # Remove the entry we just added
            self._redis.zrem(key, f"{now}:{tokens}")
            headers["Retry-After"] = str(window)
        
        return allowed, headers


# =============================================================================
# FASTAPI MIDDLEWARE
# =============================================================================

class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting.
    
    Usage:
        from fastapi import FastAPI
        from verityflux_enterprise.core.rate_limiting import RateLimitMiddleware
        
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware)
    """
    
    def __init__(self, app, config: RateLimitConfig = None):
        self.app = app
        self.config = config or RateLimitConfig.from_env()
        
        # Use Redis if available, otherwise in-memory
        if self.config.redis_url:
            self.limiter = RedisRateLimiter(self.config)
        else:
            self.limiter = InMemoryRateLimiter(self.config)
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Skip rate limiting for health checks
        path = scope.get("path", "")
        if path in ["/health", "/ready", "/metrics"]:
            await self.app(scope, receive, send)
            return
        
        # Get identifier (prefer API key, then user ID from JWT, then IP)
        identifier = self._get_identifier(scope)
        
        # Check rate limit
        allowed, headers = self.limiter.is_allowed(identifier, path)
        
        if not allowed:
            # Return 429 Too Many Requests
            response_headers = [
                (b"content-type", b"application/json"),
            ]
            for key, value in headers.items():
                response_headers.append((key.lower().encode(), str(value).encode()))
            
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": response_headers,
            })
            await send({
                "type": "http.response.body",
                "body": b'{"detail":"Rate limit exceeded. Please retry later."}',
            })
            return
        
        # Add rate limit headers to response
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing_headers = list(message.get("headers", []))
                for key, value in headers.items():
                    existing_headers.append((key.lower().encode(), str(value).encode()))
                message["headers"] = existing_headers
            await send(message)
        
        await self.app(scope, receive, send_with_headers)
    
    def _get_identifier(self, scope) -> str:
        """Extract identifier from request for rate limiting."""
        headers = dict(scope.get("headers", []))
        
        # Check for API key
        api_key = headers.get(b"x-api-key", b"").decode()
        if api_key:
            return f"apikey:{api_key[:16]}"
        
        # Check for Authorization header (JWT)
        auth = headers.get(b"authorization", b"").decode()
        if auth.startswith("Bearer "):
            # Hash the token to use as identifier
            token_hash = hashlib.md5(auth.encode()).hexdigest()[:16]
            return f"token:{token_hash}"
        
        # Fall back to IP address
        client = scope.get("client", ("unknown", 0))
        ip = client[0] if client else "unknown"
        
        # Check for forwarded headers
        forwarded = headers.get(b"x-forwarded-for", b"").decode()
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        
        return f"ip:{ip}"


# =============================================================================
# DECORATOR FOR FUNCTION-LEVEL RATE LIMITING
# =============================================================================

_function_limiter = InMemoryRateLimiter()


def rate_limit(
    requests_per_minute: int = 60,
    key_func: Callable = None,
):
    """
    Decorator for function-level rate limiting.
    
    Usage:
        @rate_limit(requests_per_minute=10)
        async def expensive_operation():
            ...
        
        @rate_limit(requests_per_minute=5, key_func=lambda user_id: f"user:{user_id}")
        async def per_user_operation(user_id: str):
            ...
    """
    def decorator(func: Callable):
        from functools import wraps
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                key = f"func:{func.__name__}"
            
            # Check rate limit
            allowed, _ = _function_limiter.is_allowed(key)
            
            if not allowed:
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded for {func.__name__}"
                )
            
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                key = f"func:{func.__name__}"
            
            allowed, _ = _function_limiter.is_allowed(key)
            
            if not allowed:
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded for {func.__name__}"
                )
            
            return func(*args, **kwargs)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "RateLimitConfig",
    "InMemoryRateLimiter",
    "RedisRateLimiter",
    "RateLimitMiddleware",
    "rate_limit",
]

#!/usr/bin/env python3
"""
Resilience & Error Recovery

Ensures VerityFlux never fully crashes
"""

from typing import Optional, Callable, Any
from functools import wraps
import logging
import traceback

logger = logging.getLogger(__name__)


class ComponentFailureError(Exception):
    """Raised when a component fails but system continues"""
    pass


def resilient(fallback_value: Any = None, 
              critical: bool = False):
    """
    Decorator for resilient operations
    
    Args:
        fallback_value: Value to return on error
        critical: If True, re-raise exception after logging
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log the error
                logger.error(
                    f"Component failure in {func.__name__}: {e}\n"
                    f"{traceback.format_exc()}"
                )
                
                # If critical, re-raise
                if critical:
                    raise ComponentFailureError(
                        f"{func.__name__} failed critically: {e}"
                    ) from e
                
                # Otherwise, return fallback and continue
                logger.warning(
                    f"Using fallback value for {func.__name__}: {fallback_value}"
                )
                return fallback_value
        
        return wrapper
    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern for external dependencies
    
    If component fails repeatedly, stop calling it temporarily
    """
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60):
        """
        Args:
            failure_threshold: Open circuit after this many failures
            recovery_timeout: Try again after this many seconds
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.last_failure_time = None
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker protection"""
        
        import time
        
        # If circuit is OPEN
        if self.state == "OPEN":
            # Check if recovery timeout elapsed
            if time.time() - self.last_failure_time > self.recovery_timeout:
                logger.info("Circuit breaker: Attempting recovery (HALF_OPEN)")
                self.state = "HALF_OPEN"
            else:
                raise ComponentFailureError(
                    f"Circuit breaker OPEN for {func.__name__}"
                )
        
        try:
            result = func(*args, **kwargs)
            
            # Success! Reset failures
            if self.state == "HALF_OPEN":
                logger.info("Circuit breaker: Recovery successful (CLOSED)")
                self.state = "CLOSED"
            
            self.failure_count = 0
            return result
            
        except Exception as e:
            import time
            
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            # Open circuit if threshold exceeded
            if self.failure_count >= self.failure_threshold:
                logger.error(
                    f"Circuit breaker: Threshold exceeded, opening circuit for {func.__name__}"
                )
                self.state = "OPEN"
            
            raise

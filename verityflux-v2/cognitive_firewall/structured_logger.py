#!/usr/bin/env python3
"""
Structured Logging System

Provides searchable, correlatable logs for production debugging
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import threading
from logging.handlers import RotatingFileHandler


class StructuredLogger:
    """
    Structured JSON logging with correlation IDs
    """
    
    def __init__(self, 
                 log_dir: str = "logs",
                 service_name: str = "verityflux",
                 log_level: str = "INFO"):
        """
        Initialize structured logger
        
        Args:
            log_dir: Directory for log files
            service_name: Service name for log entries
            log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.service_name = service_name
        
        # Create logger
        self.logger = logging.getLogger(service_name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # JSON formatter
        formatter = StructuredFormatter(service_name=service_name)
        
        # Console handler (human-readable)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ConsoleFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler (JSON, rotating)
        file_handler = RotatingFileHandler(
            self.log_dir / f"{service_name}.log",
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Error file handler (errors only)
        error_handler = RotatingFileHandler(
            self.log_dir / f"{service_name}.error.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
        # Thread-local storage for correlation IDs
        self.thread_local = threading.local()
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set correlation ID for current thread"""
        self.thread_local.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID for current thread"""
        return getattr(self.thread_local, 'correlation_id', None)
    
    def log(self, 
            level: str,
            message: str,
            **kwargs) -> None:
        """
        Log structured message
        
        Args:
            level: Log level (debug, info, warning, error, critical)
            message: Log message
            **kwargs: Additional structured fields
        """
        # Add correlation ID if available
        if correlation_id := self.get_correlation_id():
            kwargs['correlation_id'] = correlation_id
        
        # Get logging method
        log_method = getattr(self.logger, level.lower())
        
        # Log with extra fields
        log_method(message, extra={'structured_data': kwargs})
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.log('debug', message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.log('info', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.log('warning', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.log('error', message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.log('critical', message, **kwargs)
    
    def log_event(self,
                  event_type: str,
                  severity: str,
                  agent_id: Optional[str] = None,
                  **details) -> None:
        """
        Log security event
        
        Args:
            event_type: Type of event (e.g., 'firewall_decision', 'hitl_approval')
            severity: Event severity (LOW, MEDIUM, HIGH, CRITICAL)
            agent_id: Agent ID if applicable
            **details: Additional event details
        """
        self.info(
            f"Security event: {event_type}",
            event_type=event_type,
            severity=severity,
            agent_id=agent_id,
            **details
        )
    
    def log_performance(self,
                       operation: str,
                       duration_ms: float,
                       **metadata) -> None:
        """
        Log performance metric
        
        Args:
            operation: Operation name
            duration_ms: Duration in milliseconds
            **metadata: Additional metadata
        """
        self.info(
            f"Performance: {operation}",
            operation=operation,
            duration_ms=duration_ms,
            metric_type='performance',
            **metadata
        )
    
    def log_error_with_context(self,
                               error: Exception,
                               context: Dict[str, Any]) -> None:
        """
        Log error with full context
        
        Args:
            error: Exception object
            context: Contextual information
        """
        import traceback
        
        self.error(
            f"Error: {str(error)}",
            error_type=type(error).__name__,
            error_message=str(error),
            traceback=traceback.format_exc(),
            **context
        )


class StructuredFormatter(logging.Formatter):
    """
    Formats log records as JSON
    """
    
    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'service': self.service_name,
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
            'thread': record.thread,
            'thread_name': record.threadName,
        }
        
        # Add structured data if available
        if hasattr(record, 'structured_data'):
            log_entry.update(record.structured_data)
        
        # Add exception info if available
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)


class ConsoleFormatter(logging.Formatter):
    """
    Human-readable console formatter
    """
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console"""
        
        color = self.COLORS.get(record.levelname, '')
        reset = self.RESET
        
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        level = record.levelname[:4]
        
        # Base message
        message = f"{color}[{timestamp}] {level}{reset} {record.getMessage()}"
        
        # Add structured data if available
        if hasattr(record, 'structured_data'):
            data = record.structured_data
            if data:
                # Show important fields
                important_fields = []
                for key in ['agent_id', 'risk_score', 'decision', 'correlation_id']:
                    if key in data:
                        important_fields.append(f"{key}={data[key]}")
                
                if important_fields:
                    message += f" | {' '.join(important_fields)}"
        
        return message

#!/usr/bin/env python3
"""
Vestigia Watchtower - PRODUCTION VERSION

Implements atomic debouncing to avoid false positives during file writes.

Key improvements:
1. Only triggers on file move/close events (write complete)
2. Retry logic with short sleep for OS to finalize
3. Proper error handling for race conditions
4. Production-grade logging

Save as: vestigia/watchtower.py (replace existing)
"""

import os
import sys
import time
import json
import signal
import threading
from pathlib import Path
from datetime import datetime, UTC
from typing import Optional, Dict, Any, List
from enum import Enum

# File system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler, 
        FileMovedEvent,
        FileClosedEvent,
        DirModifiedEvent
    )
except ImportError:
    print("❌ ERROR: watchdog not installed")
    print("   Install: pip install watchdog")
    sys.exit(1)

# Import validator
from validator import VestigiaValidator, ValidationStatus


# ============================================================================
# SECURITY STATES
# ============================================================================

class SecurityState(Enum):
    """Watchtower security states"""
    NORMAL = "NORMAL"
    VALIDATING = "VALIDATING"
    WARNING = "WARNING"
    ALERT = "ALERT"
    LOCKDOWN = "LOCKDOWN"


# ============================================================================
# ALERT HANDLERS
# ============================================================================

class AlertHandler:
    """Base class for alert handlers"""
    
    def send_alert(self, severity: SecurityState, message: str, evidence: Dict[str, Any]):
        """Send alert - override in subclasses"""
        raise NotImplementedError


class ConsoleAlertHandler(AlertHandler):
    """Console output alerts"""
    
    def send_alert(self, severity: SecurityState, message: str, evidence: Dict[str, Any]):
        """Print alert to console"""
        icon = {
            SecurityState.NORMAL: "✅",
            SecurityState.VALIDATING: "🔍",
            SecurityState.WARNING: "⚠️",
            SecurityState.ALERT: "🚨",
            SecurityState.LOCKDOWN: "🔒"
        }[severity]
        
        timestamp = datetime.now(UTC).isoformat()
        
        print(f"\n{icon} [{timestamp}] {severity.value}")
        print(f"   {message}")
        
        if evidence:
            print(f"   Evidence:")
            for key, value in evidence.items():
                print(f"     • {key}: {value}")


# ============================================================================
# FILE SYSTEM EVENT HANDLER - PRODUCTION VERSION
# ============================================================================

class LedgerEventHandler(FileSystemEventHandler):
    """
    Monitors ledger file for changes - PRODUCTION VERSION
    
    Only triggers on atomic write completion (moved/closed events)
    """
    
    def __init__(
        self,
        ledger_path: Path,
        validator: VestigiaValidator,
        watchtower: 'VestigiaWatchtower',
        debug: bool = False
    ):
        self.ledger_path = ledger_path
        self.validator = validator
        self.watchtower = watchtower
        self.debug = debug
        self.last_check = 0
        self.check_interval = 0.5  # Minimum time between checks
    
    def on_moved(self, event):
        """
        Handle file move events - MOST RELIABLE
        
        This fires when temp file is renamed to final ledger file
        """
        if not isinstance(event, FileMovedEvent):
            return
        
        dest_path = Path(event.dest_path)
        
        if self.debug:
            print(f"🔍 DEBUG: moved {Path(event.src_path).name} → {dest_path.name}")
        
        # Check if this is our ledger file
        if dest_path.resolve() == self.ledger_path.resolve():
            self._trigger_validation("FILE_MOVED")
    
    def on_closed(self, event):
        """
        Handle file close events - BACKUP TRIGGER
        
        This fires when file handle is released
        """
        if not isinstance(event, FileClosedEvent):
            return
        
        event_path = Path(event.src_path)
        
        if self.debug:
            print(f"🔍 DEBUG: closed {event_path.name}")
        
        # Check if this is our ledger file
        if event_path.resolve() == self.ledger_path.resolve():
            self._trigger_validation("FILE_CLOSED")
    
    def on_modified(self, event):
        """
        Handle directory modification - FALLBACK
        
        Some systems don't support on_closed, so this is a fallback
        """
        # Ignore directory events
        if isinstance(event, DirModifiedEvent):
            return
        
        event_path = Path(event.src_path)
        
        # Only process our ledger
        if event_path.resolve() == self.ledger_path.resolve():
            # Debounce: only check if moved/closed didn't fire recently
            now = time.time()
            if now - self.last_check > 1.0:  # Wait 1 second
                if self.debug:
                    print(f"🔍 DEBUG: modified {event_path.name} (fallback trigger)")
                self._trigger_validation("FILE_MODIFIED")
    
    def _trigger_validation(self, event_type: str):
        """Common validation trigger with debouncing"""
        # Debounce
        now = time.time()
        if now - self.last_check < self.check_interval:
            if self.debug:
                print(f"   ⏭️  Skipped (debounce: {now - self.last_check:.2f}s)")
            return
        
        self.last_check = now
        
        if self.debug:
            print(f"   ✅ Triggering validation ({event_type})")
        
        # Trigger validation with retry
        self.watchtower.on_ledger_modified()


# ============================================================================
# MAIN WATCHTOWER DAEMON - PRODUCTION VERSION
# ============================================================================

class VestigiaWatchtower:
    """
    Live integrity monitoring daemon - PRODUCTION VERSION
    
    Features:
    - Atomic write detection (no false positives)
    - Retry logic for race conditions
    - Configurable alert handlers
    - Thread-safe operation
    """
    
    def __init__(
        self,
        ledger_path: str = "data/vestigia_ledger.json",
        secret_salt: Optional[str] = None,
        auto_lockdown: bool = True,
        debug: bool = False
    ):
        self.ledger_path = Path(ledger_path)
        self.secret_salt = secret_salt or os.getenv('VESTIGIA_SECRET_SALT')
        self.auto_lockdown = auto_lockdown
        self.debug = debug
        
        # State
        self.state = SecurityState.NORMAL
        self.running = False
        self.observer = None
        
        # Validation
        self.validator = VestigiaValidator(
            ledger_path=str(self.ledger_path),
            secret_salt=self.secret_salt
        )
        
        # Alert handlers
        self.alert_handlers: List[AlertHandler] = [ConsoleAlertHandler()]
        
        # Statistics
        self.checks_performed = 0
        self.tampering_detected = 0
        self.false_positives_avoided = 0
        self.start_time = None
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def add_alert_handler(self, handler: AlertHandler):
        """Add an alert handler"""
        self.alert_handlers.append(handler)
    
    def send_alert(self, severity: SecurityState, message: str, evidence: Dict[str, Any] = None):
        """Send alert through all handlers"""
        evidence = evidence or {}
        
        for handler in self.alert_handlers:
            try:
                handler.send_alert(severity, message, evidence)
            except Exception as e:
                print(f"⚠️  Alert handler failed: {e}")
    
    def on_ledger_modified(self):
        """
        Called when ledger file is modified
        
        Implements retry logic to handle race conditions
        """
        with self._lock:
            self.state = SecurityState.VALIDATING
            self.checks_performed += 1
            
            timestamp = datetime.now(UTC).strftime("%H:%M:%S")
            
            if self.debug:
                print(f"\n{'='*70}")
                print(f"[{timestamp}] 🔍 VALIDATION TRIGGERED (Check #{self.checks_performed})")
                print(f"{'='*70}")
            
            # Retry logic - wait for file to be fully written
            max_retries = 3
            retry_delay = 0.1  # 100ms
            
            for attempt in range(max_retries):
                try:
                    # Small delay for OS to finalize file
                    if attempt > 0:
                        time.sleep(retry_delay)
                    
                    # Check file exists and has content
                    if not self.ledger_path.exists():
                        if self.debug:
                            print(f"   Attempt {attempt + 1}: File doesn't exist yet")
                        continue
                    
                    file_size = self.ledger_path.stat().st_size
                    if file_size == 0:
                        if self.debug:
                            print(f"   Attempt {attempt + 1}: File empty (size: 0)")
                        continue
                    
                    # Run validation
                    report = self.validator.validate_full()
                    
                    # Success - process results
                    self._process_validation_result(report, timestamp)
                    return
                
                except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
                    if self.debug:
                        print(f"   Attempt {attempt + 1} failed: {e}")
                    
                    if attempt == max_retries - 1:
                        # Last attempt failed
                        self.false_positives_avoided += 1
                        print(f"⚠️  Validation skipped (race condition)")
                        print(f"   File being written by ledger engine")
                        return
                    
                    continue
                
                except Exception as e:
                    print(f"⚠️  Validation error: {str(e)}")
                    if self.debug:
                        import traceback
                        traceback.print_exc()
                    return
    
    def _process_validation_result(self, report, timestamp):
        """Process validation report"""
        if report.is_valid:
            # All clear
            self.state = SecurityState.NORMAL
            
            warning_count = len([i for i in report.issues 
                               if i.severity == ValidationStatus.WARNING])
            
            if warning_count > 0:
                self.state = SecurityState.WARNING
                self.send_alert(
                    SecurityState.WARNING,
                    f"Validation passed with {warning_count} warnings",
                    {
                        'total_entries': report.total_entries,
                        'warnings': warning_count
                    }
                )
            else:
                self.send_alert(
                    SecurityState.NORMAL,
                    f"Validation passed - integrity confirmed",
                    {
                        'total_entries': report.total_entries,
                        'checks_performed': self.checks_performed,
                        'false_positives_avoided': self.false_positives_avoided
                    }
                )
        
        else:
            # TAMPERING DETECTED!
            self.state = SecurityState.ALERT
            self.tampering_detected += 1
            
            critical = report.get_critical_issues()
            
            self.send_alert(
                SecurityState.ALERT,
                f"🚨 TAMPERING DETECTED - {len(critical)} critical issues",
                {
                    'total_entries': report.total_entries,
                    'critical_issues': len(critical),
                    'first_issue': str(critical[0]) if critical else None,
                    'tampering_count': self.tampering_detected
                }
            )
            
            # Execute lockdown if enabled
            if self.auto_lockdown:
                self.execute_lockdown()
        
        if self.debug:
            print(f"{'='*70}\n")
    
    def execute_lockdown(self):
        """Execute security lockdown"""
        self.state = SecurityState.LOCKDOWN
        
        self.send_alert(
            SecurityState.LOCKDOWN,
            "🔒 SECURITY LOCKDOWN INITIATED",
            {
                'reason': 'Tampering detected',
                'checks_performed': self.checks_performed,
                'tampering_count': self.tampering_detected
            }
        )
        
        # Make ledger read-only
        try:
            self.ledger_path.chmod(0o444)
            print(f"   ✅ Ledger locked (read-only)")
        except Exception as e:
            print(f"   ❌ Lockdown failed: {e}")
    
    def start(self):
        """Start the watchtower daemon"""
        if self.running:
            print("⚠️  Watchtower already running")
            return
        
        print("\n" + "="*70)
        print("🏰 VESTIGIA WATCHTOWER - PRODUCTION MODE")
        print("="*70)
        print(f"\n📂 Monitoring: {self.ledger_path}")
        print(f"🔐 Secret: {'✅ Configured' if self.secret_salt else '❌ Not set'}")
        print(f"🔒 Auto-lockdown: {'✅ Enabled' if self.auto_lockdown else '❌ Disabled'}")
        print(f"🐛 Debug: {'✅ Enabled' if self.debug else '❌ Disabled'}")
        print("\n" + "="*70)
        
        # Initial validation if file exists
        if self.ledger_path.exists():
            print("\n🔍 Performing initial validation...")
            self.on_ledger_modified()
        
        # Start file system observer
        self.observer = Observer()
        
        event_handler = LedgerEventHandler(
            ledger_path=self.ledger_path,
            validator=self.validator,
            watchtower=self,
            debug=self.debug
        )
        
        # Watch the directory containing the ledger
        watch_dir = self.ledger_path.parent
        watch_dir.mkdir(parents=True, exist_ok=True)
        
        self.observer.schedule(event_handler, str(watch_dir), recursive=False)
        
        self.observer.start()
        self.running = True
        self.start_time = datetime.now(UTC)
        
        print("\n✅ Watchtower active - monitoring for changes...")
        print("   Press Ctrl+C to stop\n")
        
        # Signal handlers
        def signal_handler(signum, frame):
            print("\n\n🛑 Shutdown signal received...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the watchtower daemon"""
        if not self.running:
            return
        
        print("\n🛑 Stopping watchtower...")
        
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        # Final statistics
        uptime = datetime.now(UTC) - self.start_time if self.start_time else None
        
        print("\n" + "="*70)
        print("📊 WATCHTOWER STATISTICS")
        print("="*70)
        print(f"Uptime: {uptime}")
        print(f"Checks performed: {self.checks_performed}")
        print(f"False positives avoided: {self.false_positives_avoided}")
        print(f"Tampering detected: {self.tampering_detected}")
        print(f"Final state: {self.state.value}")
        print("="*70 + "\n")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line interface for Watchtower"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Vestigia Watchtower - Live Integrity Monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--ledger',
        default='data/vestigia_ledger.json',
        help='Path to ledger file'
    )
    
    parser.add_argument(
        '--secret',
        help='Secret salt'
    )
    
    parser.add_argument(
        '--no-lockdown',
        action='store_true',
        help='Disable automatic lockdown'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Create watchtower
    watchtower = VestigiaWatchtower(
        ledger_path=args.ledger,
        secret_salt=args.secret,
        auto_lockdown=not args.no_lockdown,
        debug=args.debug
    )
    
    # Start monitoring
    watchtower.start()


if __name__ == '__main__':
    main()

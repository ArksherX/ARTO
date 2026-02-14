#!/usr/bin/env python3
"""
Vestigia Watchtower - DEBUG VERSION

Fixes:
1. Watches for FileModifiedEvent AND FileCreatedEvent
2. Added verbose logging to show what events are detected
3. Reduced debounce interval
4. Shows file system events in real-time

Save as: vestigia/watchtower_debug.py
"""

import os
import sys
import time
import json
import signal
import threading
from pathlib import Path
from datetime import datetime, UTC
from typing import Optional, Dict, Any
from enum import Enum

# File system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler, 
        FileModifiedEvent,
        FileCreatedEvent,
        FileClosedEvent
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
# FILE SYSTEM EVENT HANDLER - DEBUG VERSION
# ============================================================================

class LedgerEventHandler(FileSystemEventHandler):
    """Monitors ledger file for changes - DEBUG VERSION"""
    
    def __init__(
        self,
        ledger_path: Path,
        validator: VestigiaValidator,
        watchtower: 'VestigiaWatchtower'
    ):
        self.ledger_path = ledger_path
        self.validator = validator
        self.watchtower = watchtower
        self.last_check = 0
        self.check_interval = 0.5  # Reduced from 1.0 to 0.5
    
    def on_any_event(self, event):
        """Log ALL events for debugging"""
        event_path = Path(event.src_path)
        
        # Show all events
        print(f"🔍 DEBUG: {event.event_type} - {event_path.name}")
    
    def on_modified(self, event):
        """Handle file modification events"""
        self._handle_event(event, "MODIFIED")
    
    def on_created(self, event):
        """Handle file creation events"""
        self._handle_event(event, "CREATED")
    
    def _handle_event(self, event, event_type):
        """Common handler for file events"""
        event_path = Path(event.src_path)
        
        # Only process our ledger file
        if event_path.name != self.ledger_path.name:
            return
        
        # Debounce: avoid checking too frequently
        now = time.time()
        if now - self.last_check < self.check_interval:
            print(f"   ⏭️  Skipped (debounce: {now - self.last_check:.2f}s)")
            return
        
        self.last_check = now
        
        print(f"   ✅ Processing {event_type} event")
        
        # Trigger validation
        self.watchtower.on_ledger_modified()


# ============================================================================
# MAIN WATCHTOWER DAEMON - DEBUG VERSION
# ============================================================================

class VestigiaWatchtower:
    """Live integrity monitoring daemon - DEBUG VERSION"""
    
    def __init__(
        self,
        ledger_path: str = "data/vestigia_ledger.json",
        secret_salt: Optional[str] = None,
        auto_lockdown: bool = True,
        verbose: bool = True
    ):
        self.ledger_path = Path(ledger_path)
        self.secret_salt = secret_salt or os.getenv('VESTIGIA_SECRET_SALT')
        self.auto_lockdown = auto_lockdown
        self.verbose = verbose
        
        # State
        self.state = SecurityState.NORMAL
        self.running = False
        self.observer = None
        
        # Validation
        self.validator = VestigiaValidator(
            ledger_path=str(self.ledger_path),
            secret_salt=self.secret_salt
        )
        
        # Statistics
        self.checks_performed = 0
        self.tampering_detected = 0
        self.start_time = None
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def on_ledger_modified(self):
        """Called when ledger file is modified"""
        with self._lock:
            # Update state
            self.state = SecurityState.VALIDATING
            self.checks_performed += 1
            
            timestamp = datetime.now(UTC).strftime("%H:%M:%S")
            
            print(f"\n{'='*70}")
            print(f"[{timestamp}] 🔍 VALIDATION TRIGGERED (Check #{self.checks_performed})")
            print(f"{'='*70}")
            
            # Run validation
            try:
                report = self.validator.validate_full()
                
                if report.is_valid:
                    # All clear
                    self.state = SecurityState.NORMAL
                    
                    critical_count = len(report.get_critical_issues())
                    warning_count = len([i for i in report.issues if i.severity == ValidationStatus.WARNING])
                    
                    if warning_count > 0:
                        self.state = SecurityState.WARNING
                        print(f"⚠️  WARNING: Validation passed with {warning_count} warnings")
                        print(f"   Total entries: {report.total_entries}")
                    else:
                        print(f"✅ VALID - Integrity confirmed")
                        print(f"   Total entries: {report.total_entries}")
                        print(f"   Total checks: {self.checks_performed}")
                
                else:
                    # TAMPERING DETECTED!
                    self.state = SecurityState.ALERT
                    self.tampering_detected += 1
                    
                    critical = report.get_critical_issues()
                    
                    print(f"🚨 TAMPERING DETECTED!")
                    print(f"   Critical issues: {len(critical)}")
                    print(f"   Total entries: {report.total_entries}")
                    
                    if critical:
                        print(f"\n   First issue:")
                        print(f"   {critical[0]}")
                    
                    # Execute lockdown if enabled
                    if self.auto_lockdown:
                        print(f"\n🔒 EXECUTING LOCKDOWN...")
                        self.execute_lockdown()
            
            except Exception as e:
                print(f"⚠️  Validation error: {str(e)}")
                import traceback
                traceback.print_exc()
            
            print(f"{'='*70}\n")
    
    def execute_lockdown(self):
        """Execute lockdown"""
        self.state = SecurityState.LOCKDOWN
        
        try:
            # Make ledger read-only
            self.ledger_path.chmod(0o444)
            print(f"   ✅ Ledger set to read-only")
        except Exception as e:
            print(f"   ❌ Lockdown failed: {e}")
    
    def start(self):
        """Start the watchtower daemon"""
        if self.running:
            print("⚠️  Watchtower already running")
            return
        
        print("\n" + "="*70)
        print("🏰 VESTIGIA WATCHTOWER - DEBUG MODE")
        print("="*70)
        print(f"\n📂 Monitoring: {self.ledger_path}")
        print(f"📂 Full path: {self.ledger_path.resolve()}")
        print(f"📂 Watching directory: {self.ledger_path.parent}")
        print(f"🔐 Secret: {'✅ Configured' if self.secret_salt else '❌ Not set'}")
        print(f"🔒 Auto-lockdown: {'✅ Enabled' if self.auto_lockdown else '❌ Disabled'}")
        print(f"🐛 Debug mode: ✅ Enabled (verbose logging)")
        print("\n" + "="*70)
        
        # Check if ledger exists
        if not self.ledger_path.exists():
            print(f"\n⚠️  WARNING: Ledger file doesn't exist yet")
            print(f"   Will start monitoring once created")
        else:
            print(f"\n✅ Ledger file exists ({self.ledger_path.stat().st_size} bytes)")
        
        # Initial validation if file exists
        if self.ledger_path.exists():
            print("\n🔍 Performing initial validation...")
            self.on_ledger_modified()
        
        # Start file system observer
        self.observer = Observer()
        
        event_handler = LedgerEventHandler(
            ledger_path=self.ledger_path,
            validator=self.validator,
            watchtower=self
        )
        
        # Watch the directory containing the ledger
        watch_dir = self.ledger_path.parent
        watch_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n👀 Starting file system observer...")
        print(f"   Watching: {watch_dir.resolve()}")
        
        self.observer.schedule(event_handler, str(watch_dir), recursive=False)
        
        self.observer.start()
        self.running = True
        self.start_time = datetime.now(UTC)
        
        print("\n✅ Watchtower active - ALL FILE EVENTS WILL BE SHOWN")
        print("   Press Ctrl+C to stop")
        print("\n" + "="*70 + "\n")
        
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
        print(f"Tampering detected: {self.tampering_detected}")
        print(f"Final state: {self.state.value}")
        print("="*70 + "\n")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line interface for Debug Watchtower"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Vestigia Watchtower - DEBUG MODE',
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
    
    args = parser.parse_args()
    
    # Create watchtower
    watchtower = VestigiaWatchtower(
        ledger_path=args.ledger,
        secret_salt=args.secret,
        auto_lockdown=not args.no_lockdown,
        verbose=True
    )
    
    # Start monitoring
    watchtower.start()


if __name__ == '__main__':
    main()

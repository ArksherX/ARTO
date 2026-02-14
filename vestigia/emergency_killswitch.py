#!/usr/bin/env python3
"""
Emergency Kill-Switch - Active Defense System

Monitors Vestigia for tampering and can kill orchestrator processes.
Implements the "emergency stop" button for production safety.

Key Features:
- Monitors Vestigia for HISTORY_REWRITE_DETECTED
- Can send SIGKILL to orchestrator PIDs
- Logs all kill events
- Provides human override capability

Save as: vestigia/emergency_killswitch.py
"""

import os
import signal
import time
import sys
import psutil
from pathlib import Path
from typing import List, Optional, Set
from datetime import datetime, UTC
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent))

from event_hooks import VestigiaEventHook, IntentType, EventStatus
from validator import VestigiaValidator


class KillSwitchMode(Enum):
    """Operating modes for kill switch"""
    MONITOR_ONLY = "MONITOR_ONLY"      # Just log, don't kill
    AUTO_KILL = "AUTO_KILL"            # Kill on detection
    HUMAN_CONFIRM = "HUMAN_CONFIRM"    # Ask before killing


class EmergencyKillSwitch:
    """
    Emergency kill switch for orchestrator processes
    
    Monitors Vestigia for tampering and can terminate processes.
    The "circuit breaker" for the ASI system.
    """
    
    def __init__(
        self,
        ledger_path: str = 'data/vestigia_ledger.json',
        mode: KillSwitchMode = KillSwitchMode.AUTO_KILL,
        check_interval: int = 2,
        agent_id: str = "emergency_killswitch"
    ):
        self.ledger_path = ledger_path
        self.mode = mode
        self.check_interval = check_interval
        self.agent_id = agent_id
        
        self.hook = VestigiaEventHook(agent_id=agent_id, enable_external_anchor=False)
        self.validator = VestigiaValidator(ledger_path)
        
        # Track monitored processes
        self.monitored_pids: Set[int] = set()
        self.killed_pids: Set[int] = set()
        
        # Statistics
        self.checks_performed = 0
        self.kills_executed = 0
        self.tampering_detected = 0
        
        self._log_initialization()
    
    def _log_initialization(self):
        """Log kill switch initialization"""
        self.hook.log_security_event(
            "Emergency Kill-Switch initialized",
            EventStatus.WARNING,
            threat_indicators={
                'mode': self.mode.value,
                'check_interval': self.check_interval,
                'monitored_ledger': self.ledger_path
            }
        )
        
        print("\n" + "="*70)
        print("🚨 EMERGENCY KILL-SWITCH INITIALIZED")
        print("="*70)
        print(f"   Mode: {self.mode.value}")
        print(f"   Check interval: {self.check_interval}s")
        print(f"   Ledger: {self.ledger_path}")
        print("="*70 + "\n")
    
    def register_process(self, pid: int, name: str = "orchestrator"):
        """
        Register a process to monitor
        
        Args:
            pid: Process ID to monitor
            name: Human-readable process name
        """
        self.monitored_pids.add(pid)
        
        print(f"✅ Registered process: {name} (PID {pid})")
        
        self.hook.log_intent(
            f"Process registered for monitoring: {name}",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={'pid': pid, 'name': name}
        )
    
    def find_orchestrator_processes(self) -> List[psutil.Process]:
        """
        Find running orchestrator processes
        
        Looks for Python processes running orchestrator scripts.
        """
        orchestrators = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and any('orchestrator' in arg.lower() for arg in cmdline):
                    orchestrators.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return orchestrators
    
    def auto_register_orchestrators(self):
        """Automatically find and register orchestrator processes"""
        orchestrators = self.find_orchestrator_processes()
        
        if orchestrators:
            print(f"\n🔍 Found {len(orchestrators)} orchestrator process(es):")
            for proc in orchestrators:
                try:
                    pid = proc.pid
                    cmdline = ' '.join(proc.cmdline())
                    self.register_process(pid, f"orchestrator-{pid}")
                    print(f"   • PID {pid}: {cmdline[:60]}...")
                except:
                    pass
        else:
            print("\n⚠️  No orchestrator processes found")
    
    def check_integrity(self) -> bool:
        """
        Check ledger integrity
        
        Returns True if intact, False if tampered
        """
        self.checks_performed += 1
        
        try:
            report = self.validator.validate_full()
            
            if report.is_valid:
                return True
            else:
                # Check for critical tampering
                critical = report.get_critical_issues()
                
                if critical:
                    self.tampering_detected += 1
                    
                    # Log tampering
                    self.hook.log_security_event(
                        "CRITICAL: Ledger tampering detected",
                        EventStatus.CRITICAL,
                        threat_indicators={
                            'critical_issues': len(critical),
                            'total_issues': len(report.issues),
                            'check_number': self.checks_performed
                        }
                    )
                    
                    return False
                
                return True
        
        except Exception as e:
            print(f"⚠️  Integrity check failed: {e}")
            return True  # Fail-open to avoid false positives
    
    def kill_process(self, pid: int, force: bool = True) -> bool:
        """
        Kill a process
        
        Args:
            pid: Process ID to kill
            force: Use SIGKILL (True) or SIGTERM (False)
        
        Returns True if killed successfully
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_cmdline = ' '.join(proc.cmdline())
            
            print(f"\n🔪 KILLING PROCESS")
            print(f"   PID: {pid}")
            print(f"   Name: {proc_name}")
            print(f"   Command: {proc_cmdline[:60]}...")
            
            # Log kill attempt
            self.hook.log_security_event(
                f"Emergency kill executed on PID {pid}",
                EventStatus.CRITICAL,
                threat_indicators={
                    'pid': pid,
                    'process_name': proc_name,
                    'command': proc_cmdline[:200],
                    'signal': 'SIGKILL' if force else 'SIGTERM'
                }
            )
            
            # Execute kill
            if force:
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGTERM)
            
            # Wait to confirm
            time.sleep(0.5)
            
            if not psutil.pid_exists(pid):
                print(f"   ✅ Process {pid} terminated")
                self.killed_pids.add(pid)
                self.kills_executed += 1
                return True
            else:
                print(f"   ⚠️  Process {pid} still running")
                return False
        
        except psutil.NoSuchProcess:
            print(f"   ℹ️  Process {pid} already terminated")
            return True
        except Exception as e:
            print(f"   ❌ Kill failed: {e}")
            return False
    
    def handle_tampering_detection(self) -> bool:
        """
        Handle detected tampering based on mode
        
        Returns True if processes were killed
        """
        print("\n" + "="*70)
        print("🚨 TAMPERING DETECTED - EMERGENCY PROTOCOL ACTIVATED")
        print("="*70)
        print(f"   Mode: {self.mode.value}")
        print(f"   Monitored processes: {len(self.monitored_pids)}")
        print("="*70)
        
        if self.mode == KillSwitchMode.MONITOR_ONLY:
            print("\n⚠️  MONITOR ONLY mode - logging but not killing")
            return False
        
        elif self.mode == KillSwitchMode.HUMAN_CONFIRM:
            print("\n🤚 Human confirmation required")
            response = input("➡️  Kill all monitored processes? (yes/no): ").lower().strip()
            
            if response not in ['yes', 'y']:
                print("   ℹ️  Kill aborted by human")
                
                self.hook.log_intent(
                    "Emergency kill aborted by human",
                    IntentType.PERMISSION_CHECK,
                    EventStatus.WARNING,
                    metadata={'tampering_count': self.tampering_detected}
                )
                
                return False
        
        # Execute kills (AUTO_KILL or confirmed HUMAN_CONFIRM)
        print(f"\n⚡ Killing {len(self.monitored_pids)} process(es)...")
        
        killed_count = 0
        for pid in list(self.monitored_pids):
            if pid not in self.killed_pids:
                if self.kill_process(pid):
                    killed_count += 1
        
        if killed_count > 0:
            print(f"\n✅ Emergency kill complete: {killed_count} process(es) terminated")
        else:
            print(f"\n⚠️  No processes killed")
        
        return killed_count > 0
    
    def run_monitor(self, duration: Optional[int] = None):
        """
        Run continuous monitoring
        
        Args:
            duration: Run for N seconds (None = forever)
        """
        print(f"\n🔍 Starting continuous monitoring...")
        print(f"   Check interval: {self.check_interval}s")
        print(f"   Duration: {'Forever' if duration is None else f'{duration}s'}")
        print("\n✅ Monitoring active - Press Ctrl+C to stop\n")
        
        start_time = time.time()
        
        try:
            while True:
                # Check if duration exceeded
                if duration and (time.time() - start_time) > duration:
                    print("\n⏱️  Monitoring duration reached")
                    break
                
                # Perform integrity check
                is_intact = self.check_integrity()
                
                timestamp = datetime.now(UTC).strftime("%H:%M:%S")
                
                if is_intact:
                    print(f"[{timestamp}] ✅ Check #{self.checks_performed}: Integrity OK", end='\r')
                else:
                    print(f"\n[{timestamp}] 🚨 Check #{self.checks_performed}: TAMPERING DETECTED")
                    
                    # Handle tampering
                    self.handle_tampering_detection()
                
                time.sleep(self.check_interval)
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Monitoring stopped by user")
        
        finally:
            self._print_statistics()
    
    def _print_statistics(self):
        """Print monitoring statistics"""
        print("\n" + "="*70)
        print("📊 KILL-SWITCH STATISTICS")
        print("="*70)
        print(f"   Checks performed: {self.checks_performed}")
        print(f"   Tampering detected: {self.tampering_detected}")
        print(f"   Kills executed: {self.kills_executed}")
        print(f"   Monitored PIDs: {len(self.monitored_pids)}")
        print(f"   Killed PIDs: {len(self.killed_pids)}")
        print("="*70 + "\n")


def demo_killswitch():
    """Demonstrate kill switch functionality"""
    print("\n" + "="*70)
    print("🚨 EMERGENCY KILL-SWITCH - DEMO")
    print("="*70)
    
    print("\nScenario: Monitor for tampering and kill orchestrator")
    print("="*70)
    
    # Create kill switch
    killswitch = EmergencyKillSwitch(
        mode=KillSwitchMode.HUMAN_CONFIRM,
        check_interval=2
    )
    
    # Auto-discover orchestrators
    killswitch.auto_register_orchestrators()
    
    # If no orchestrators found, simulate
    if not killswitch.monitored_pids:
        print("\n💡 No orchestrators running - simulating with dummy PID")
        dummy_pid = os.getpid()  # Use this process as demo
        killswitch.register_process(dummy_pid, "demo_orchestrator")
    
    # Run monitoring for 30 seconds
    print("\n🔍 Monitoring for 30 seconds...")
    print("   Trigger tampering (rogue_agent.py) in another terminal to test")
    print("   Or press Ctrl+C to stop\n")
    
    killswitch.run_monitor(duration=30)


if __name__ == '__main__':
    try:
        demo_killswitch()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

#!/usr/bin/env python3
"""
Vestigia Forensic Reconstructor

Analyzes tampered ledgers and recovers deleted evidence
by comparing against backups and examining hash chain breaks.

Save as: vestigia/forensics.py
"""

import json
import sys
from pathlib import Path
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ForensicFinding:
    """Represents a forensic discovery"""
    severity: str  # CRITICAL, WARNING, INFO
    category: str  # DELETION, MODIFICATION, CORRUPTION
    location: str  # Entry index or description
    description: str
    evidence: Dict[str, Any]
    timestamp: str


class ForensicReconstructor:
    """Forensic analysis tool for tampered Vestigia ledgers"""
    
    def __init__(self, live_ledger_path: str, backup_ledger_path: Optional[str] = None):
        self.live_path = Path(live_ledger_path)
        self.backup_path = Path(backup_ledger_path) if backup_ledger_path else None
        self.findings: List[ForensicFinding] = []
        
    def analyze(self) -> Dict[str, Any]:
        """Run complete forensic analysis"""
        
        print("\n" + "="*70)
        print("🕵️  VESTIGIA FORENSIC RECONSTRUCTOR")
        print("="*70)
        print(f"\n📂 Live Ledger: {self.live_path}")
        
        if self.backup_path:
            print(f"📂 Backup Ledger: {self.backup_path}")
        else:
            print("⚠️  No backup provided - limited analysis")
        
        print("="*70 + "\n")
        
        # Load data
        live_data = self._load_ledger(self.live_path)
        backup_data = self._load_ledger(self.backup_path) if self.backup_path else None
        
        if live_data is None:
            print("❌ Could not load live ledger - analysis aborted")
            return {'success': False, 'findings': []}
        
        # Run analysis phases
        self._check_truncation(live_data, backup_data)
        self._check_modifications(live_data, backup_data)
        self._check_hash_chain(live_data)
        self._identify_attack_patterns(live_data, backup_data)
        
        # Generate report
        return self._generate_report(live_data, backup_data)
    
    def _load_ledger(self, path: Optional[Path]) -> Optional[List[Dict]]:
        """Safely load a ledger file"""
        if not path or not path.exists():
            return None
        
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️  Error loading {path}: {e}")
            return None
    
    def _check_truncation(self, live_data: List[Dict], backup_data: Optional[List[Dict]]):
        """Detect if entries were deleted from the end"""
        print("ANALYSIS 1: Checking for Truncation")
        print("-" * 70)
        
        if not backup_data:
            print("⚠️  Skipped (no backup)")
            print()
            return
        
        live_count = len(live_data)
        backup_count = len(backup_data)
        
        if live_count < backup_count:
            deleted_count = backup_count - live_count
            
            finding = ForensicFinding(
                severity="CRITICAL",
                category="DELETION",
                location=f"Entries {live_count}-{backup_count-1}",
                description=f"{deleted_count} entries deleted from end of ledger",
                evidence={
                    'live_entries': live_count,
                    'backup_entries': backup_count,
                    'deleted_count': deleted_count
                },
                timestamp=datetime.now(UTC).isoformat()
            )
            self.findings.append(finding)
            
            print(f"🚨 TRUNCATION DETECTED: {deleted_count} entries deleted\n")
            print("📜 RECOVERED DELETED ENTRIES:")
            
            for i, entry in enumerate(backup_data[live_count:], start=live_count):
                print(f"\n   Entry {i}:")
                print(f"   ├─ Timestamp: {entry.get('timestamp', 'N/A')}")
                print(f"   ├─ Actor: {entry.get('actor_id', 'N/A')}")
                print(f"   ├─ Action: {entry.get('action_type', 'N/A')}")
                print(f"   ├─ Status: {entry.get('status', 'N/A')}")
                
                evidence = entry.get('evidence', {})
                if isinstance(evidence, dict):
                    summary = evidence.get('summary', str(evidence)[:50])
                else:
                    summary = str(evidence)[:50]
                print(f"   └─ Evidence: {summary}")
        else:
            print("✅ No truncation detected")
        
        print()
    
    def _check_modifications(self, live_data: List[Dict], backup_data: Optional[List[Dict]]):
        """Detect modified entries by comparing with backup"""
        print("ANALYSIS 2: Checking for Modifications")
        print("-" * 70)
        
        if not backup_data:
            print("⚠️  Skipped (no backup)")
            print()
            return
        
        modifications = 0
        min_len = min(len(live_data), len(backup_data))
        
        for i in range(min_len):
            live_entry = live_data[i]
            backup_entry = backup_data[i]
            
            # Compare evidence fields
            live_evidence = live_entry.get('evidence', {})
            backup_evidence = backup_entry.get('evidence', {})
            
            if live_evidence != backup_evidence:
                modifications += 1
                
                finding = ForensicFinding(
                    severity="CRITICAL",
                    category="MODIFICATION",
                    location=f"Entry {i}",
                    description="Evidence field was modified",
                    evidence={
                        'original': backup_evidence,
                        'modified': live_evidence,
                        'actor_id': live_entry.get('actor_id'),
                        'action_type': live_entry.get('action_type')
                    },
                    timestamp=datetime.now(UTC).isoformat()
                )
                self.findings.append(finding)
                
                print(f"\n🚨 MODIFICATION DETECTED: Entry {i}")
                print(f"   Actor: {live_entry.get('actor_id', 'N/A')}")
                print(f"   Action: {live_entry.get('action_type', 'N/A')}")
                print(f"   Original: {str(backup_evidence)[:60]}...")
                print(f"   Modified: {str(live_evidence)[:60]}...")
        
        if modifications == 0:
            print("✅ No modifications detected")
        else:
            print(f"\n🚨 Total modifications: {modifications}")
        
        print()
    
    def _check_hash_chain(self, live_data: List[Dict]):
        """Verify hash chain integrity"""
        print("ANALYSIS 3: Checking Hash Chain Integrity")
        print("-" * 70)
        
        try:
            from validator import VestigiaValidator
            
            validator = VestigiaValidator(str(self.live_path))
            report = validator.validate_full()
            
            if report.is_valid:
                print("✅ Hash chain intact - no tampering detected")
            else:
                critical_issues = report.get_critical_issues()
                print(f"🚨 HASH CHAIN BROKEN: {len(critical_issues)} critical issues\n")
                
                for issue in critical_issues[:5]:  # Show first 5
                    message = getattr(issue, 'message', None) or getattr(issue, 'description', str(issue))
                    print(f"   • Entry {getattr(issue, 'entry_index', 'N/A')}: {issue.issue_type}")
                    print(f"     {message}")
                    
                    finding = ForensicFinding(
                        severity="CRITICAL",
                        category="CORRUPTION",
                        location=f"Entry {getattr(issue, 'entry_number', 'N/A')}",
                        description=issue.message,
                        evidence={'issue_type': issue.issue_type},
                        timestamp=datetime.now(UTC).isoformat()
                    )
                    self.findings.append(finding)
                
                if len(critical_issues) > 5:
                    print(f"\n   ... and {len(critical_issues) - 5} more issues")
        
        except ImportError:
            print("⚠️  Validator not available - skipping hash chain check")
        except Exception as e:
            print(f"⚠️  Hash chain check failed: {e}")
        
        print()
    
    def _identify_attack_patterns(self, live_data: List[Dict], backup_data: Optional[List[Dict]]):
        """Identify known attack patterns"""
        print("ANALYSIS 4: Attack Pattern Recognition")
        print("-" * 70)
        
        patterns_found = []
        
        # Pattern 1: Suspicious deletions
        if backup_data and len(live_data) < len(backup_data):
            deleted = backup_data[len(live_data):]
            critical_deleted = [e for e in deleted if e.get('status') == 'CRITICAL']
            
            if critical_deleted:
                patterns_found.append({
                    'pattern': 'EVIDENCE_DESTRUCTION',
                    'confidence': 'HIGH',
                    'description': f'{len(critical_deleted)} CRITICAL events deleted'
                })
        
        # Pattern 2: Status downgrades
        if backup_data:
            for i, (live, backup) in enumerate(zip(live_data, backup_data)):
                if backup.get('status') == 'CRITICAL' and live.get('status') != 'CRITICAL':
                    patterns_found.append({
                        'pattern': 'SEVERITY_DOWNGRADE',
                        'confidence': 'HIGH',
                        'description': f'Entry {i} severity downgraded'
                    })
        
        # Pattern 3: Rogue agent signatures
        rogue_actions = ['UNAUTHORIZED', 'EXFILTRATE', 'PRIVILEGE', 'BYPASS']
        for i, entry in enumerate(live_data):
            action = entry.get('action_type', '').upper()
            evidence = str(entry.get('evidence', '')).upper()
            
            if any(sig in action or sig in evidence for sig in rogue_actions):
                patterns_found.append({
                    'pattern': 'ROGUE_AGENT_ACTIVITY',
                    'confidence': 'MEDIUM',
                    'description': f'Entry {i}: Suspicious action detected',
                    'details': action
                })
        
        if patterns_found:
            print(f"🎯 {len(patterns_found)} attack patterns identified:\n")
            for pattern in patterns_found[:5]:
                print(f"   • {pattern['pattern']} (Confidence: {pattern['confidence']})")
                print(f"     {pattern['description']}")
        else:
            print("✅ No known attack patterns detected")
        
        print()
    
    def _generate_report(self, live_data: List[Dict], backup_data: Optional[List[Dict]]) -> Dict[str, Any]:
        """Generate final forensic report"""
        print("="*70)
        print("📋 FORENSIC REPORT SUMMARY")
        print("="*70 + "\n")
        
        critical = [f for f in self.findings if f.severity == "CRITICAL"]
        warnings = [f for f in self.findings if f.severity == "WARNING"]
        
        print(f"🔴 Critical Findings: {len(critical)}")
        print(f"🟡 Warnings: {len(warnings)}")
        print(f"📊 Total Findings: {len(self.findings)}")
        
        if critical:
            print(f"\n🚨 CRITICAL ISSUES:")
            for finding in critical[:5]:
                print(f"   • {finding.category}: {finding.description}")
                print(f"     Location: {finding.location}")
        
        print("\n" + "="*70)
        print("💡 RECOMMENDATIONS")
        print("="*70 + "\n")
        
        if backup_data and len(live_data) < len(backup_data):
            print("1. ✅ Restore from backup immediately")
            print("   Deleted entries can be recovered from backup ledger")
        
        if critical:
            print("2. 🔒 Lock down affected systems")
            print("   Prevent further tampering until investigation complete")
        
        print("3. 📝 Document all findings for incident response")
        print("4. 🔍 Investigate actor_id patterns in recovered entries")
        print("5. 🛡️  Review and strengthen access controls")
        
        print()
        
        return {
            'success': True,
            'findings': self.findings,
            'summary': {
                'critical': len(critical),
                'warnings': len(warnings),
                'total': len(self.findings)
            }
        }


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Vestigia Forensic Reconstructor - Analyze tampered ledgers'
    )
    parser.add_argument('ledger', help='Path to ledger file to analyze')
    parser.add_argument('--backup', help='Path to backup ledger for comparison')
    parser.add_argument('--output', help='Save report to JSON file')
    
    args = parser.parse_args()
    
    # Run analysis
    reconstructor = ForensicReconstructor(args.ledger, args.backup)
    report = reconstructor.analyze()
    
    # Save report if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now(UTC).isoformat(),
                'ledger': str(args.ledger),
                'backup': str(args.backup) if args.backup else None,
                'findings': [
                    {
                        'severity': f.severity,
                        'category': f.category,
                        'location': f.location,
                        'description': f.description,
                        'evidence': f.evidence,
                        'timestamp': f.timestamp
                    }
                    for f in reconstructor.findings
                ],
                'summary': report['summary']
            }, f, indent=4)
        
        print(f"\n💾 Report saved to: {output_path}")


if __name__ == '__main__':
    main()

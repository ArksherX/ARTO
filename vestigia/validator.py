#!/usr/bin/env python3
"""
Vestigia Validator - FIXED to match ledger_engine.py EXACTLY

KEY FIX: Uses canonical JSON (sort_keys=True, separators=(',',':'))
to match the ledger engine's hash calculation
"""

import json
import hashlib
import hmac
import os
from pathlib import Path
from datetime import datetime, UTC, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

# ============================================================================
# VALIDATION RESULT TYPES
# ============================================================================

class ValidationStatus(Enum):
    """Validation result status"""
    VALID = "VALID"
    INVALID = "INVALID"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

@dataclass
class ValidationIssue:
    """Represents a single validation issue"""
    severity: ValidationStatus
    entry_index: Optional[int]
    issue_type: str
    description: str
    evidence: Dict = field(default_factory=dict)
    
    def __str__(self):
        icon = {
            ValidationStatus.VALID: "✅",
            ValidationStatus.WARNING: "⚠️",
            ValidationStatus.INVALID: "❌",
            ValidationStatus.CRITICAL: "🚨"
        }[self.severity]
        
        location = f"Entry {self.entry_index}" if self.entry_index is not None else "Ledger"
        return f"{icon} {location}: {self.issue_type} - {self.description}"

@dataclass
class ValidationReport:
    """Complete validation report"""
    ledger_path: str
    validation_time: str
    is_valid: bool
    total_entries: int
    issues: List[ValidationIssue] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    
    def add_issue(self, severity: ValidationStatus, issue_type: str, description: str, 
                  entry_index: Optional[int] = None, evidence: Optional[Dict] = None):
        """Add validation issue"""
        self.issues.append(ValidationIssue(
            severity=severity,
            entry_index=entry_index,
            issue_type=issue_type,
            description=description,
            evidence=evidence or {}
        ))
        
        if severity in [ValidationStatus.INVALID, ValidationStatus.CRITICAL]:
            self.is_valid = False
    
    def get_critical_issues(self) -> List[ValidationIssue]:
        """Get only critical issues"""
        return [i for i in self.issues if i.severity == ValidationStatus.CRITICAL]
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        status_icon = "✅" if self.is_valid else "❌"
        status_text = "VALID" if self.is_valid else "INVALID"
        
        summary = [
            f"\n{'='*70}",
            f"VESTIGIA VALIDATION REPORT",
            f"{'='*70}",
            f"\nLedger: {self.ledger_path}",
            f"Validated: {self.validation_time}",
            f"Status: {status_icon} {status_text}",
            f"\nTotal Entries: {self.total_entries}",
            f"Total Issues: {len(self.issues)}",
        ]
        
        # Issue breakdown
        by_severity = {}
        for issue in self.issues:
            by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
        
        if by_severity:
            summary.append("\nIssue Breakdown:")
            for severity, count in sorted(by_severity.items(), key=lambda x: x[0].value):
                icon = {
                    ValidationStatus.VALID: "✅",
                    ValidationStatus.WARNING: "⚠️",
                    ValidationStatus.INVALID: "❌",
                    ValidationStatus.CRITICAL: "🚨"
                }[severity]
                summary.append(f"  {icon} {severity.value}: {count}")
        
        # Statistics
        if self.statistics:
            summary.append("\nStatistics:")
            for key, value in self.statistics.items():
                summary.append(f"  • {key}: {value}")
        
        # Critical issues
        critical = self.get_critical_issues()
        if critical:
            summary.append("\n🚨 CRITICAL ISSUES:")
            for issue in critical[:5]:
                summary.append(f"  {issue}")
            if len(critical) > 5:
                summary.append(f"  ... and {len(critical) - 5} more")
        
        summary.append("\n" + "="*70)
        
        return "\n".join(summary)

# ============================================================================
# VALIDATOR ENGINE
# ============================================================================

class VestigiaValidator:
    """Complete forensic validation engine"""
    
    def __init__(
        self,
        ledger_path: str,
        secret_salt: Optional[str] = None,
        witness_path: Optional[str] = None,
        anchor_repo: Optional[str] = None
    ):
        self.ledger_path = Path(ledger_path)
        self.secret_salt = secret_salt or os.getenv('VESTIGIA_SECRET_SALT', 'default_salt_change_me')
        self.witness_path = Path(witness_path) if witness_path else Path('data/witness.hash')
        self.anchor_repo = Path(anchor_repo) if anchor_repo else Path('vestigia_anchors')
        
        if self.secret_salt == 'default_salt_change_me':
            print("⚠️  WARNING: Using default salt - validation may be inaccurate")
    
    def validate_full(self) -> ValidationReport:
        """Complete validation - all checks"""
        report = ValidationReport(
            ledger_path=str(self.ledger_path),
            validation_time=datetime.now(UTC).isoformat(),
            is_valid=True,
            total_entries=0
        )
        
        # Load ledger
        ledger_data = self._load_ledger()
        if not ledger_data:
            report.add_issue(
                ValidationStatus.CRITICAL,
                "EMPTY_LEDGER",
                "Ledger file is empty or missing"
            )
            return report
        
        report.total_entries = len(ledger_data)
        
        # Run all validations
        self._validate_hash_chain(ledger_data, report)
        self._validate_genesis_block(ledger_data, report)
        self._validate_timestamps(ledger_data, report)
        self._detect_time_gaps(ledger_data, report)
        self._validate_event_structure(ledger_data, report)
        
        # Optional validations
        if self.witness_path.exists():
            self._validate_merkle_witness(ledger_data, report)
        
        # NEW: Check out-of-band witness for history rewrite attacks
        self._validate_witness_consistency(ledger_data, report)
        
        if self.anchor_repo.exists():
            self._validate_git_anchors(ledger_data, report)
        
        # Generate statistics
        report.statistics = self._generate_statistics(ledger_data)
        
        return report
    
    def _load_ledger(self) -> List[Dict]:
        """Load ledger data"""
        try:
            with open(self.ledger_path, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def _validate_hash_chain(self, ledger: List[Dict], report: ValidationReport):
        """
        Validate complete hash chain integrity
        
        CRITICAL FIX: Uses CANONICAL JSON to match ledger_engine.py exactly
        """
        if not ledger:
            return
        
        for i, entry in enumerate(ledger):
            # Skip genesis block
            if i == 0 and entry.get('action_type') == 'LEDGER_INITIALIZED':
                continue
            
            # Get previous hash
            expected_prev_hash = ledger[i-1]['integrity_hash'] if i > 0 else 'ROOT'
            actual_prev_hash = entry.get('previous_hash', 'ROOT')
            
            # Check previous hash link
            if expected_prev_hash != actual_prev_hash:
                report.add_issue(
                    ValidationStatus.CRITICAL,
                    "BROKEN_CHAIN",
                    f"Previous hash mismatch",
                    entry_index=i,
                    evidence={
                        'event_id': entry.get('event_id'),
                        'expected': expected_prev_hash[:16],
                        'actual': actual_prev_hash[:16]
                    }
                )
                continue
            
            # Recalculate hash - MUST MATCH LEDGER ENGINE EXACTLY
            try:
                timestamp = entry['timestamp']
                actor_id = entry['actor_id']
                action_type = entry['action_type']
                status = entry['status']
                evidence = entry['evidence']
                previous_hash = entry.get('previous_hash', 'ROOT')
                
                # CRITICAL: Use CANONICAL JSON (sort_keys=True, separators=(',',':'))
                # This MUST match ledger_engine._generate_integrity_hash()
                evidence_str = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
                
                # Reconstruct payload EXACTLY as ledger engine does
                tenant_id = entry.get("tenant_id")
                if tenant_id:
                    payload = f"{timestamp}{tenant_id}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
                else:
                    payload = f"{timestamp}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
                
                # Calculate expected hash
                if self.secret_salt and self.secret_salt != 'default_salt_change_me':
                    expected_hash = hmac.new(
                        self.secret_salt.encode(),
                        payload.encode(),
                        hashlib.sha256
                    ).hexdigest()
                else:
                    expected_hash = hashlib.sha256(payload.encode()).hexdigest()
                
                actual_hash = entry['integrity_hash']
                
                if expected_hash != actual_hash:
                    report.add_issue(
                        ValidationStatus.CRITICAL,
                        "HASH_MISMATCH",
                        f"Integrity hash mismatch - entry was modified",
                        entry_index=i,
                        evidence={
                            'event_id': entry.get('event_id'),
                            'expected': expected_hash[:16],
                            'actual': actual_hash[:16],
                            'actor': entry.get('actor_id'),
                            'action': entry.get('action_type')
                        }
                    )
            except Exception as e:
                report.add_issue(
                    ValidationStatus.INVALID,
                    "HASH_CALCULATION_ERROR",
                    f"Failed to recalculate hash: {str(e)}",
                    entry_index=i
                )
    
    def _validate_genesis_block(self, ledger: List[Dict], report: ValidationReport):
        """Validate genesis block"""
        if not ledger:
            return
        
        genesis = ledger[0]
        
        if genesis.get('actor_id') != 'SYSTEM':
            report.add_issue(
                ValidationStatus.WARNING,
                "INVALID_GENESIS",
                "Genesis block actor_id should be SYSTEM",
                entry_index=0
            )
        
        if genesis.get('action_type') != 'LEDGER_INITIALIZED':
            report.add_issue(
                ValidationStatus.WARNING,
                "INVALID_GENESIS",
                "Genesis block action_type should be LEDGER_INITIALIZED",
                entry_index=0
            )
    
    def _validate_timestamps(self, ledger: List[Dict], report: ValidationReport):
        """Validate timestamps"""
        for i, entry in enumerate(ledger):
            timestamp_str = entry.get('timestamp')
            
            if not timestamp_str:
                report.add_issue(
                    ValidationStatus.INVALID,
                    "MISSING_TIMESTAMP",
                    "Entry missing timestamp",
                    entry_index=i
                )
                continue
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                
                # Check not in future
                now = datetime.now(UTC)
                if timestamp > now:
                    report.add_issue(
                        ValidationStatus.WARNING,
                        "FUTURE_TIMESTAMP",
                        f"Timestamp is {(timestamp - now).total_seconds():.0f}s in the future",
                        entry_index=i
                    )
                
                # Check sequential order
                if i > 0:
                    prev_timestamp_str = ledger[i-1].get('timestamp')
                    if prev_timestamp_str:
                        prev_timestamp = datetime.fromisoformat(prev_timestamp_str.replace('Z', '+00:00'))
                        if timestamp < prev_timestamp:
                            report.add_issue(
                                ValidationStatus.CRITICAL,
                                "NON_SEQUENTIAL_TIMESTAMP",
                                f"Timestamp goes backward",
                                entry_index=i
                            )
            
            except Exception as e:
                report.add_issue(
                    ValidationStatus.INVALID,
                    "INVALID_TIMESTAMP",
                    f"Cannot parse timestamp: {str(e)}",
                    entry_index=i
                )
    
    def _detect_time_gaps(self, ledger: List[Dict], report: ValidationReport):
        """Detect suspicious time gaps"""
        if len(ledger) < 2:
            return
        
        max_gap = timedelta(hours=24)
        
        for i in range(1, len(ledger)):
            try:
                current_ts = datetime.fromisoformat(ledger[i]['timestamp'].replace('Z', '+00:00'))
                prev_ts = datetime.fromisoformat(ledger[i-1]['timestamp'].replace('Z', '+00:00'))
                
                gap = current_ts - prev_ts
                
                if gap > max_gap:
                    report.add_issue(
                        ValidationStatus.WARNING,
                        "LARGE_TIME_GAP",
                        f"Suspicious {gap.total_seconds()/3600:.1f}h gap between entries",
                        entry_index=i,
                        evidence={
                            'gap_hours': gap.total_seconds() / 3600,
                            'previous_event': ledger[i-1].get('event_id'),
                            'current_event': ledger[i].get('event_id')
                        }
                    )
            except Exception:
                pass
    
    def _validate_event_structure(self, ledger: List[Dict], report: ValidationReport):
        """Validate event structure"""
        required_fields = ['timestamp', 'actor_id', 'action_type', 'status', 
                          'evidence', 'integrity_hash', 'event_id', 'previous_hash']
        
        for i, entry in enumerate(ledger):
            missing = [f for f in required_fields if f not in entry]
            
            if missing:
                report.add_issue(
                    ValidationStatus.INVALID,
                    "MISSING_FIELDS",
                    f"Missing required fields: {', '.join(missing)}",
                    entry_index=i
                )
    
    def _validate_merkle_witness(self, ledger: List[Dict], report: ValidationReport):
        """Validate Merkle witness"""
        try:
            with open(self.witness_path, 'r') as f:
                witness_content = f.read().strip()
            try:
                witness_data = json.loads(witness_content)
            except json.JSONDecodeError:
                # Legacy/plain-text witness format is handled by
                # _validate_witness_consistency(); do not warn here.
                return
            
            witnesses = witness_data.get('witnesses', [])
            
            if not witnesses:
                report.add_issue(
                    ValidationStatus.WARNING,
                    "NO_WITNESSES",
                    "No Merkle witnesses found"
                )
                return
            
            # Check current hash
            if ledger:
                current_hash = ledger[-1]['integrity_hash']
                matching = [w for w in witnesses if w['merkle_root'] == current_hash]
                
                if matching:
                    report.add_issue(
                        ValidationStatus.VALID,
                        "WITNESS_VERIFIED",
                        f"Verified against witness {matching[0]['witness_id']}"
                    )
                else:
                    report.add_issue(
                        ValidationStatus.WARNING,
                        "NO_MATCHING_WITNESS",
                        f"Current hash not found in witnesses"
                    )
        
        except Exception as e:
            report.add_issue(
                ValidationStatus.WARNING,
                "WITNESS_CHECK_FAILED",
                f"Cannot verify witness: {str(e)}"
            )
    
    def _validate_witness_consistency(self, ledger: List[Dict], report: ValidationReport):
        """
        Validate out-of-band witness - CRITICAL SECURITY CHECK
        
        This detects "history rewrite" attacks where attacker replaces
        entire ledger with a new valid chain
        """
        witness_file = self.ledger_path.parent / "witness.hash"
        
        if not witness_file.exists():
            report.add_issue(
                ValidationStatus.WARNING,
                "WITNESS_FILE_MISSING",
                "No witness.hash file found (first run or deleted)"
            )
            return
        
        try:
            with open(witness_file, 'r') as f:
                witness_content = f.read().strip()

            # Structured Merkle witness files are validated separately in
            # _validate_merkle_witness(). Do not misinterpret them as the
            # legacy plain-text last-hash witness format.
            try:
                witness_data = json.loads(witness_content)
                if isinstance(witness_data, dict) and "witnesses" in witness_data:
                    if not witness_data.get("witnesses"):
                        report.add_issue(
                            ValidationStatus.WARNING,
                            "NO_WITNESSES",
                            "Structured Merkle witness file exists but no witness anchors are recorded yet"
                        )
                    return
            except json.JSONDecodeError:
                pass

            witness_hash = witness_content
            
            if not ledger:
                report.add_issue(
                    ValidationStatus.WARNING,
                    "EMPTY_LEDGER_WITH_WITNESS",
                    "Ledger empty but witness exists (suspicious)"
                )
                return
            
            # Get actual last hash from ledger
            actual_last_hash = ledger[-1]['integrity_hash']
            
            # Compare
            if actual_last_hash != witness_hash:
                report.add_issue(
                    ValidationStatus.CRITICAL,
                    "HISTORY_REWRITE_DETECTED",
                    "Ledger hash doesn't match witness - entire history may have been swapped!",
                    evidence={
                        'witness_hash': witness_hash[:16] + "...",
                        'ledger_hash': actual_last_hash[:16] + "...",
                        'entry_count': len(ledger)
                    }
                )
            else:
                report.add_issue(
                    ValidationStatus.VALID,
                    "WITNESS_CONSISTENCY_OK",
                    "Out-of-band witness matches ledger"
                )
        
        except Exception as e:
            report.add_issue(
                ValidationStatus.WARNING,
                "WITNESS_CHECK_ERROR",
                f"Failed to check witness: {str(e)}"
            )
    
    def _validate_git_anchors(self, ledger: List[Dict], report: ValidationReport):
        """Validate Git anchors"""
        try:
            import subprocess
            
            result = subprocess.run(
                ['git', 'log', '--oneline'],
                cwd=self.anchor_repo,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                report.add_issue(
                    ValidationStatus.WARNING,
                    "GIT_CHECK_FAILED",
                    "Cannot read Git anchor history"
                )
                return
            
            anchor_count = len([l for l in result.stdout.split('\n') if 'Anchor' in l])
            
            if anchor_count > 0:
                report.add_issue(
                    ValidationStatus.VALID,
                    "GIT_ANCHORS_FOUND",
                    f"Found {anchor_count} Git anchors"
                )
            else:
                report.add_issue(
                    ValidationStatus.WARNING,
                    "NO_GIT_ANCHORS",
                    "No Git anchors found"
                )
        
        except Exception as e:
            report.add_issue(
                ValidationStatus.WARNING,
                "GIT_CHECK_ERROR",
                f"Git anchor check failed: {str(e)}"
            )
    
    def _generate_statistics(self, ledger: List[Dict]) -> Dict:
        """Generate statistics"""
        if not ledger:
            return {}
        
        stats = {
            'Total Entries': len(ledger),
            'Date Range': f"{ledger[0]['timestamp'][:10]} to {ledger[-1]['timestamp'][:10]}",
        }
        
        # Count by status
        by_status = {}
        for entry in ledger:
            status = entry.get('status', 'UNKNOWN')
            by_status[status] = by_status.get(status, 0) + 1
        
        for status, count in sorted(by_status.items()):
            stats[f'{status} Events'] = count
        
        # Count by action
        by_action = {}
        for entry in ledger:
            action = entry.get('action_type', 'UNKNOWN')
            by_action[action] = by_action.get(action, 0) + 1
        
        # Top 3 actions
        top_actions = sorted(by_action.items(), key=lambda x: x[1], reverse=True)[:3]
        stats['Top Actions'] = ', '.join([f"{a[0]} ({a[1]})" for a in top_actions])
        
        return stats

# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line validation interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vestigia Validator')
    parser.add_argument('ledger', help='Path to ledger file')
    parser.add_argument('--secret', help='Secret salt')
    parser.add_argument('--witness', help='Path to witness file')
    parser.add_argument('--anchors', help='Path to Git anchor repository')
    parser.add_argument('--output', help='Save report to file (JSON)')
    parser.add_argument('--verbose', action='store_true', help='Show all issues')
    
    args = parser.parse_args()
    
    validator = VestigiaValidator(
        ledger_path=args.ledger,
        secret_salt=args.secret,
        witness_path=args.witness,
        anchor_repo=args.anchors
    )
    
    print(f"\n🔍 Validating: {args.ledger}")
    report = validator.validate_full()
    
    print(report.get_summary())
    
    if args.verbose and report.issues:
        print("\n📋 All Issues:")
        for issue in report.issues:
            print(f"  {issue}")
    
    if args.output:
        report_data = {
            'ledger_path': report.ledger_path,
            'validation_time': report.validation_time,
            'is_valid': report.is_valid,
            'total_entries': report.total_entries,
            'issues': [
                {
                    'severity': i.severity.value,
                    'entry_index': i.entry_index,
                    'type': i.issue_type,
                    'description': i.description,
                    'evidence': i.evidence
                }
                for i in report.issues
            ],
            'statistics': report.statistics
        }
        
        with open(args.output, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n💾 Report saved to: {args.output}")
    
    return 0 if report.is_valid else 1

if __name__ == '__main__':
    exit(main())

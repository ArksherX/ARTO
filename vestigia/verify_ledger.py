#!/usr/bin/env python3
"""
Vestigia Verifier - Cryptographic Tamper Detection
The "Truth Validator" for audit trails

Save as: vestigia/verify_ledger.py
"""

import json
import hashlib
import hmac
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class VerificationResult:
    """Result of ledger verification"""
    is_valid: bool
    total_entries: int
    verified_entries: int
    first_tampered_index: Optional[int]
    tampering_details: Optional[str]
    verification_timestamp: str
    
    def to_dict(self) -> dict:
        return {
            'is_valid': self.is_valid,
            'total_entries': self.total_entries,
            'verified_entries': self.verified_entries,
            'first_tampered_index': self.first_tampered_index,
            'tampering_details': self.tampering_details,
            'verification_timestamp': self.verification_timestamp
        }


class VestigiaVerifier:
    """
    Independent verification of Vestigia ledger integrity
    
    Can detect:
    - Deleted entries (breaks hash chain)
    - Modified entries (hash mismatch)
    - Time gaps (missing heartbeats)
    """
    
    def __init__(self, ledger_path: str, secret_salt: Optional[str] = None):
        self.ledger_path = Path(ledger_path)
        self.secret_salt = secret_salt
        
        if not self.ledger_path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")
    
    def _load_ledger(self) -> List[dict]:
        """Load ledger from disk"""
        with open(self.ledger_path, 'r') as f:
            return json.load(f)
    
    def _recalculate_hash(self, last_hash: str, event_data: dict) -> str:
        """Recalculate integrity hash for verification"""
        canonical_data = json.dumps(event_data, sort_keys=True)
        combined = f"{last_hash}{canonical_data}"
        
        if self.secret_salt:
            return hmac.new(
                self.secret_salt.encode(),
                combined.encode(),
                hashlib.sha256
            ).hexdigest()
        else:
            return hashlib.sha256(combined.encode()).hexdigest()
    
    def verify_full_chain(self) -> VerificationResult:
        """
        Verify complete hash chain integrity
        
        Returns comprehensive verification result
        """
        trail = self._load_ledger()
        total_entries = len(trail)
        
        if total_entries == 0:
            return VerificationResult(
                is_valid=True,
                total_entries=0,
                verified_entries=0,
                first_tampered_index=None,
                tampering_details=None,
                verification_timestamp=datetime.utcnow().isoformat()
            )
        
        # Verify each entry
        for i in range(1, total_entries):  # Skip genesis block
            entry = trail[i]
            previous_hash = trail[i-1]['integrity_hash']
            
            # Reconstruct event data (without integrity_hash)
            event_data = {
                k: v for k, v in entry.items()
                if k != 'integrity_hash'
            }
            
            # Recalculate hash
            expected_hash = self._recalculate_hash(previous_hash, event_data)
            actual_hash = entry['integrity_hash']
            
            # Check for tampering
            if expected_hash != actual_hash:
                return VerificationResult(
                    is_valid=False,
                    total_entries=total_entries,
                    verified_entries=i,
                    first_tampered_index=i,
                    tampering_details=f"Hash mismatch at entry {i} (Event ID: {entry.get('event_id', 'unknown')})",
                    verification_timestamp=datetime.utcnow().isoformat()
                )
        
        # All entries verified
        return VerificationResult(
            is_valid=True,
            total_entries=total_entries,
            verified_entries=total_entries,
            first_tampered_index=None,
            tampering_details=None,
            verification_timestamp=datetime.utcnow().isoformat()
        )
    
    def detect_time_gaps(self, max_gap_hours: int = 2) -> List[Tuple[int, str]]:
        """
        Detect suspicious time gaps in ledger
        
        Returns list of (index, gap_description)
        """
        trail = self._load_ledger()
        gaps = []
        
        for i in range(1, len(trail)):
            prev_time = datetime.fromisoformat(trail[i-1]['timestamp'])
            curr_time = datetime.fromisoformat(trail[i]['timestamp'])
            
            gap_hours = (curr_time - prev_time).total_seconds() / 3600
            
            if gap_hours > max_gap_hours:
                gaps.append((
                    i,
                    f"Gap of {gap_hours:.1f} hours between entries {i-1} and {i}"
                ))
        
        return gaps
    
    def generate_verification_report(self) -> dict:
        """Generate comprehensive verification report"""
        chain_result = self.verify_full_chain()
        time_gaps = self.detect_time_gaps()
        trail = self._load_ledger()
        
        # Count event types
        event_counts = {}
        status_counts = {}
        
        for entry in trail:
            action = entry.get('action_type', 'UNKNOWN')
            status = entry.get('status', 'UNKNOWN')
            
            event_counts[action] = event_counts.get(action, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'verification': chain_result.to_dict(),
            'statistics': {
                'total_entries': len(trail),
                'event_types': event_counts,
                'status_breakdown': status_counts,
                'first_entry': trail[0]['timestamp'] if trail else None,
                'last_entry': trail[-1]['timestamp'] if trail else None
            },
            'time_gaps': [
                {'index': idx, 'description': desc}
                for idx, desc in time_gaps
            ],
            'integrity_status': 'VERIFIED' if chain_result.is_valid else 'COMPROMISED'
        }


# ============================================================================
# CLI TOOL
# ============================================================================

def main():
    """Command-line verification tool"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Vestigia Ledger Verification Tool"
    )
    parser.add_argument(
        'ledger_path',
        help='Path to vestigia_ledger.json'
    )
    parser.add_argument(
        '--secret',
        help='Secret salt for HMAC verification (if used)',
        default=None
    )
    parser.add_argument(
        '--report',
        help='Output path for JSON report',
        default=None
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("  🔍 Vestigia Ledger Verification")
    print("=" * 70)
    
    # Initialize verifier
    verifier = VestigiaVerifier(args.ledger_path, args.secret)
    
    # Run verification
    print(f"\n📂 Ledger: {args.ledger_path}")
    print("🔐 Verifying cryptographic integrity...\n")
    
    result = verifier.verify_full_chain()
    
    # Print results
    print(f"Total Entries: {result.total_entries}")
    print(f"Verified: {result.verified_entries}/{result.total_entries}")
    
    if result.is_valid:
        print("\n✅ VERIFICATION PASSED - Ledger integrity intact")
        print("   No tampering detected")
    else:
        print("\n🚨 VERIFICATION FAILED - Tampering detected!")
        print(f"   First tampered entry: Index {result.first_tampered_index}")
        print(f"   Details: {result.tampering_details}")
    
    # Check time gaps
    print("\n⏰ Checking for suspicious time gaps...")
    time_gaps = verifier.detect_time_gaps()
    
    if time_gaps:
        print(f"   ⚠️  Found {len(time_gaps)} suspicious gaps:")
        for idx, desc in time_gaps[:5]:  # Show first 5
            print(f"      - {desc}")
    else:
        print("   ✅ No suspicious time gaps detected")
    
    # Generate full report
    if args.report:
        report = verifier.generate_verification_report()
        
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Full report saved to: {args.report}")
    
    print("\n" + "=" * 70)
    
    # Exit with appropriate code
    return 0 if result.is_valid else 1


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # CLI mode
        sys.exit(main())
    else:
        # Test mode
        print("=" * 70)
        print("  🔍 Vestigia Verifier - Test Mode")
        print("=" * 70)
        
        # Look for test ledger
        test_ledger = "test_ledger.json"
        
        if not Path(test_ledger).exists():
            print(f"\n❌ Test ledger not found: {test_ledger}")
            print("   Run vestigia_core.py first to create test data")
            sys.exit(1)
        
        verifier = VestigiaVerifier(test_ledger)
        
        print(f"\n📂 Verifying: {test_ledger}\n")
        
        # Run verification
        result = verifier.verify_full_chain()
        
        if result.is_valid:
            print(f"✅ VALID - All {result.total_entries} entries verified")
        else:
            print(f"🚨 INVALID - Tampering at index {result.first_tampered_index}")
        
        # Generate report
        report = verifier.generate_verification_report()
        
        print("\n📊 Ledger Statistics:")
        print(f"   Total Entries: {report['statistics']['total_entries']}")
        print(f"   Event Types: {report['statistics']['event_types']}")
        print(f"   Status Breakdown: {report['statistics']['status_breakdown']}")
        
        print("\n✅ Test complete!")

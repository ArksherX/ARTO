#!/usr/bin/env python3
"""
Vestigia Production Verifier
Enhanced verification with Merkle witness validation

Save as: vestigia/security/verifier.py
"""

import json
import hashlib
import hmac
from datetime import datetime, UTC
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class VerificationResult:
    """Comprehensive verification result"""
    is_valid: bool
    total_entries: int
    verified_entries: int
    first_tampered_index: Optional[int]
    tampering_details: Optional[str]
    verification_timestamp: str
    merkle_verified: bool
    merkle_details: Optional[str]
    time_gaps: List[Tuple[int, str]]
    
    def to_dict(self) -> dict:
        return {
            'is_valid': self.is_valid,
            'total_entries': self.total_entries,
            'verified_entries': self.verified_entries,
            'first_tampered_index': self.first_tampered_index,
            'tampering_details': self.tampering_details,
            'verification_timestamp': self.verification_timestamp,
            'merkle_verified': self.merkle_verified,
            'merkle_details': self.merkle_details,
            'time_gaps': [{'index': idx, 'description': desc} for idx, desc in self.time_gaps]
        }
    
    def print_report(self):
        """Print human-readable report"""
        print("\n" + "=" * 70)
        print("  🔍 VERIFICATION REPORT")
        print("=" * 70)
        
        print(f"\n📊 Summary:")
        print(f"   Total Entries: {self.total_entries}")
        print(f"   Verified: {self.verified_entries}/{self.total_entries}")
        print(f"   Timestamp: {self.verification_timestamp}")
        
        print(f"\n🔗 Hash Chain:")
        if self.is_valid:
            print("   ✅ VALID - All entries verified")
        else:
            print(f"   🚨 INVALID - Tampering at index {self.first_tampered_index}")
            print(f"   Details: {self.tampering_details}")
        
        print(f"\n⚓ Merkle Witness:")
        if self.merkle_verified:
            print("   ✅ VERIFIED - Ledger matches external witness")
            print(f"   {self.merkle_details}")
        else:
            print("   ⚠️  NOT VERIFIED")
            if self.merkle_details:
                print(f"   {self.merkle_details}")
        
        print(f"\n⏰ Time Gap Analysis:")
        if self.time_gaps:
            print(f"   ⚠️  Found {len(self.time_gaps)} suspicious gaps:")
            for idx, desc in self.time_gaps[:5]:
                print(f"      - {desc}")
        else:
            print("   ✅ No suspicious time gaps")
        
        print("\n" + "=" * 70)


class ProductionVerifier:
    """
    Production-grade ledger verifier
    
    Features:
    - Hash chain verification
    - Merkle witness validation
    - Time gap detection
    - File replacement detection
    - Comprehensive reporting
    """
    
    def __init__(
        self, 
        ledger_path: str,
        witness_path: str = "data/witness.hash",
        secret_salt: Optional[str] = None
    ):
        self.ledger_path = Path(ledger_path)
        self.witness_path = Path(witness_path)
        self.secret_salt = secret_salt
        
        if not self.ledger_path.exists():
            raise FileNotFoundError(f"Ledger not found: {ledger_path}")
    
    def _load_ledger(self) -> List[dict]:
        """Load ledger from disk"""
        with open(self.ledger_path, 'r') as f:
            return json.load(f)
    
    def _load_witness(self) -> Optional[dict]:
        """Load witness data if available (handles JSON and plain-text formats)"""
        if not self.witness_path.exists():
            return None

        content = self.witness_path.read_text().strip()
        if not content:
            return None

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Plain-text witness hash (written by ledger_engine._witness_state)
            return {'plain_hash': content}
    
    def _recalculate_hash(self, entry: dict, previous_hash: str) -> str:
        """
        Recalculate integrity hash for verification.

        MUST match core/ledger_engine.py _generate_integrity_hash() exactly:
        - Field-by-field concatenation
        - Canonical JSON for evidence (sort_keys=True, separators=(',',':'))
        """
        timestamp = entry['timestamp']
        actor_id = entry['actor_id']
        action_type = entry['action_type']
        status = entry['status']
        evidence = entry['evidence']

        # CRITICAL: canonical JSON matching ledger_engine.py
        evidence_str = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
        tenant_id = entry.get("tenant_id")
        if tenant_id:
            payload = f"{timestamp}{tenant_id}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
        else:
            payload = f"{timestamp}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"

        if self.secret_salt:
            return hmac.new(
                self.secret_salt.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
        else:
            return hashlib.sha256(payload.encode()).hexdigest()
    
    def verify_hash_chain(self) -> Tuple[bool, int, Optional[int], Optional[str]]:
        """
        Verify complete hash chain
        
        Returns: (is_valid, total, tampered_index, details)
        """
        trail = self._load_ledger()
        total_entries = len(trail)
        
        if total_entries == 0:
            return True, 0, None, None
        
        # Verify each entry
        for i in range(1, total_entries):
            entry = trail[i]
            previous_hash = trail[i-1]['integrity_hash']
            
            # Check previous_hash field
            if entry.get('previous_hash') != previous_hash:
                return (
                    False,
                    total_entries,
                    i,
                    f"Previous hash mismatch at entry {i}"
                )

            # Recalculate hash using same algorithm as ledger_engine.py
            expected_hash = self._recalculate_hash(entry, previous_hash)
            actual_hash = entry['integrity_hash']
            
            # Check for tampering
            if expected_hash != actual_hash:
                return (
                    False,
                    total_entries,
                    i,
                    f"Hash mismatch at entry {i} (Event: {entry.get('event_id', 'unknown')})"
                )
        
        return True, total_entries, None, None
    
    def verify_merkle_witness(self) -> Tuple[bool, Optional[str]]:
        """
        Verify ledger against Merkle witness
        
        This prevents total file replacement attacks
        
        Returns: (is_verified, details)
        """
        witness_data = self._load_witness()

        if not witness_data:
            return False, "No witness file found"

        trail = self._load_ledger()

        if not trail:
            return False, "Empty ledger"

        # Get current ledger hash
        current_hash = trail[-1]['integrity_hash']
        entry_count = len(trail)

        # Handle plain-text witness (from ledger_engine._witness_state)
        if 'plain_hash' in witness_data:
            if witness_data['plain_hash'] == current_hash:
                return True, "Verified against out-of-band witness hash"
            else:
                return False, "Ledger hash does not match witness (possible history rewrite)"

        # Handle structured witness (from MerkleWitness)
        witnesses = witness_data.get('witnesses', [])

        for witness in reversed(witnesses):  # Check most recent first
            if witness['entry_count'] == entry_count:
                if witness['merkle_root'] == current_hash:
                    return True, f"Verified against {witness['witness_id']} ({witness['timestamp']})"
                else:
                    return False, f"Hash mismatch with {witness['witness_id']}"

        # No matching witness found (not necessarily tampering - might be new entries)
        return False, f"No witness for {entry_count} entries (might be recent activity)"
    
    def detect_time_gaps(self, max_gap_hours: int = 2) -> List[Tuple[int, str]]:
        """
        Detect suspicious time gaps
        
        Large gaps might indicate tampering window
        
        Returns: List of (index, description)
        """
        trail = self._load_ledger()
        gaps = []
        
        for i in range(1, len(trail)):
            try:
                # Parse timestamps (they should be timezone-aware from ledger)
                prev_time = datetime.fromisoformat(trail[i-1]['timestamp'])
                curr_time = datetime.fromisoformat(trail[i]['timestamp'])
                
                # Ensure both are timezone-aware for comparison
                if prev_time.tzinfo is None:
                    prev_time = prev_time.replace(tzinfo=UTC)
                if curr_time.tzinfo is None:
                    curr_time = curr_time.replace(tzinfo=UTC)
                
                gap_hours = (curr_time - prev_time).total_seconds() / 3600
                
                if gap_hours > max_gap_hours:
                    gaps.append((
                        i,
                        f"Gap of {gap_hours:.1f} hours between entries {i-1} and {i}"
                    ))
            except (ValueError, KeyError):
                # Malformed timestamp
                gaps.append((i, f"Malformed timestamp at entry {i}"))
        
        return gaps
    
    def verify_full(self) -> VerificationResult:
        """
        Comprehensive verification
        
        Returns complete VerificationResult
        """
        # Hash chain verification
        is_valid, total, tampered_index, details = self.verify_hash_chain()
        
        # Merkle witness verification
        merkle_verified, merkle_details = self.verify_merkle_witness()
        
        # Time gap detection
        time_gaps = self.detect_time_gaps()
        
        return VerificationResult(
            is_valid=is_valid,
            total_entries=total,
            verified_entries=tampered_index if tampered_index else total,
            first_tampered_index=tampered_index,
            tampering_details=details,
            verification_timestamp=datetime.now(UTC).isoformat(),
            merkle_verified=merkle_verified,
            merkle_details=merkle_details,
            time_gaps=time_gaps
        )
    
    def visualize_chain(self, max_entries: int = 10):
        """
        Visualize hash chain for presentation
        
        Shows dependency between entries
        """
        trail = self._load_ledger()
        
        print("\n" + "=" * 70)
        print("  🔗 HASH CHAIN VISUALIZATION")
        print("=" * 70 + "\n")
        
        entries_to_show = min(max_entries, len(trail))
        
        for i in range(entries_to_show):
            entry = trail[i]
            
            print(f"Entry {i}: {entry['event_id']}")
            print(f"  ├─ Action: {entry['action_type']}")
            print(f"  ├─ Previous Hash: {entry.get('previous_hash', 'N/A')[:16]}...")
            print(f"  └─ Integrity Hash: {entry['integrity_hash'][:16]}...")
            
            if i < entries_to_show - 1:
                print("  │")
                print("  ↓ (hash chain link)")
                print("  │")
        
        if len(trail) > max_entries:
            print(f"\n  ... ({len(trail) - max_entries} more entries)")
        
        print("\n" + "=" * 70)
        print("If ANY entry is modified, all subsequent hashes break!")
        print("=" * 70 + "\n")


# ============================================================================
# CLI TOOL
# ============================================================================

def main():
    """Command-line verification tool"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Vestigia Production Verifier"
    )
    parser.add_argument(
        'ledger_path',
        help='Path to ledger JSON file'
    )
    parser.add_argument(
        '--witness',
        help='Path to witness.hash file',
        default='data/witness.hash'
    )
    parser.add_argument(
        '--secret',
        help='Secret salt for HMAC verification',
        default=None
    )
    parser.add_argument(
        '--visualize',
        help='Visualize hash chain',
        action='store_true'
    )
    parser.add_argument(
        '--json',
        help='Output as JSON',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    # Initialize verifier
    verifier = ProductionVerifier(
        args.ledger_path,
        args.witness,
        args.secret
    )
    
    # Run verification
    result = verifier.verify_full()
    
    # Output
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        result.print_report()
    
    # Visualize if requested
    if args.visualize:
        verifier.visualize_chain()
    
    # Exit code
    return 0 if result.is_valid else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

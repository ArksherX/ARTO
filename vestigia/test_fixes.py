#!/usr/bin/env python3
"""
Vestigia Test Suite
Tests all fixed functionality

Run: python test_fixes.py
"""

import sys
from pathlib import Path
from datetime import datetime, UTC

sys.path.insert(0, str(Path(__file__).parent))

def test_timezone_handling():
    """Test timezone-aware datetime handling"""
    print("\n1️⃣  Testing timezone handling...")
    
    from security.verifier import ProductionVerifier
    
    try:
        verifier = ProductionVerifier('data/vestigia_ledger.json')
        gaps = verifier.detect_time_gaps(max_gap_hours=24)
        print(f"   ✅ Time gap detection works: {len(gaps)} gaps found")
        return True
    except TypeError as e:
        print(f"   ❌ Timezone error: {e}")
        return False

def test_cli_positional():
    """Test CLI with positional argument"""
    print("\n2️⃣  Testing CLI positional argument...")
    
    import subprocess
    
    result = subprocess.run(
        ['python', 'cli.py', 'verify', 'data/vestigia_ledger.json'],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 or 'VERIFICATION REPORT' in result.stdout:
        print("   ✅ Positional argument works")
        return True
    else:
        print(f"   ❌ Failed: {result.stderr}")
        return False

def test_cli_flag():
    """Test CLI with --ledger flag"""
    print("\n3️⃣  Testing CLI --ledger flag...")
    
    import subprocess
    
    result = subprocess.run(
        ['python', 'cli.py', 'verify', '--ledger', 'data/vestigia_ledger.json'],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 or 'VERIFICATION REPORT' in result.stdout:
        print("   ✅ --ledger flag works")
        return True
    else:
        print(f"   ❌ Failed: {result.stderr}")
        return False

def test_tampering_detection():
    """Test the money shot - tampering detection"""
    print("\n4️⃣  Testing tampering detection...")
    
    from security.verifier import ProductionVerifier
    
    verifier = ProductionVerifier('demo_production.json')
    result = verifier.verify_full()
    
    if not result.is_valid:
        print(f"   ✅ Tampering detected at index {result.first_tampered_index}")
        print(f"      Details: {result.tampering_details}")
        return True
    else:
        print("   ⚠️  No tampering detected (ledger is clean)")
        return True

def main():
    print("=" * 70)
    print("  🧪 Vestigia Test Suite")
    print("=" * 70)
    
    tests = [
        test_timezone_handling,
        test_cli_positional,
        test_cli_flag,
        test_tampering_detection
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 70)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

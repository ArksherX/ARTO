#!/usr/bin/env python3
"""
Vestigia Production Readiness Test & Verification
Tests all 4 production gaps and provides deployment checklist
"""

import json
import os
import threading
import time
from pathlib import Path
from datetime import datetime, UTC

def test_environment_setup():
    """Test 1: Environment & Secret Management"""
    print("\n" + "="*70)
    print("TEST 1: Environment & Secret Management")
    print("="*70)
    
    from production_hardening import SecretManager
    
    secret = SecretManager.get_secret_salt()
    
    checks = {
        "Secret loaded": len(secret) > 20,
        "Secret from env": 'VESTIGIA_SECRET_SALT' in os.environ,
        "Not default salt": secret != "default_salt_change_me"
    }
    
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {check}")
    
    return all(checks.values())

def test_external_anchoring():
    """Test 2: External Anchoring (Git)"""
    print("\n" + "="*70)
    print("TEST 2: External Anchoring")
    print("="*70)
    
    from production_hardening import ExternalAnchor
    
    anchor = ExternalAnchor(anchor_type='git', config={'repo_path': 'vestigia_anchors'})
    
    # Test anchor creation
    test_hash = f"test_{datetime.now(UTC).isoformat()}"
    anchor_id = anchor.anchor(test_hash, 100, {'test': True})
    
    # Test verification
    is_valid = anchor.verify_anchor(anchor_id, test_hash)
    
    checks = {
        "Git repo exists": Path('vestigia_anchors/.git').exists(),
        "Anchor created": anchor_id is not None,
        "Verification passed": is_valid
    }
    
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {check}")
    
    return all(checks.values())

def test_concurrency():
    """Test 3: Concurrent Write Safety"""
    print("\n" + "="*70)
    print("TEST 3: Concurrency Control")
    print("="*70)
    
    from core.ledger_engine import VestigiaLedger
    
    # Clean test
    test_file = Path('data/test_concurrency.json')
    test_file.unlink(missing_ok=True)
    
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=False)
    
    success_count = 0
    lock = threading.Lock()
    
    def worker(thread_id):
        nonlocal success_count
        for i in range(10):
            try:
                ledger.append_event(
                    actor_id=f'thread_{thread_id}',
                    action_type='CONCURRENCY_TEST',
                    status='SUCCESS',
                    evidence=f'Event {i}'
                )
                with lock:
                    success_count += 1
            except Exception as e:
                print(f"  ⚠️  Thread {thread_id} failed: {e}")
    
    # Launch 5 threads
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Verify
    events = ledger.query_events(action_type='CONCURRENCY_TEST', limit=100)
    
    checks = {
        "All writes succeeded": success_count == 50,
        "All events in ledger": len(events) == 50,
        "No data loss": success_count == len(events)
    }
    
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {check} ({success_count}/50 writes, {len(events)}/50 stored)")
    
    # Cleanup
    test_file.unlink(missing_ok=True)
    
    return all(checks.values())

def test_rotation():
    """Test 4: Ledger Rotation & Archival"""
    print("\n" + "="*70)
    print("TEST 4: Storage Scalability (Rotation)")
    print("="*70)
    
    from core.ledger_engine import VestigiaLedger
    from production_hardening import LedgerRotation, ExternalAnchor
    
    # Clean test
    test_file = Path('data/test_rotation.json')
    archive_path = Path('data/test_archives')
    test_file.unlink(missing_ok=True)
    
    # Clear archives
    if archive_path.exists():
        import shutil
        shutil.rmtree(archive_path)
    
    # Create ledger with small rotation threshold
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=False)
    
    # Manually set rotation threshold to 25 for testing
    anchor = ExternalAnchor(anchor_type='git', config={'repo_path': 'vestigia_anchors'})
    rotation = LedgerRotation(
        base_path=str(test_file),
        max_entries=25,
        archive_path=str(archive_path),
        anchor=anchor
    )
    
    # Add 50 events (should trigger 2 rotations)
    print("  Adding 50 events...")
    for i in range(50):
        ledger.append_event(
            actor_id=f'test_agent_{i}',
            action_type='ROTATION_TEST',
            status='SUCCESS',
            evidence=f'Event {i}'
        )
        
        # Check if rotation needed
        with open(test_file, 'r') as f:
            current_data = json.load(f)
        
        if rotation.should_rotate(len(current_data)):
            last_hash = current_data[-1]['integrity_hash']
            archive_file = rotation.rotate(
                current_hash=last_hash,
                entry_count=len(current_data),
                anchor=anchor
            )
            print(f"  📦 Rotation triggered at {len(current_data)} entries → {archive_file}")
    
    # Count archives
    archives = list(archive_path.glob('ledger_*.json')) if archive_path.exists() else []
    
    checks = {
        "Archive directory created": archive_path.exists(),
        "Archives created": len(archives) > 0,
        "Expected rotations": len(archives) >= 1  # At least 1 rotation
    }
    
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        detail = f"({len(archives)} archives)" if "created" in check.lower() else ""
        print(f"  {status} {check} {detail}")
    
    # Show archive files
    if archives:
        print("\n  📂 Archives created:")
        for archive in archives:
            size = archive.stat().st_size
            print(f"     • {archive.name} ({size:,} bytes)")
    
    return all(checks.values())

def test_integration():
    """Test 5: Full Integration Test"""
    print("\n" + "="*70)
    print("TEST 5: Full Integration")
    print("="*70)
    
    from core.ledger_engine import VestigiaLedger
    
    # Clean test
    test_file = Path('data/test_integration.json')
    test_file.unlink(missing_ok=True)
    
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=True)
    
    # Simulate real-world IAM operations
    operations = [
        ('agent_001', 'IDENTITY_VERIFIED', 'SUCCESS', 'User authenticated'),
        ('agent_001', 'TOKEN_ISSUED', 'SUCCESS', 'JWT token generated'),
        ('agent_002', 'ACCESS_REQUEST', 'BLOCKED', 'Insufficient permissions'),
        ('agent_003', 'THREAT_DETECTED', 'CRITICAL', 'SQL injection attempt'),
        ('system', 'SECURITY_SCAN', 'SUCCESS', 'Hourly scan completed')
    ]
    
    print("  Logging IAM operations...")
    for actor, action, status, evidence in operations:
        ledger.append_event(
            actor_id=actor,
            action_type=action,
            status=status,
            evidence=evidence
        )
        print(f"    • {action} ({status})")
    
    # Verify
    stats = ledger.get_statistics()
    critical_events = ledger.query_events(limit=100)
    critical_count = sum(1 for e in critical_events if e.get('status') == 'CRITICAL')
    
    checks = {
        "Events logged": stats['total_events'] >= 5,
        "Critical events tracked": critical_count > 0,
        "Ledger file exists": test_file.exists()
    }
    
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        print(f"  {status} {check}")
    
    # Cleanup
    test_file.unlink(missing_ok=True)
    
    return all(checks.values())

def generate_deployment_checklist():
    """Generate final deployment checklist"""
    print("\n" + "="*70)
    print("PRODUCTION DEPLOYMENT CHECKLIST")
    print("="*70)
    
    checklist = {
        "Phase 1: External Anchoring": [
            "Git anchor repository initialized",
            "Anchor verified working",
            "Optional: Remote Git backup configured"
        ],
        "Phase 2: Concurrency Control": [
            "portalocker installed",
            "File locking tested (50/50)",
            "Lock timeout configured (10s)"
        ],
        "Phase 3: Secret Management": [
            "VESTIGIA_SECRET_SALT in environment",
            ".env file in .gitignore",
            "Secret NOT in Git repository"
        ],
        "Phase 4: Storage Scalability": [
            "Ledger rotation configured",
            "Archive directory created",
            "Rotation threshold set (10,000)"
        ],
        "Phase 5: Integration": [
            "Dashboard updated",
            "CLI verified",
            "Monitoring configured"
        ]
    }
    
    for phase, items in checklist.items():
        print(f"\n{phase}:")
        for item in items:
            print(f"  ☐ {item}")

def main():
    """Run all production readiness tests"""
    print("="*70)
    print("🏭 VESTIGIA PRODUCTION READINESS VERIFICATION")
    print("="*70)
    
    results = {}
    
    try:
        results['Environment'] = test_environment_setup()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Environment'] = False
    
    try:
        results['Anchoring'] = test_external_anchoring()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Anchoring'] = False
    
    try:
        results['Concurrency'] = test_concurrency()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Concurrency'] = False
    
    try:
        results['Rotation'] = test_rotation()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Rotation'] = False
    
    try:
        results['Integration'] = test_integration()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Integration'] = False
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for test, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status} - {test}")
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - PRODUCTION READY!")
        generate_deployment_checklist()
    else:
        print("\n⚠️  Some tests failed - review errors above")
    
    return passed == total

if __name__ == "__main__":
    main()

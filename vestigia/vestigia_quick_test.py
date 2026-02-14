#!/usr/bin/env python3
"""
Quick Test Script - Validates all fixes
Run this to verify Vestigia is working correctly
"""

import json
from pathlib import Path
from core.ledger_engine import VestigiaLedger
from production_hardening import LedgerRotation, ExternalAnchor
from validator import VestigiaValidator

def test_1_basic_ledger():
    """Test 1: Basic ledger operations"""
    print("\n" + "="*70)
    print("TEST 1: Basic Ledger Operations")
    print("="*70)
    
    test_file = Path('data/test_basic.json')
    test_file.unlink(missing_ok=True)
    
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=False)
    
    # Add events
    for i in range(5):
        ledger.append_event(
            actor_id=f'agent_{i}',
            action_type='TEST',
            status='SUCCESS',
            evidence=f'Test event {i}'
        )
    
    stats = ledger.get_statistics()
    passed = stats['total_events'] == 6  # 5 + genesis
    
    print(f"  {'✅' if passed else '❌'} Events logged: {stats['total_events']}/6")
    
    # Validate
    validator = VestigiaValidator(str(test_file))
    report = validator.validate_full()
    
    print(f"  {'✅' if report.is_valid else '❌'} Hash chain integrity: {'VALID' if report.is_valid else 'INVALID'}")
    print(f"  {'✅' if len(report.issues) <= 2 else '❌'} Issues found: {len(report.issues)}")
    
    test_file.unlink(missing_ok=True)
    
    return passed and report.is_valid

def test_2_rotation():
    """Test 2: Ledger rotation"""
    print("\n" + "="*70)
    print("TEST 2: Ledger Rotation")
    print("="*70)
    
    test_file = Path('data/test_rotation_fixed.json')
    archive_path = Path('data/test_archives_fixed')
    
    test_file.unlink(missing_ok=True)
    if archive_path.exists():
        import shutil
        shutil.rmtree(archive_path)
    
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=False)
    anchor = ExternalAnchor(anchor_type='git', config={'repo_path': 'vestigia_anchors'})
    
    rotation = LedgerRotation(
        base_path=str(test_file),
        max_entries=10,
        archive_path=str(archive_path)
    )
    
    # Add 25 events (should trigger 2 rotations)
    rotations_done = 0
    for i in range(25):
        ledger.append_event(
            actor_id=f'agent_{i}',
            action_type='ROTATION_TEST',
            status='SUCCESS',
            evidence=f'Event {i}'
        )
        
        with open(test_file, 'r') as f:
            data = json.load(f)
        
        if rotation.should_rotate(len(data)):
            last_hash = data[-1]['integrity_hash']
            archive_file = rotation.rotate(
                current_hash=last_hash,
                entry_count=len(data),
                anchor=anchor
            )
            
            if archive_file and Path(archive_file).exists():
                rotations_done += 1
                print(f"  ✅ Rotation {rotations_done}: {Path(archive_file).name}")
    
    # Verify archives
    archives = list(archive_path.glob('ledger_*.json'))
    passed = len(archives) >= 2
    
    print(f"\n  {'✅' if passed else '❌'} Archives created: {len(archives)}/2+")
    
    for archive in archives:
        size = archive.stat().st_size
        print(f"     • {archive.name} ({size:,} bytes)")
    
    return passed

def test_3_validation():
    """Test 3: Validator detects tampering"""
    print("\n" + "="*70)
    print("TEST 3: Tamper Detection")
    print("="*70)
    
    test_file = Path('data/test_tamper.json')
    test_file.unlink(missing_ok=True)
    
    # Create ledger
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=False)
    
    for i in range(5):
        ledger.append_event(
            actor_id=f'agent_{i}',
            action_type='CRITICAL',
            status='CRITICAL',
            evidence=f'Critical event {i}'
        )
    
    # Validate clean ledger
    validator = VestigiaValidator(str(test_file))
    clean_report = validator.validate_full()
    
    print(f"  ✅ Clean ledger: {'VALID' if clean_report.is_valid else 'INVALID'}")
    
    # Tamper with entry
    with open(test_file, 'r') as f:
        data = json.load(f)
    
    data[2]['evidence'] = 'TAMPERED - EVIDENCE DELETED'
    
    with open(test_file, 'w') as f:
        json.dump(data, f, indent=4)
    
    # Validate tampered ledger
    tampered_report = validator.validate_full()
    
    detected = not tampered_report.is_valid
    print(f"  {'✅' if detected else '❌'} Tampering detected: {detected}")
    
    if detected:
        critical = tampered_report.get_critical_issues()
        print(f"  🚨 Critical issues: {len(critical)}")
        for issue in critical[:2]:
            print(f"     • {issue.issue_type} at entry {issue.entry_index}")
    
    test_file.unlink(missing_ok=True)
    
    return clean_report.is_valid and detected

def test_4_git_anchors():
    """Test 4: Git anchor verification"""
    print("\n" + "="*70)
    print("TEST 4: Git Anchor Verification")
    print("="*70)
    
    anchor = ExternalAnchor(anchor_type='git', config={'repo_path': 'vestigia_anchors'})
    
    # Create anchor
    test_hash = f"test_hash_{Path('data/test.json').stat().st_mtime if Path('data/test.json').exists() else 0}"
    anchor_id = anchor.anchor(test_hash, 100, {'test': 'validation'})
    
    anchor_created = anchor_id is not None and not anchor_id.startswith('failed_')
    print(f"  {'✅' if anchor_created else '❌'} Anchor created: {anchor_id[:16] if anchor_id else 'FAILED'}...")
    
    # Verify anchor
    verified = anchor.verify_anchor(anchor_id, test_hash) if anchor_created else False
    print(f"  {'✅' if verified else '❌'} Anchor verified: {verified}")
    
    return anchor_created and verified

def test_5_complete_integration():
    """Test 5: Complete integration"""
    print("\n" + "="*70)
    print("TEST 5: Complete Integration")
    print("="*70)
    
    test_file = Path('data/test_integration_final.json')
    test_file.unlink(missing_ok=True)
    
    # Create ledger with anchoring
    ledger = VestigiaLedger(str(test_file), enable_external_anchor=True)
    
    # Simulate real IAM operations
    operations = [
        ('user_001', 'IDENTITY_VERIFIED', 'SUCCESS', 'Authentication successful'),
        ('user_001', 'TOKEN_ISSUED', 'SUCCESS', 'JWT token generated'),
        ('attacker', 'ACCESS_REQUEST', 'BLOCKED', 'Unauthorized access attempt'),
        ('attacker', 'THREAT_DETECTED', 'CRITICAL', 'SQL injection detected'),
        ('system', 'SECURITY_SCAN', 'SUCCESS', 'Hourly scan completed')
    ]
    
    for actor, action, status, evidence in operations:
        ledger.append_event(
            actor_id=actor,
            action_type=action,
            status=status,
            evidence=evidence
        )
    
    # Validate
    validator = VestigiaValidator(str(test_file))
    report = validator.validate_full()
    
    print(f"  ✅ Operations logged: {report.total_entries}")
    print(f"  {'✅' if report.is_valid else '❌'} Validation: {'VALID' if report.is_valid else 'INVALID'}")
    print(f"  {'✅' if report.statistics else '❌'} Statistics generated: {len(report.statistics)} metrics")
    
    # Show statistics
    if report.statistics:
        print("\n  📊 Statistics:")
        for key, value in list(report.statistics.items())[:5]:
            print(f"     • {key}: {value}")
    
    test_file.unlink(missing_ok=True)
    
    return report.is_valid

def main():
    """Run all tests"""
    print("="*70)
    print("🧪 VESTIGIA COMPLETE TEST SUITE")
    print("="*70)
    
    results = {}
    
    try:
        results['Basic Operations'] = test_1_basic_ledger()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Basic Operations'] = False
    
    try:
        results['Rotation'] = test_2_rotation()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Rotation'] = False
    
    try:
        results['Tamper Detection'] = test_3_validation()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Tamper Detection'] = False
    
    try:
        results['Git Anchors'] = test_4_git_anchors()
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        results['Git Anchors'] = False
    
    try:
        results['Integration'] = test_5_complete_integration()
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
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - VESTIGIA IS PRODUCTION-READY!")
        print("\n📋 Next Steps:")
        print("  1. Review validator.py for forensic verification")
        print("  2. Update dashboard with validation status")
        print("  3. Prepare CISO presentation")
        print("  4. Submit DEF CON talk proposal")
    else:
        print("\n⚠️  Some tests failed - review errors above")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)

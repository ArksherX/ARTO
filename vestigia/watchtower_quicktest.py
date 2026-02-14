#!/usr/bin/env python3
"""
Quick test to verify Watchtower installation

Run this to check all dependencies and basic functionality
"""

import sys
from pathlib import Path

def test_dependencies():
    """Test required dependencies"""
    print("="*70)
    print("DEPENDENCY CHECK")
    print("="*70 + "\n")
    
    tests = []
    
    # Test watchdog
    try:
        import watchdog
        print("✅ watchdog installed")
        tests.append(True)
    except ImportError:
        print("❌ watchdog NOT installed")
        print("   Install: pip install watchdog")
        tests.append(False)
    
    # Test validator
    try:
        from validator import VestigiaValidator
        print("✅ validator.py found")
        tests.append(True)
    except ImportError:
        print("❌ validator.py NOT found")
        print("   Save validator.py to current directory")
        tests.append(False)
    
    # Test ledger engine
    try:
        from core.ledger_engine import VestigiaLedger
        print("✅ core/ledger_engine.py found")
        tests.append(True)
    except ImportError:
        print("❌ core/ledger_engine.py NOT found")
        print("   Check core/ directory")
        tests.append(False)
    
    # Test data directory
    data_dir = Path('data')
    if data_dir.exists():
        print("✅ data/ directory exists")
        tests.append(True)
    else:
        print("⚠️  data/ directory missing (will be created)")
        data_dir.mkdir(parents=True)
        print("   ✅ Created data/ directory")
        tests.append(True)
    
    return all(tests)

def test_basic_functionality():
    """Test basic Watchtower functionality"""
    print("\n" + "="*70)
    print("FUNCTIONALITY CHECK")
    print("="*70 + "\n")
    
    try:
        from watchtower import VestigiaWatchtower, ConsoleAlertHandler, SecurityState
        print("✅ Watchtower imports successful")
        
        # Create test ledger
        from core.ledger_engine import VestigiaLedger
        
        test_ledger = Path('data/test_watchtower.json')
        if test_ledger.exists():
            test_ledger.unlink()
        
        ledger = VestigiaLedger(str(test_ledger), enable_external_anchor=False)
        ledger.append_event('test', 'TEST', 'SUCCESS', 'Test event')
        print("✅ Test ledger created")
        
        # Create watchtower (don't start, just test instantiation)
        watchtower = VestigiaWatchtower(
            ledger_path=str(test_ledger),
            auto_lockdown=False
        )
        print("✅ Watchtower instantiation successful")
        
        # Test validator
        from validator import VestigiaValidator
        validator = VestigiaValidator(str(test_ledger))
        report = validator.validate_full()
        
        if report.is_valid:
            print("✅ Validator working correctly")
        else:
            print("❌ Validator failed on test ledger")
            return False
        
        # Cleanup
        test_ledger.unlink()
        print("✅ Cleanup successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def print_next_steps():
    """Print next steps"""
    print("\n" + "="*70)
    print("NEXT STEPS")
    print("="*70 + "\n")
    
    print("1. Start the Watchtower:")
    print("   python watchtower.py")
    print("")
    print("2. In another terminal, create a test event:")
    print("   python << 'EOF'")
    print("   from core.ledger_engine import VestigiaLedger")
    print("   ledger = VestigiaLedger('data/vestigia_ledger.json', enable_external_anchor=False)")
    print("   ledger.append_event('test', 'TEST', 'SUCCESS', 'Watchtower test')")
    print("   EOF")
    print("")
    print("3. Run the full demo:")
    print("   Terminal 1: python watchtower.py --no-lockdown")
    print("   Terminal 2: python demo_watchtower.py")
    print("")
    print("4. Check the setup guide:")
    print("   See 'Watchtower Setup & Integration Guide' artifact")

def main():
    """Run all tests"""
    print("\n🧪 VESTIGIA WATCHTOWER - QUICK TEST\n")
    
    deps_ok = test_dependencies()
    
    if not deps_ok:
        print("\n❌ Dependency check failed - install missing dependencies first")
        sys.exit(1)
    
    func_ok = test_basic_functionality()
    
    if not func_ok:
        print("\n❌ Functionality check failed - review errors above")
        sys.exit(1)
    
    print("\n" + "="*70)
    print("✅ ALL TESTS PASSED - WATCHTOWER READY")
    print("="*70)
    
    print_next_steps()

if __name__ == '__main__':
    main()

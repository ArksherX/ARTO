#!/usr/bin/env python3
"""
Vestigia Cleanup Script
Fixes corrupted ledgers and provides fresh start

Run: python cleanup_and_reset.py
"""

import sys
import shutil
from pathlib import Path
from datetime import datetime


def backup_existing_data():
    """Backup current data before cleanup"""
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"pre_cleanup_{timestamp}"
    
    files_to_backup = [
        'data/vestigia_ledger.json',
        'data/witness.hash',
        'demo_production.json'
    ]
    
    backed_up = []
    
    for file_path in files_to_backup:
        src = Path(file_path)
        if src.exists():
            dst = backup_dir / f"{backup_name}_{src.name}"
            shutil.copy2(src, dst)
            backed_up.append(str(dst))
            print(f"✅ Backed up: {file_path} → {dst}")
    
    return backed_up


def clean_corrupted_ledgers():
    """Remove corrupted ledgers"""
    files_to_clean = [
        'data/vestigia_ledger.json',
        'data/witness.hash',
        'demo_production.json',
        'compliance_report.json',
        'compliance_report.csv',
        'test_ledger.json',
        'test_production_ledger.json'
    ]
    
    cleaned = []
    
    for file_path in files_to_clean:
        path = Path(file_path)
        if path.exists():
            try:
                path.unlink()
                cleaned.append(str(path))
                print(f"🗑️  Removed: {file_path}")
            except PermissionError:
                print(f"⚠️  Permission denied: {file_path} (may need sudo)")
    
    return cleaned


def remove_hardening():
    """Remove any hardening that might prevent cleanup"""
    import subprocess
    
    print("\n🔓 Removing hardening...")
    
    try:
        result = subprocess.run(
            ['python', 'hardening.py', '--disable'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("✅ Hardening removed")
        else:
            print("⚠️  Hardening removal failed (may not have been enabled)")
    except Exception as e:
        print(f"⚠️  Could not remove hardening: {e}")


def initialize_fresh_ledger():
    """Initialize a fresh, clean ledger"""
    print("\n🆕 Initializing fresh ledger...")
    
    sys.path.insert(0, str(Path(__file__).parent))
    
    try:
        from core.ledger_engine import VestigiaLedger
        
        # Create new ledger (will auto-initialize)
        ledger = VestigiaLedger('data/vestigia_ledger.json')
        
        print("✅ Fresh ledger initialized")
        
        # Verify it's clean
        from security.verifier import ProductionVerifier
        verifier = ProductionVerifier('data/vestigia_ledger.json')
        result = verifier.verify_full()
        
        if result.is_valid:
            print("✅ Verification passed - ledger is clean")
        else:
            print("⚠️  Verification failed - something went wrong")
        
        return True
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        return False


def show_summary(backed_up, cleaned):
    """Show summary of operations"""
    print("\n" + "=" * 70)
    print("  🧹 Cleanup Summary")
    print("=" * 70 + "\n")
    
    print(f"Backed up: {len(backed_up)} files")
    for file in backed_up:
        print(f"  • {file}")
    
    print(f"\nCleaned: {len(cleaned)} files")
    for file in cleaned:
        print(f"  • {file}")
    
    print("\n" + "=" * 70)
    print("  ✅ Fresh Start Complete!")
    print("=" * 70 + "\n")
    
    print("You can now run:")
    print("  1. python cli.py verify                    # Should pass")
    print("  2. python cli.py log agent_001 TEST SUCCESS 'Fresh start'")
    print("  3. python production_demo.py               # Clean demo")
    print("")


def main():
    print("\n" + "=" * 70)
    print("  🧹 Vestigia Cleanup & Fresh Start")
    print("=" * 70 + "\n")
    
    print("⚠️  This will:")
    print("  1. Backup existing data")
    print("  2. Remove corrupted ledgers")
    print("  3. Remove hardening (if any)")
    print("  4. Initialize fresh ledger")
    print("")
    
    response = input("Continue? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        print("❌ Cancelled")
        return 1
    
    print("")
    
    # Step 1: Backup
    print("📦 Step 1: Backing up existing data...")
    backed_up = backup_existing_data()
    
    # Step 2: Remove hardening
    print("\n🔓 Step 2: Removing hardening...")
    remove_hardening()
    
    # Step 3: Clean
    print("\n🗑️  Step 3: Cleaning corrupted files...")
    cleaned = clean_corrupted_ledgers()
    
    # Step 4: Initialize fresh
    print("\n🆕 Step 4: Initializing fresh ledger...")
    success = initialize_fresh_ledger()
    
    if not success:
        print("\n⚠️  Fresh initialization failed")
        print("Try manually:")
        print("  rm data/vestigia_ledger.json")
        print("  python -c 'from core.ledger_engine import VestigiaLedger; VestigiaLedger()'")
        return 1
    
    # Summary
    show_summary(backed_up, cleaned)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Vestigia Complete Reset Script
Clears ALL state including shared audit log
"""
import os
import shutil
from pathlib import Path

def reset_vestigia():
    """Complete reset of Vestigia state"""
    
    print("=" * 70)
    print("🧹 VESTIGIA COMPLETE RESET")
    print("=" * 70)
    
    # Define paths
    vestigia_data = Path(__file__).parent / "data"
    shared_state = Path(__file__).parent.parent / "shared_state"
    shared_audit = shared_state / "shared_audit.log"
    
    items_to_delete = []
    
    # 1. Vestigia local data files
    if vestigia_data.exists():
        for pattern in ["*.json", "*.hash", "*.backup"]:
            items_to_delete.extend(vestigia_data.glob(pattern))
    
    # 2. Archives directory
    archives = vestigia_data / "archives"
    if archives.exists():
        items_to_delete.append(archives)
    
    # 3. Shared audit log (THE KEY ADDITION)
    if shared_audit.exists():
        items_to_delete.append(shared_audit)
    
    print("\nThis will delete:")
    print("  • All ledger files (data/*.json)")
    print("  • All witness files (data/*.hash)")
    print("  • All backup files (data/*.backup)")
    print("  • Archive directory (data/archives/)")
    print("  • Shared audit log (shared_state/shared_audit.log)")
    print(f"\nTotal items: {len(items_to_delete)}")
    
    response = input("\n⚠️  Are you sure you want to continue? (yes/no): ")
    
    if response.lower() != 'yes':
        print("❌ Reset cancelled")
        return
    
    print("\n🧹 Starting cleanup...")
    removed = 0
    
    for item in items_to_delete:
        try:
            if item.is_dir():
                shutil.rmtree(item)
                print(f"   ✅ Deleted: {item.name}/ directory")
            else:
                item.unlink()
                print(f"   ✅ Deleted: {item.name}")
            removed += 1
        except Exception as e:
            print(f"   ⚠️  Failed to delete {item.name}: {e}")
    
    print(f"\n✅ Cleanup complete - {removed} items removed")
    print("\n💡 Vestigia is now in clean state")
    print("   Next steps:")
    print("   1. Restart the suite: MODE=demo python3 suite_orchestrator.py")
    print("   2. Generate tokens in Tessera")
    print("   3. Check Vestigia dashboard")
    print("=" * 70)

if __name__ == "__main__":
    reset_vestigia()

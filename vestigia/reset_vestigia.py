#!/usr/bin/env python3
"""
Vestigia Reset Script

Cleans up all ledgers, witnesses, and temporary files to start fresh.
Useful before running demos or when witness gets out of sync.

Save as: vestigia/reset_vestigia.py
"""

import sys
from pathlib import Path
import shutil


def reset_vestigia():
    """Reset all Vestigia data files"""
    
    print("\n" + "="*70)
    print("🧹 VESTIGIA RESET SCRIPT")
    print("="*70 + "\n")
    
    print("This will delete:")
    print("  • All ledger files (data/*.json)")
    print("  • All witness files (data/*.hash)")
    print("  • All backup files (data/*.backup)")
    print("  • Archive directory (data/archives/)")
    
    response = input("\n⚠️  Are you sure you want to continue? (yes/no): ")
    
    if response.lower() not in ['yes', 'y']:
        print("\n❌ Reset cancelled")
        return
    
    print("\n🧹 Starting cleanup...\n")
    
    data_dir = Path('data')
    removed_count = 0
    
    # Remove ledger files
    for pattern in ['*.json', '*.hash', '*.backup']:
        for file in data_dir.glob(pattern):
            try:
                file.unlink()
                print(f"   ✅ Deleted: {file.name}")
                removed_count += 1
            except Exception as e:
                print(f"   ⚠️  Could not delete {file.name}: {e}")
    
    # Remove archives directory
    archives_dir = data_dir / 'archives'
    if archives_dir.exists():
        try:
            shutil.rmtree(archives_dir)
            print(f"   ✅ Deleted: archives/ directory")
            removed_count += 1
        except Exception as e:
            print(f"   ⚠️  Could not delete archives/: {e}")
    
    # Remove any temp files
    for file in data_dir.glob('*.tmp'):
        try:
            file.unlink()
            print(f"   ✅ Deleted: {file.name}")
            removed_count += 1
        except Exception as e:
            pass
    
    print(f"\n✅ Cleanup complete - {removed_count} items removed")
    print("\n💡 Vestigia is now in clean state")
    print("   You can now run:")
    print("   • python demo_complete.py")
    print("   • python rogue_agent.py")
    print("   • python demo_event_hooks.py")
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    try:
        reset_vestigia()
    except KeyboardInterrupt:
        print("\n\n⚠️  Reset interrupted")
        sys.exit(0)

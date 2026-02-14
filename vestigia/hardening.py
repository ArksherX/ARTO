#!/usr/bin/env python3
"""
Vestigia Hardening Script
OS-level protection for immutable ledgers

Save as: vestigia/hardening.py
Run: sudo python hardening.py --enable
"""

import os
import sys
import stat
import subprocess
from pathlib import Path
from typing import List, Tuple
import argparse


class VestigiaHardening:
    """
    OS-level hardening for Vestigia ledgers
    
    Features:
    - Read-only file permissions
    - Append-only attributes (Linux)
    - File immutability (Linux chattr +i)
    - Backup automation
    - Access auditing
    """
    
    def __init__(self, ledger_path: str, witness_path: str = "data/witness.hash"):
        self.ledger_path = Path(ledger_path)
        self.witness_path = Path(witness_path)
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self.is_linux = sys.platform.startswith('linux')
    
    def check_permissions(self) -> dict:
        """Check current file permissions"""
        results = {}
        
        for path_name, path in [('ledger', self.ledger_path), ('witness', self.witness_path)]:
            if not path.exists():
                results[path_name] = {'exists': False}
                continue
            
            st = path.stat()
            mode = st.st_mode
            
            results[path_name] = {
                'exists': True,
                'readable': bool(mode & stat.S_IRUSR),
                'writable': bool(mode & stat.S_IWUSR),
                'executable': bool(mode & stat.S_IXUSR),
                'mode': oct(stat.S_IMODE(mode)),
                'owner': st.st_uid,
                'group': st.st_gid
            }
        
        return results
    
    def set_read_only(self) -> Tuple[bool, str]:
        """
        Set files to read-only (chmod 444)
        
        Prevents accidental modification
        """
        try:
            for path in [self.ledger_path, self.witness_path]:
                if path.exists():
                    path.chmod(0o444)  # r--r--r--
            
            return True, "Files set to read-only (444)"
        except PermissionError:
            return False, "Permission denied - need sudo/root"
        except Exception as e:
            return False, f"Error: {e}"
    
    def set_append_only_linux(self) -> Tuple[bool, str]:
        """
        Set append-only attribute (Linux only)
        
        Requires root privileges
        Uses chattr +a (allows append, prevents delete/modify)
        """
        if not self.is_linux:
            return False, "Append-only mode only available on Linux"
        
        if not self.is_root:
            return False, "Requires root/sudo privileges"
        
        try:
            subprocess.run(
                ['chattr', '+a', str(self.ledger_path)],
                check=True,
                capture_output=True
            )
            return True, f"Append-only enabled for {self.ledger_path}"
        except subprocess.CalledProcessError as e:
            return False, f"chattr failed: {e.stderr.decode()}"
        except FileNotFoundError:
            return False, "chattr command not found"
    
    def set_immutable_linux(self) -> Tuple[bool, str]:
        """
        Set immutable attribute (Linux only)
        
        Requires root privileges
        Uses chattr +i (prevents ANY changes, even by root)
        """
        if not self.is_linux:
            return False, "Immutable mode only available on Linux"
        
        if not self.is_root:
            return False, "Requires root/sudo privileges"
        
        try:
            subprocess.run(
                ['chattr', '+i', str(self.witness_path)],
                check=True,
                capture_output=True
            )
            return True, f"Immutable flag set for {self.witness_path}"
        except subprocess.CalledProcessError as e:
            return False, f"chattr failed: {e.stderr.decode()}"
        except FileNotFoundError:
            return False, "chattr command not found"
    
    def remove_attributes_linux(self) -> Tuple[bool, str]:
        """
        Remove special attributes (for maintenance)
        
        Requires root privileges
        """
        if not self.is_linux:
            return False, "Only available on Linux"
        
        if not self.is_root:
            return False, "Requires root/sudo privileges"
        
        try:
            for path in [self.ledger_path, self.witness_path]:
                if path.exists():
                    subprocess.run(
                        ['chattr', '-a', '-i', str(path)],
                        check=True,
                        capture_output=True
                    )
            return True, "All attributes removed"
        except subprocess.CalledProcessError as e:
            return False, f"chattr failed: {e.stderr.decode()}"
    
    def create_backup(self, backup_dir: str = "backups") -> Tuple[bool, str]:
        """Create timestamped backup of ledger"""
        from datetime import datetime, UTC
        import shutil
        
        backup_path = Path(backup_dir)
        backup_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        
        try:
            # Backup ledger
            if self.ledger_path.exists():
                ledger_backup = backup_path / f"ledger_{timestamp}.json"
                shutil.copy2(self.ledger_path, ledger_backup)
            
            # Backup witness
            if self.witness_path.exists():
                witness_backup = backup_path / f"witness_{timestamp}.hash"
                shutil.copy2(self.witness_path, witness_backup)
            
            return True, f"Backup created in {backup_path}"
        except Exception as e:
            return False, f"Backup failed: {e}"
    
    def print_status(self):
        """Print current hardening status"""
        print("\n" + "=" * 70)
        print("  🔒 Vestigia Hardening Status")
        print("=" * 70 + "\n")
        
        print(f"System: {'Linux' if self.is_linux else sys.platform}")
        print(f"Privileges: {'root' if self.is_root else 'user'}\n")
        
        perms = self.check_permissions()
        
        for name, info in perms.items():
            print(f"{name.upper()}:")
            if not info['exists']:
                print("  ❌ File not found\n")
                continue
            
            print(f"  📄 Path: {self.ledger_path if name == 'ledger' else self.witness_path}")
            print(f"  🔐 Mode: {info['mode']}")
            print(f"  ✓ Readable: {info['readable']}")
            print(f"  ✓ Writable: {info['writable']}")
            print()
        
        # Check Linux attributes
        if self.is_linux:
            print("Linux Attributes:")
            for path_name, path in [('Ledger', self.ledger_path), ('Witness', self.witness_path)]:
                if path.exists():
                    try:
                        result = subprocess.run(
                            ['lsattr', str(path)],
                            capture_output=True,
                            text=True
                        )
                        attrs = result.stdout.split()[0] if result.returncode == 0 else "N/A"
                        print(f"  {path_name}: {attrs}")
                    except FileNotFoundError:
                        print(f"  {path_name}: lsattr not available")
        
        print("\n" + "=" * 70)


def main():
    """CLI for hardening operations"""
    parser = argparse.ArgumentParser(
        description="Vestigia Ledger Hardening Tool"
    )
    parser.add_argument(
        'ledger_path',
        nargs='?',
        default='data/vestigia_ledger.json',
        help='Path to ledger file'
    )
    parser.add_argument(
        '--witness',
        default='data/witness.hash',
        help='Path to witness file'
    )
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show current hardening status'
    )
    parser.add_argument(
        '--enable',
        action='store_true',
        help='Enable all available protections'
    )
    parser.add_argument(
        '--readonly',
        action='store_true',
        help='Set files to read-only (chmod 444)'
    )
    parser.add_argument(
        '--append-only',
        action='store_true',
        help='Enable append-only mode (Linux, requires root)'
    )
    parser.add_argument(
        '--immutable',
        action='store_true',
        help='Make witness immutable (Linux, requires root)'
    )
    parser.add_argument(
        '--disable',
        action='store_true',
        help='Remove all protections (for maintenance)'
    )
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create backup before operations'
    )
    
    args = parser.parse_args()
    
    # Initialize hardening
    hardening = VestigiaHardening(args.ledger_path, args.witness)
    
    # Show status
    if args.status or not any([args.enable, args.readonly, args.append_only, args.immutable, args.disable]):
        hardening.print_status()
        return 0
    
    print("\n" + "=" * 70)
    print("  🔒 Vestigia Hardening Operations")
    print("=" * 70 + "\n")
    
    # Create backup if requested
    if args.backup:
        success, msg = hardening.create_backup()
        print(f"{'✅' if success else '❌'} Backup: {msg}")
    
    # Disable protections (for maintenance)
    if args.disable:
        if not hardening.is_root:
            print("❌ Disable requires root/sudo privileges")
            return 1
        
        success, msg = hardening.remove_attributes_linux()
        print(f"{'✅' if success else '❌'} Remove attributes: {msg}")
        return 0
    
    # Enable protections
    operations = []
    
    if args.readonly or args.enable:
        operations.append(('Read-only', hardening.set_read_only))
    
    if args.append_only or args.enable:
        operations.append(('Append-only', hardening.set_append_only_linux))
    
    if args.immutable or args.enable:
        operations.append(('Immutable', hardening.set_immutable_linux))
    
    # Execute operations
    for name, operation in operations:
        success, msg = operation()
        print(f"{'✅' if success else '⚠️ '} {name}: {msg}")
    
    print("\n" + "=" * 70)
    print("⚠️  IMPORTANT:")
    print("  - Append-only: Ledger can be appended but not modified/deleted")
    print("  - Immutable: Witness cannot be changed (even by root)")
    print("  - Use --disable to remove protections for maintenance")
    print("=" * 70 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

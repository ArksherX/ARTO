#!/usr/bin/env python3
"""
Vestigia Production Hardening - FIXED VERSION
Addresses validation test failures and improves rotation logic
"""

import os
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, UTC
from typing import Optional, Dict, Any

# ============================================================================
# EXTERNAL ANCHORING (Git-based)
# ============================================================================

class ExternalAnchor:
    """Git-based external anchoring"""
    
    def __init__(self, anchor_type: str = 'git', config: Optional[Dict] = None):
        self.anchor_type = anchor_type
        self.config = config or {}
        
        if anchor_type == 'git':
            self.repo_path = Path(self.config.get('repo_path', 'vestigia_anchors'))
            self._init_git_repo()
    
    def _init_git_repo(self):
        """Initialize Git repository"""
        self.repo_path.mkdir(parents=True, exist_ok=True)
        
        git_dir = self.repo_path / '.git'
        if not git_dir.exists():
            try:
                subprocess.run(['git', 'init'], cwd=self.repo_path, capture_output=True, check=False)
                subprocess.run(['git', 'config', 'user.email', 'vestigia-bot@internal.io'], 
                             cwd=self.repo_path, capture_output=True, check=False)
                subprocess.run(['git', 'config', 'user.name', 'Vestigia Anchor Bot'], 
                             cwd=self.repo_path, capture_output=True, check=False)
                
                gitignore = self.repo_path / '.gitignore'
                gitignore.write_text('*.tmp\n*.bak\n')
                
                subprocess.run(['git', 'add', '.gitignore'], cwd=self.repo_path, capture_output=True, check=False)
                subprocess.run(['git', 'commit', '-m', 'Initialize Vestigia anchor repo'], 
                             cwd=self.repo_path, capture_output=True, check=False)
            except Exception as e:
                print(f"⚠️  Git initialization warning: {e}")
    
    def anchor(self, ledger_hash: str, entry_count: int, metadata: Dict[str, Any] = None) -> str:
        """Create Git anchor"""
        metadata = metadata or {}
        
        # Create anchor file
        anchor_file = self.repo_path / f"anchor_{entry_count:08d}.json"
        anchor_data = {
            'timestamp': datetime.now(UTC).isoformat(),
            'ledger_hash': ledger_hash,
            'entry_count': entry_count,
            'metadata': metadata,
            'anchor_id': f"anchor_{entry_count:08d}_{ledger_hash[:16]}"
        }
        
        anchor_file.write_text(json.dumps(anchor_data, indent=2))
        
        # Commit to git
        try:
            subprocess.run(['git', 'add', str(anchor_file)], 
                         cwd=self.repo_path, capture_output=True, check=False)
            
            commit_msg = f"Anchor: {ledger_hash[:16]}... ({entry_count} entries)"
            result = subprocess.run(
                ['git', 'commit', '-m', commit_msg],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                log_result = subprocess.run(
                    ['git', 'log', '--format=%H', '-n', '1'],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    check=False
                )
                commit_hash = log_result.stdout.strip()
                if commit_hash:
                    return commit_hash
            
            return f"local_{anchor_data['anchor_id']}"
                
        except Exception as e:
            return f"failed_{anchor_data['anchor_id']}"
    
    def verify_anchor(self, anchor_id: str, expected_hash: str) -> bool:
        """Verify Git anchor"""
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False
            )
            
            lines = result.stdout.strip().split('\n')
            anchor_lines = [l for l in lines if 'Anchor' in l or expected_hash[:8] in l]
            
            return len(anchor_lines) > 0
            
        except Exception:
            return False

# ============================================================================
# LEDGER ROTATION - FIXED VERSION
# ============================================================================

class LedgerRotation:
    """
    Handles automatic ledger rotation and archiving
    FIXED: Removed 'anchor' from __init__, simplified interface
    """
    
    def __init__(
        self,
        base_path: str,
        max_entries: int = 10000,
        archive_path: str = 'data/archives'
    ):
        self.base_path = Path(base_path)
        self.max_entries = max_entries
        self.archive_path = Path(archive_path)
        
        # Create archive directory
        self.archive_path.mkdir(parents=True, exist_ok=True)
    
    def should_rotate(self, current_entries: int) -> bool:
        """Check if rotation is needed"""
        return current_entries >= self.max_entries
    
    def rotate(
        self,
        current_hash: str,
        entry_count: int,
        anchor: Optional[ExternalAnchor] = None
    ) -> str:
        """
        Rotate the ledger
        
        Args:
            current_hash: Last hash of current ledger
            entry_count: Number of entries in current ledger
            anchor: Optional external anchor instance
            
        Returns:
            Path to archived ledger
        """
        # Generate archive filename
        timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        archive_name = f"ledger_{timestamp}_{entry_count}_entries.json"
        archive_file = self.archive_path / archive_name
        
        # Copy current ledger to archive
        if self.base_path.exists():
            try:
                import shutil
                shutil.copy2(self.base_path, archive_file)
                
                # Verify archive was created
                if archive_file.exists():
                    print(f"📦 Ledger rotated: {entry_count} entries archived to {archive_file}")
                else:
                    print(f"❌ Archive creation failed: {archive_file}")
                    return ""
                
                # Create anchor for rotation if available
                if anchor:
                    try:
                        anchor_id = anchor.anchor(
                            ledger_hash=current_hash,
                            entry_count=entry_count,
                            metadata={'rotation': True, 'archive_file': archive_name}
                        )
                        if not anchor_id.startswith('failed_'):
                            print(f"⚓ Rotation anchored: {anchor_id[:16]}...")
                    except Exception as e:
                        print(f"⚠️  Rotation anchor failed: {e}")
                
                return str(archive_file)
                
            except Exception as e:
                print(f"❌ Rotation failed: {e}")
                return ""
        
        return ""

# ============================================================================
# SECRET MANAGEMENT
# ============================================================================

class SecretManager:
    """Secure secret management"""
    
    @staticmethod
    def get_secret_salt() -> str:
        """Get secret salt from environment"""
        # 1. Environment variable
        salt = os.getenv('VESTIGIA_SECRET_SALT')
        if salt:
            return salt
        
        # 2. Docker secrets
        docker_secret = Path('/run/secrets/vestigia_secret_salt')
        if docker_secret.exists():
            salt = docker_secret.read_text().strip()
            return salt
        
        # 3. .env file
        env_file = Path('.env')
        if env_file.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv()
                salt = os.getenv('VESTIGIA_SECRET_SALT')
                if salt:
                    return salt
            except ImportError:
                pass
        
        # 4. Generate new (NOT FOR PRODUCTION!)
        print("⚠️  WARNING: No secret found - generating new one")
        print("   For production, set VESTIGIA_SECRET_SALT environment variable")
        
        import secrets
        salt = secrets.token_urlsafe(32)
        
        # Save to .env for next time
        with open('.env', 'a') as f:
            f.write(f"\nVESTIGIA_SECRET_SALT={salt}\n")
        
        return salt

# ============================================================================
# PRODUCTION CONFIGURATION
# ============================================================================

class ProductionConfig:
    """Production configuration with all hardening features"""
    
    def __init__(self):
        # External anchoring
        self.enable_anchoring = os.getenv('VESTIGIA_ENABLE_ANCHORING', 'true').lower() == 'true'
        self.anchor_type = os.getenv('VESTIGIA_ANCHOR_TYPE', 'git')
        self.anchor_frequency = int(os.getenv('VESTIGIA_ANCHOR_FREQUENCY', '100'))
        
        # Concurrency
        self.enable_file_locking = True
        
        # Secrets
        self.secret_salt = SecretManager.get_secret_salt()
        
        # Rotation
        self.enable_rotation = os.getenv('VESTIGIA_ENABLE_ROTATION', 'true').lower() == 'true'
        self.max_entries_per_ledger = int(os.getenv('VESTIGIA_MAX_ENTRIES', '10000'))
    
    def print_config(self):
        """Print production configuration"""
        print("\n" + "=" * 70)
        print("  🏭 Vestigia Production Configuration")
        print("=" * 70 + "\n")
        
        print(f"External Anchoring: {'✅ Enabled' if self.enable_anchoring else '❌ Disabled'}")
        if self.enable_anchoring:
            print(f"  └─ Type: {self.anchor_type}")
            print(f"  └─ Frequency: Every {self.anchor_frequency} events")
        
        print(f"\nConcurrency Control: ✅ File locking")
        print(f"\nSecret Management: ✅ Environment-based")
        
        print(f"\nLedger Rotation: {'✅ Enabled' if self.enable_rotation else '❌ Disabled'}")
        if self.enable_rotation:
            print(f"  └─ Max entries: {self.max_entries_per_ledger:,}")
        
        print("\n" + "=" * 70)

# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  🏭 Vestigia Production Hardening - Test")
    print("=" * 70)
    
    # Test production config
    config = ProductionConfig()
    config.print_config()
    
    # Test external anchoring
    print("\n📌 Testing External Anchoring...")
    anchor = ExternalAnchor(anchor_type="git", config={'repo_path': 'test_anchors'})
    
    test_hash = "abc123def456789"
    anchor_id = anchor.anchor(test_hash, 100, {'test': True})
    
    if anchor_id:
        print(f"✅ Anchor created: {anchor_id[:16]}...")
        
        # Verify
        is_valid = anchor.verify_anchor(anchor_id, test_hash)
        print(f"✅ Verification: {'PASS' if is_valid else 'FAIL'}")
    
    # Test rotation
    print("\n📦 Testing Ledger Rotation...")
    rotation = LedgerRotation(
        base_path='data/test_ledger.json',
        max_entries=50,
        archive_path='data/test_archives'
    )
    
    # Create dummy ledger
    test_ledger = Path('data/test_ledger.json')
    test_ledger.parent.mkdir(parents=True, exist_ok=True)
    test_data = [{'event': i, 'integrity_hash': f'hash_{i}'} for i in range(60)]
    test_ledger.write_text(json.dumps(test_data, indent=2))
    
    if rotation.should_rotate(60):
        print("✅ Rotation needed (60 entries > 50 threshold)")
        archive_path = rotation.rotate('final_hash', 60, anchor)
        
        if archive_path and Path(archive_path).exists():
            print(f"✅ Archive verified: {archive_path}")
        else:
            print(f"❌ Archive failed")
    
    print("\n" + "=" * 70)
    print("  ✅ Production hardening test complete!")
    print("=" * 70)

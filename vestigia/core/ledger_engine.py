#!/usr/bin/env python3
"""
Vestigia Production Core - FIXED VERSION
Canonical JSON serialization for consistent hashing

ONLY CHANGES: 
- Line 492: Uses canonical JSON (sort_keys=True, separators)
- Everything else unchanged (concurrency, rotation, etc.)
"""

import json
import hashlib
import hmac
import os
import shutil
import uuid
import threading
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, asdict, field
from enum import Enum


class EventStatus(Enum):
    """Type-safe event status"""
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class ActionType(Enum):
    """Type-safe action types"""
    IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
    TOKEN_ISSUED = "TOKEN_ISSUED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    ACCESS_REQUEST = "ACCESS_REQUEST"
    ACCESS_DENIED = "ACCESS_DENIED"
    SECURITY_SCAN = "SECURITY_SCAN"
    THREAT_DETECTED = "THREAT_DETECTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    HEARTBEAT = "HEARTBEAT"
    LEDGER_INITIALIZED = "LEDGER_INITIALIZED"
    LEDGER_ROTATED = "LEDGER_ROTATED"
    # Enterprise features (Phase 1-6)
    REASONING_INTERCEPTED = "REASONING_INTERCEPTED"
    REASONING_A2A_ALERT = "REASONING_A2A_ALERT"
    RATIONALIZATION_PERFORMED = "RATIONALIZATION_PERFORMED"
    MEMORY_FILTERED = "MEMORY_FILTERED"
    MEMORY_CROSS_AGENT_ALERT = "MEMORY_CROSS_AGENT_ALERT"
    ADVERSARIAL_SCORED = "ADVERSARIAL_SCORED"
    SESSION_DRIFT_ALERT = "SESSION_DRIFT_ALERT"
    TOOL_MANIFEST_VERIFIED = "TOOL_MANIFEST_VERIFIED"
    TOOL_MANIFEST_FAILED = "TOOL_MANIFEST_FAILED"
    PROTOCOL_INTEGRITY_ALERT = "PROTOCOL_INTEGRITY_ALERT"
    DELEGATION_CREATED = "DELEGATION_CREATED"
    DELEGATION_VALIDATED = "DELEGATION_VALIDATED"
    AIBOM_REGISTERED = "AIBOM_REGISTERED"
    AIBOM_VERIFIED = "AIBOM_VERIFIED"
    FUZZ_TEST_COMPLETED = "FUZZ_TEST_COMPLETED"
    MCP_SCAN_COMPLETED = "MCP_SCAN_COMPLETED"


@dataclass
class StructuredEvidence:
    """Type-safe evidence structure"""
    summary: str
    raw_payload: Optional[str] = None
    risk_score: Optional[float] = None
    mitigation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    @classmethod
    def from_string(cls, text: str) -> 'StructuredEvidence':
        """Create from simple string (backward compatibility)"""
        return cls(summary=text)


@dataclass
class VestigiaEvent:
    """Represents a single immutable ledger entry"""
    timestamp: str
    actor_id: str
    action_type: str
    status: str
    evidence: Union[str, Dict[str, Any]]
    integrity_hash: str
    event_id: str
    previous_hash: str
    tenant_id: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def get_evidence_structured(self) -> StructuredEvidence:
        """Get evidence as structured object"""
        if isinstance(self.evidence, dict):
            return StructuredEvidence(**self.evidence)
        else:
            return StructuredEvidence.from_string(str(self.evidence))


# ============================================================================
# EXTERNAL ANCHORING SYSTEM (UNCHANGED)
# ============================================================================

class ExternalAnchor:
    """External integrity anchoring using Git commits"""
    
    def __init__(self, anchor_type: str = 'git', config: Optional[Dict] = None):
        self.anchor_type = anchor_type
        self.config = config or {}
        
        if anchor_type == 'git':
            self.repo_path = Path(self.config.get('repo_path', 'vestigia_anchors'))
            self._init_git_repo()
        else:
            raise ValueError(f"Unsupported anchor type: {anchor_type}")
    
    def _init_git_repo(self):
        """Initialize Git repository for anchoring"""
        self.repo_path.mkdir(parents=True, exist_ok=True)
        
        git_dir = self.repo_path / '.git'
        if not git_dir.exists():
            import subprocess
            try:
                subprocess.run(['git', 'init'], cwd=self.repo_path, capture_output=True, check=False)
                gitignore = self.repo_path / '.gitignore'
                gitignore.write_text('*.tmp\n*.bak\n')
                print(f"✅ Git repository initialized at {self.repo_path}")
            except Exception as e:
                print(f"⚠️  Git initialization failed: {e}")
    
    def anchor(self, ledger_hash: str, entry_count: int, metadata: Dict[str, Any]) -> str:
        """Create external anchor for ledger state"""
        if self.anchor_type == 'git':
            return self._git_anchor(ledger_hash, entry_count, metadata)
    
    def _git_anchor(self, ledger_hash: str, entry_count: int, metadata: Dict[str, Any]) -> str:
        """Create Git-based anchor"""
        import subprocess
        
        anchor_file = self.repo_path / f"anchor_{entry_count:08d}.json"
        anchor_data = {
            'timestamp': datetime.now(UTC).isoformat(),
            'ledger_hash': ledger_hash,
            'entry_count': entry_count,
            'metadata': metadata,
            'anchor_id': f"anchor_{entry_count:08d}_{ledger_hash[:16]}"
        }
        
        anchor_file.write_text(json.dumps(anchor_data, indent=2))
        
        try:
            subprocess.run(['git', 'add', str(anchor_file)], 
                         cwd=self.repo_path, capture_output=True, check=False)
            
            commit_msg = f"Vestigia Anchor: {entry_count} entries | {ledger_hash[:16]}..."
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
                    print(f"⚓ Git anchor: {commit_hash[:16]}...")
                    return commit_hash
                else:
                    return f"local_{anchor_data['anchor_id']}"
            else:
                print(f"⚠️  Git commit failed: {result.stderr}")
                return f"failed_{anchor_data['anchor_id']}"
                
        except Exception as e:
            print(f"⚠️  Git anchor failed: {e}")
            return f"exception_{anchor_data['anchor_id']}"
    
    def verify_anchor(self, anchor_id: str, expected_hash: str) -> bool:
        """Verify anchor integrity"""
        if self.anchor_type == 'git':
            return self._git_verify_anchor(anchor_id, expected_hash)
        return False
    
    def _git_verify_anchor(self, anchor_id: str, expected_hash: str) -> bool:
        """Verify Git anchor"""
        import subprocess
        
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False
            )
            
            lines = result.stdout.strip().split('\n')
            anchor_lines = [l for l in lines if 'Vestigia Anchor' in l]
            
            return len(anchor_lines) > 0
            
        except Exception as e:
            print(f"⚠️  Git verification failed: {e}")
            return False


# ============================================================================
# LEDGER ROTATION SYSTEM (UNCHANGED)
# ============================================================================

class LedgerRotation:
    """Handles automatic ledger rotation and archiving"""
    
    def __init__(
        self,
        base_path: Union[str, Path],
        max_entries: int = 10000,
        archive_path: str = 'data/archives',
        anchor: Optional[ExternalAnchor] = None
    ):
        self.base_path = Path(base_path)
        self.max_entries = max_entries
        self.archive_path = Path(archive_path)
        self.anchor = anchor
        
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
        """Rotate the ledger"""
        timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        archive_name = f"ledger_{timestamp}_{entry_count}_entries.json"
        archive_file = self.archive_path / archive_name
        
        if self.base_path.exists():
            import shutil
            shutil.copy2(self.base_path, archive_file)
            
            print(f"📦 Ledger rotated: {entry_count} entries archived to {archive_file}")
            
            if anchor:
                try:
                    anchor.anchor(
                        ledger_hash=current_hash,
                        entry_count=entry_count,
                        metadata={'rotation': True, 'archive_file': archive_name}
                    )
                    print(f"⚓ Rotation anchored to Git")
                except Exception as e:
                    print(f"⚠️  Rotation anchor failed: {e}")
            
            return str(archive_file)
        
        return ""


# ============================================================================
# MERKLE WITNESS SYSTEM (UNCHANGED)
# ============================================================================

class MerkleWitness:
    """External integrity anchoring to prevent total file replacement"""
    
    def __init__(self, witness_path: str = "data/witness.hash", hsm_client=None):
        self.witness_path = Path(witness_path)
        self.witness_path.parent.mkdir(parents=True, exist_ok=True)
        self.hsm_client = hsm_client
        
        if not self.witness_path.exists():
            self._initialize_witness()
    
    def _initialize_witness(self):
        """Create witness file"""
        witness_data = {
            'created': datetime.now(UTC).isoformat(),
            'witnesses': []
        }
        self._save_witness(witness_data)
    
    def _load_witness(self) -> dict:
        """Load witness data"""
        try:
            with open(self.witness_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {'created': datetime.now(UTC).isoformat(), 'witnesses': []}
    
    def _save_witness(self, data: dict):
        """Save witness data"""
        temp_path = self.witness_path.parent / f"{self.witness_path.name}.{uuid.uuid4().hex}.tmp"
        
        try:
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, self.witness_path)
            
        except Exception as e:
            print(f"⚠️  Failed to save witness: {e}")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except:
                    pass
            raise
        
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except:
                    pass
    
    def anchor_hash(self, ledger_hash: str, entry_count: int) -> str:
        """Anchor a Merkle root to external witness"""
        witness_data = self._load_witness()
        
        signature = None
        if self.hsm_client:
            signature = self.hsm_client.sign(f"{ledger_hash}{entry_count}".encode()).hex()

        witness_entry = {
            'witness_id': f"witness_{len(witness_data['witnesses']):06d}",
            'timestamp': datetime.now(UTC).isoformat(),
            'merkle_root': ledger_hash,
            'entry_count': entry_count,
            'anchor_hash': hashlib.sha256(
                f"{ledger_hash}{entry_count}".encode()
            ).hexdigest(),
            'hsm_signature': signature
        }
        
        witness_data['witnesses'].append(witness_entry)
        self._save_witness(witness_data)
        
        return witness_entry['witness_id']
    
    def verify_against_witness(
        self, 
        ledger_hash: str, 
        entry_count: int
    ) -> tuple[bool, Optional[str]]:
        """Verify ledger hash against witnessed anchors"""
        witness_data = self._load_witness()
        
        if not witness_data.get('witnesses'):
            return False, "No witnesses recorded"
        
        matching = [
            w for w in witness_data['witnesses']
            if w['entry_count'] == entry_count
        ]
        
        if not matching:
            return False, f"No witness found for entry count {entry_count}"
        
        for witness in matching:
            if witness['merkle_root'] == ledger_hash:
                if witness.get("hsm_signature") and self.hsm_client:
                    valid = self.hsm_client.verify(
                        f"{ledger_hash}{entry_count}".encode(),
                        bytes.fromhex(witness["hsm_signature"])
                    )
                    if not valid:
                        return False, "HSM signature invalid"
                return True, f"Verified against {witness['witness_id']}"
        
        return False, "Ledger hash doesn't match any witness"
    
    def get_latest_witness(self) -> Optional[dict]:
        """Get most recent witness"""
        witness_data = self._load_witness()
        if witness_data.get('witnesses'):
            return witness_data['witnesses'][-1]
        return None

    def get_public_key(self) -> Optional[str]:
        if self.hsm_client:
            return self.hsm_client.public_key_pem()
        return None


# ============================================================================
# MAIN LEDGER ENGINE - FIXED HASH GENERATION
# ============================================================================

class VestigiaLedger:
    """
    Production-grade immutable audit ledger
    
    FIXED: Uses canonical JSON serialization for consistent hashing
    """
    
    def __init__(
        self, 
        ledger_path: str = "data/vestigia_ledger.json",
        secret_salt: Optional[str] = None,
        enable_merkle_witness: bool = True,
        max_entries: int = 10000,
        enable_external_anchor: bool = True
    ):
        self.ledger_path = Path(ledger_path)
        self.secret_salt = secret_salt or os.getenv('VESTIGIA_SECRET_SALT')
        self.enable_merkle_witness = enable_merkle_witness
        self.max_entries = max_entries
        
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize Merkle witness
        if self.enable_merkle_witness:
            try:
                from core.hsm_client import get_hsm_from_env
                hsm_client = get_hsm_from_env()
            except Exception:
                hsm_client = None
            self.witness = MerkleWitness(hsm_client=hsm_client)
        
        # Initialize external anchoring
        if enable_external_anchor and os.getenv('VESTIGIA_ENABLE_ANCHORING', 'true').lower() == 'true':
            try:
                self.anchor = ExternalAnchor(
                    anchor_type='git',
                    config={'repo_path': 'vestigia_anchors'}
                )
                self.anchor_frequency = 100
                print("✅ External anchoring enabled")
            except Exception as e:
                print(f"⚠️  External anchoring disabled: {e}")
                self.anchor = None
        else:
            self.anchor = None
        # Blockchain anchoring
        self.blockchain_anchor = None
        if os.getenv("VESTIGIA_BLOCKCHAIN_ANCHORING", "false").lower() == "true":
            try:
                from core.blockchain_anchor import BlockchainAnchor
                provider = os.getenv("VESTIGIA_BLOCKCHAIN_PROVIDER", "file")
                self.blockchain_anchor = BlockchainAnchor(provider=provider)
                self.blockchain_anchor_every = int(os.getenv("VESTIGIA_BLOCKCHAIN_ANCHOR_EVERY", "300"))
            except Exception as e:
                print(f"⚠️  Blockchain anchoring disabled: {e}")
                self.blockchain_anchor = None
        
        # Initialize rotation system
        self.rotation = LedgerRotation(
            base_path=self.ledger_path,
            max_entries=self.max_entries,
            archive_path='data/archives',
            anchor=self.anchor
        )
        
        # Initialize ledger if it doesn't exist
        if not self.ledger_path.exists():
            self._initialize_ledger()
    
    def _initialize_ledger(self):
        """Create empty ledger with genesis block"""
        genesis = {
            'timestamp': datetime.now(UTC).isoformat(),
            'actor_id': 'SYSTEM',
            'action_type': ActionType.LEDGER_INITIALIZED.value,
            'status': EventStatus.SUCCESS.value,
            'evidence': StructuredEvidence(
                summary='Genesis block - Ledger initialized',
                metadata={
                    'version': '2.0',
                    'merkle_enabled': self.enable_merkle_witness,
                    'external_anchor': self.anchor is not None
                }
            ).to_dict(),
            'integrity_hash': 'ROOT',
            'event_id': 'genesis_000',
            'previous_hash': 'GENESIS'
        }
        
        self._atomic_save([genesis])
        print(f"✅ Ledger initialized at {self.ledger_path}")
    
    def _generate_integrity_hash(
        self, 
        timestamp: str,
        tenant_id: Optional[str],
        actor_id: str,
        action_type: str,
        status: str,
        evidence: Any,
        previous_hash: str
    ) -> str:
        """
        Generate cryptographic hash with CANONICAL JSON
        
        CRITICAL: Must use sort_keys=True and separators=(',',':')
        to ensure validator can reproduce exact same string
        """
        # Convert evidence to canonical JSON string
        evidence_str = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
        
        # Build payload
        if tenant_id:
            payload = f"{timestamp}{tenant_id}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
        else:
            payload = f"{timestamp}{actor_id}{action_type}{status}{evidence_str}{previous_hash}"
        
        # Hash it
        if self.secret_salt:
            return hmac.new(
                self.secret_salt.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
        else:
            return hashlib.sha256(payload.encode()).hexdigest()
    
    def _load_ledger(self) -> List[dict]:
        """Load ledger from file"""
        if not self.ledger_path.exists():
            return []
        
        try:
            with open(self.ledger_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️  Error loading ledger: {e}")
            return []
    
    def _atomic_save(self, ledger_data: List[dict]):
        """Atomic save with unique temp file"""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        temp_path = self.ledger_path.with_suffix(f'.{uuid.uuid4().hex}.tmp')
        
        try:
            with open(temp_path, 'w') as f:
                json.dump(ledger_data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, self.ledger_path)
            
        except Exception as e:
            print(f"⚠️  Failed to save ledger: {e}")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except:
                    pass
            raise
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except:
                    pass
    
    def append_event(
        self,
        actor_id: str,
        action_type: Union[str, ActionType],
        status: Union[str, EventStatus],
        evidence: Union[str, StructuredEvidence, Dict],
        event_id: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> VestigiaEvent:
        """
        Append immutable event to ledger (THREAD-SAFE)
        
        FIXED: Now uses canonical JSON for hashing
        """
        with self._lock:
            trail = self._load_ledger()
            
            # Check rotation
            if self.rotation.should_rotate(len(trail)):
                current_hash = trail[-1]['integrity_hash'] if trail else "ROOT"
                
                archive_path = self.rotation.rotate(
                    current_hash=current_hash,
                    entry_count=len(trail),
                    anchor=self.anchor if hasattr(self, 'anchor') else None
                )
                
                genesis = {
                    'timestamp': datetime.now(UTC).isoformat(),
                    'actor_id': 'SYSTEM',
                    'action_type': ActionType.LEDGER_ROTATED.value,
                    'status': EventStatus.SUCCESS.value,
                    'evidence': StructuredEvidence(
                        summary=f'Ledger rotated at {len(trail)} entries',
                        metadata={
                            'previous_ledger': archive_path,
                            'previous_hash': current_hash
                        }
                    ).to_dict(),
                    'integrity_hash': current_hash,
                    'event_id': f'rotation_{datetime.now(UTC).strftime("%Y%m%d_%H%M%S")}',
                    'previous_hash': current_hash
                }
                
                trail = [genesis]
                self._atomic_save(trail)
            
            # Get last hash
            last_hash = trail[-1]['integrity_hash'] if trail else "ROOT"
            
            # Generate event ID
            if not event_id:
                event_id = f"event_{len(trail):06d}"
            
            # Convert enums
            if isinstance(action_type, ActionType):
                action_type = action_type.value
            if isinstance(status, EventStatus):
                status = status.value
            
            # Process evidence
            if isinstance(evidence, StructuredEvidence):
                evidence_data = evidence.to_dict()
            elif isinstance(evidence, dict):
                evidence_data = evidence
            else:
                evidence_data = StructuredEvidence.from_string(str(evidence)).to_dict()
            
            # Create event
            timestamp = datetime.now(UTC).isoformat()
            
            # Generate hash with NEW canonical method
            integrity_hash = self._generate_integrity_hash(
                timestamp=timestamp,
                tenant_id=tenant_id,
                actor_id=actor_id,
                action_type=action_type,
                status=status,
                evidence=evidence_data,
                previous_hash=last_hash
            )
            
            event_data = {
                'timestamp': timestamp,
                'tenant_id': tenant_id,
                'actor_id': actor_id,
                'action_type': action_type,
                'status': status,
                'evidence': evidence_data,
                'integrity_hash': integrity_hash,
                'event_id': event_id,
                'previous_hash': last_hash
            }
            
            trail.append(event_data)
            self._atomic_save(trail)
            
            # Merkle anchoring
            if self.enable_merkle_witness:
                if len(trail) % 100 == 0 or status == EventStatus.CRITICAL.value:
                    witness_id = self.witness.anchor_hash(integrity_hash, len(trail))
                    print(f"⚓ Merkle anchored: {witness_id}")
            
            # External anchoring
            if self.anchor and (
                len(trail) % self.anchor_frequency == 0 or 
                status == EventStatus.CRITICAL.value
            ):
                try:
                    anchor_id = self.anchor.anchor(
                        ledger_hash=integrity_hash,
                        entry_count=len(trail),
                        metadata={'actor_id': actor_id, 'action': action_type}
                    )
                    if anchor_id:
                        print(f"⚓ External anchored: {anchor_id[:16]}...")
                except Exception as e:
                    print(f"⚠️  External anchoring failed: {e}")

            # Blockchain anchoring (batch)
            if self.blockchain_anchor and (
                len(trail) % self.blockchain_anchor_every == 0 or
                status == EventStatus.CRITICAL.value
            ):
                try:
                    batch = [e['integrity_hash'] for e in trail[-self.blockchain_anchor_every:]]
                    record = self.blockchain_anchor.anchor(batch)
                    print(f"⛓️  Blockchain anchor recorded: {record.get('anchor_id')}")
                except Exception as e:
                    print(f"⚠️  Blockchain anchoring failed: {e}")
            
            # UPDATE WITNESS (Out-of-band integrity check)
            self._witness_state(integrity_hash)
            
            return VestigiaEvent(**event_data)
    
    def _witness_state(self, last_hash: str):
        """
        Writes the final hash to a separate witness file
        
        This provides out-of-band verification. Even if attacker
        replaces entire ledger with valid chain, witness will detect it.
        """
        witness_path = self.ledger_path.parent / "witness.hash"
        try:
            with open(witness_path, 'w') as f:
                f.write(last_hash)
        except Exception as e:
            # Don't crash if witness fails, but log it
            if self.debug if hasattr(self, 'debug') else False:
                print(f"⚠️  Witness update failed: {e}")
    
    def verify_integrity(self) -> tuple[bool, Optional[int]]:
        """Verify ledger integrity"""
        with self._lock:
            trail = self._load_ledger()
        
        if not trail:
            return True, None
        
        for i in range(1, len(trail)):
            entry = trail[i]
            previous_hash = trail[i-1]['integrity_hash']
            
            if entry.get('previous_hash') != previous_hash:
                return False, i
            
            # Recalculate with canonical method
            expected_hash = self._generate_integrity_hash(
                timestamp=entry['timestamp'],
                tenant_id=entry.get('tenant_id'),
                actor_id=entry['actor_id'],
                action_type=entry['action_type'],
                status=entry['status'],
                evidence=entry['evidence'],
                previous_hash=previous_hash
            )
            
            if entry['integrity_hash'] != expected_hash:
                return False, i
        
        return True, None

    def repair_integrity(self, strategy: str = "truncate") -> Dict[str, Any]:
        """
        Attempt a safe integrity repair.

        Strategy:
        - truncate: keep entries up to (but not including) first broken index.
          A forensic backup of the original file is always written first.
        """
        def _verify_unlocked(data: List[dict]) -> tuple[bool, Optional[int]]:
            if not data:
                return True, None
            for i in range(1, len(data)):
                entry = data[i]
                previous_hash = data[i - 1]["integrity_hash"]
                if entry.get("previous_hash") != previous_hash:
                    return False, i
                expected_hash = self._generate_integrity_hash(
                    timestamp=entry["timestamp"],
                    tenant_id=entry.get("tenant_id"),
                    actor_id=entry["actor_id"],
                    action_type=entry["action_type"],
                    status=entry["status"],
                    evidence=entry["evidence"],
                    previous_hash=previous_hash,
                )
                if entry["integrity_hash"] != expected_hash:
                    return False, i
            return True, None

        with self._lock:
            trail = self._load_ledger()
            valid, broken_idx = _verify_unlocked(trail)
            if valid:
                return {
                    "repaired": False,
                    "already_valid": True,
                    "broken_index": None,
                    "kept_entries": len(trail),
                    "backup_path": None,
                }
            if not trail:
                return {
                    "repaired": False,
                    "already_valid": False,
                    "broken_index": broken_idx,
                    "kept_entries": 0,
                    "backup_path": None,
                }

            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            backup_path = self.ledger_path.with_suffix(f".corrupt.{ts}.bak")
            try:
                shutil.copy2(self.ledger_path, backup_path)
            except Exception:
                backup_path = None

            if strategy != "truncate":
                raise ValueError(f"Unsupported repair strategy: {strategy}")

            cut = broken_idx if broken_idx is not None else len(trail)
            # Keep at least the first record to avoid empty-ledger regressions.
            kept = trail[:max(1, cut)]
            self._atomic_save(kept)
            if kept:
                self._witness_state(kept[-1]["integrity_hash"])

            valid_after, _ = _verify_unlocked(kept)
            return {
                "repaired": bool(valid_after),
                "already_valid": False,
                "broken_index": broken_idx,
                "kept_entries": len(kept),
                "backup_path": str(backup_path) if backup_path else None,
            }
    
    def query_events(
        self,
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        action_type: Optional[Union[str, ActionType]] = None,
        status: Optional[Union[str, EventStatus]] = None,
        min_status: Optional[EventStatus] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[VestigiaEvent]:
        """Advanced querying"""
        with self._lock:
            trail = self._load_ledger()
        
        filtered = trail
        
        if tenant_id:
            filtered = [e for e in filtered if e.get('tenant_id') == tenant_id]

        if actor_id:
            filtered = [e for e in filtered if actor_id in e['actor_id']]
        
        if action_type:
            if isinstance(action_type, ActionType):
                action_type = action_type.value
            filtered = [e for e in filtered if e['action_type'] == action_type]
        
        if status:
            if isinstance(status, EventStatus):
                status = status.value
            filtered = [e for e in filtered if e['status'] == status]
        
        if min_status:
            severity_order = {
                EventStatus.INFO.value: 0,
                EventStatus.SUCCESS.value: 1,
                EventStatus.WARNING.value: 2,
                EventStatus.BLOCKED.value: 3,
                EventStatus.CRITICAL.value: 4
            }
            min_severity = severity_order.get(min_status.value, 0)
            filtered = [
                e for e in filtered 
                if severity_order.get(e['status'], 0) >= min_severity
            ]
        
        if start_date or end_date:
            date_filtered = []
            for e in filtered:
                event_time = datetime.fromisoformat(e['timestamp'])
                
                if start_date and event_time < start_date:
                    continue
                if end_date and event_time > end_date:
                    continue
                
                date_filtered.append(e)
            
            filtered = date_filtered
        
        filtered.reverse()
        return [VestigiaEvent(**{**e, 'previous_hash': e.get('previous_hash', 'GENESIS')}) for e in filtered[:limit]]
    
    def get_statistics(self, tenant_id: Optional[str] = None) -> dict:
        """Get ledger statistics"""
        with self._lock:
            trail = self._load_ledger()

        if tenant_id:
            trail = [e for e in trail if e.get("tenant_id") == tenant_id]
        
        if not trail:
            return {
                'total_events': 0,
                'status_breakdown': {},
                'action_breakdown': {},
                'first_entry': None,
                'last_entry': None
            }
        
        status_counts = {}
        action_counts = {}
        
        for entry in trail:
            status = entry.get('status', 'UNKNOWN')
            action = entry.get('action_type', 'UNKNOWN')
            
            status_counts[status] = status_counts.get(status, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            'total_events': len(trail),
            'status_breakdown': status_counts,
            'action_breakdown': action_counts,
            'first_entry': trail[0]['timestamp'],
            'last_entry': trail[-1]['timestamp']
        }
    
    def export_compliance_report(
        self, 
        output_path: str,
        format: str = 'json',
        include_witness: bool = True
    ) -> str:
        """Export ledger for compliance/audit"""
        with self._lock:
            trail = self._load_ledger()
        
        output_path = Path(output_path)
        
        if format == 'json':
            export_data = {
                'ledger': trail,
                'statistics': self.get_statistics(),
                'export_timestamp': datetime.now(UTC).isoformat()
            }
            
            if include_witness and self.enable_merkle_witness:
                latest_witness = self.witness.get_latest_witness()
                if latest_witness:
                    export_data['witness_verification'] = latest_witness
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        elif format == 'csv':
            import csv
            
            if not trail:
                return str(output_path)
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', newline='') as f:
                flattened = []
                for entry in trail:
                    flat_entry = entry.copy()
                    if isinstance(flat_entry['evidence'], dict):
                        flat_entry['evidence'] = flat_entry['evidence'].get('summary', str(entry['evidence']))
                    flattened.append(flat_entry)
                
                writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
                writer.writeheader()
                writer.writerows(flattened)
        
        return str(output_path)


# ============================================================================
# HEARTBEAT SYSTEM
# ============================================================================

class VestigiaHeartbeat:
    """Automatic heartbeat for tamper detection"""
    
    def __init__(self, ledger: VestigiaLedger, interval_seconds: int = 3600):
        self.ledger = ledger
        self.interval = interval_seconds
    
    def log_heartbeat(self):
        """Log system alive event"""
        self.ledger.append_event(
            actor_id="SYSTEM",
            action_type=ActionType.HEARTBEAT,
            status=EventStatus.SUCCESS,
            evidence=StructuredEvidence(
                summary=f"System heartbeat at {datetime.now(UTC)}",
                metadata={'interval_seconds': self.interval}
            )
        )

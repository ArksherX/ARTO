#!/usr/bin/env python3
"""
Atomic Operations

Ensures data consistency with write-ahead logging
"""

import json
import fcntl
import tempfile
from pathlib import Path
from typing import Dict, Any, Callable
from datetime import datetime
import shutil


class WriteAheadLog:
    """
    Write-Ahead Log (WAL) for atomic operations
    
    Ensures data isn't lost even if system crashes mid-write
    """
    
    def __init__(self, log_dir: str = "wal"):
        """
        Initialize WAL
        
        Args:
            log_dir: Directory for WAL files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.wal_file = self.log_dir / "operations.wal"
    
    def atomic_write(self, 
                    file_path: Path,
                    data: Dict[str, Any]) -> bool:
        """
        Atomic file write with WAL
        
        Steps:
        1. Write to WAL
        2. Write to temp file
        3. Atomic rename
        4. Remove from WAL
        
        Args:
            file_path: Target file path
            data: Data to write
        
        Returns:
            True if successful
        """
        operation_id = datetime.now().strftime('%Y%m%d%H%M%S%f')
        
        try:
            # Step 1: Write to WAL
            self._append_to_wal({
                'operation_id': operation_id,
                'type': 'write',
                'file': str(file_path),
                'timestamp': datetime.now().isoformat()
            })
            
            # Step 2: Write to temp file
            temp_file = file_path.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Step 3: Atomic rename
            shutil.move(str(temp_file), str(file_path))
            
            # Step 4: Remove from WAL
            self._remove_from_wal(operation_id)
            
            return True
            
        except Exception as e:
            print(f"Atomic write failed: {e}")
            # Operation stays in WAL for recovery
            return False
    
    def atomic_update(self,
                     file_path: Path,
                     update_func: Callable[[Dict], Dict]) -> bool:
        """
        Atomic file update
        
        Args:
            file_path: File to update
            update_func: Function that takes current data and returns updated data
        
        Returns:
            True if successful
        """
        # Acquire file lock
        lock_file = file_path.with_suffix('.lock')
        
        try:
            with open(lock_file, 'w') as lock_fd:
                # Exclusive lock
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                
                # Read current data
                if file_path.exists():
                    with open(file_path, 'r') as f:
                        current_data = json.load(f)
                else:
                    current_data = {}
                
                # Apply update
                updated_data = update_func(current_data)
                
                # Atomic write
                result = self.atomic_write(file_path, updated_data)
                
                # Release lock
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                
                return result
                
        except Exception as e:
            print(f"Atomic update failed: {e}")
            return False
        finally:
            # Clean up lock file
            if lock_file.exists():
                lock_file.unlink()
    
    def recover_pending_operations(self) -> int:
        """
        Recover operations from WAL after crash
        
        Returns:
            Number of operations recovered
        """
        if not self.wal_file.exists():
            return 0
        
        recovered = 0
        
        try:
            with open(self.wal_file, 'r') as f:
                for line in f:
                    try:
                        operation = json.loads(line)
                        
                        # Attempt to complete the operation
                        if operation['type'] == 'write':
                            # Check if operation completed
                            file_path = Path(operation['file'])
                            temp_file = file_path.with_suffix('.tmp')
                            
                            if temp_file.exists():
                                # Complete the interrupted operation
                                shutil.move(str(temp_file), str(file_path))
                                recovered += 1
                                
                    except Exception as e:
                        print(f"Recovery failed for operation: {e}")
            
            # Clear WAL after recovery
            self.wal_file.unlink()
            
        except Exception as e:
            print(f"WAL recovery failed: {e}")
        
        return recovered
    
    def _append_to_wal(self, operation: Dict) -> None:
        """Append operation to WAL"""
        with open(self.wal_file, 'a') as f:
            # Acquire lock
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(json.dumps(operation) + '\n')
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    
    def _remove_from_wal(self, operation_id: str) -> None:
        """Remove completed operation from WAL"""
        if not self.wal_file.exists():
            return
        
        # Read all operations
        with open(self.wal_file, 'r') as f:
            operations = f.readlines()
        
        # Filter out completed operation
        remaining = [
            line for line in operations
            if operation_id not in line
        ]
        
        # Write back
        with open(self.wal_file, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.writelines(remaining)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class AtomicCounter:
    """
    Thread-safe atomic counter
    
    Useful for generating unique IDs
    """
    
    def __init__(self, initial_value: int = 0, file_path: Optional[Path] = None):
        """
        Initialize atomic counter
        
        Args:
            initial_value: Starting value
            file_path: Persist counter to file
        """
        import threading
        
        self.value = initial_value
        self.lock = threading.Lock()
        self.file_path = file_path
        
        # Load from file if exists
        if file_path and file_path.exists():
            with open(file_path, 'r') as f:
                self.value = int(f.read())
    
    def increment(self, amount: int = 1) -> int:
        """
        Atomically increment counter
        
        Returns:
            New value
        """
        with self.lock:
            self.value += amount
            
            # Persist to file
            if self.file_path:
                with open(self.file_path, 'w') as f:
                    f.write(str(self.value))
                    f.flush()
                    os.fsync(f.fileno())
            
            return self.value
    
    def get(self) -> int:
        """Get current value"""
        with self.lock:
            return self.value

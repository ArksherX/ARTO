#!/usr/bin/env python3
"""
Verify backup integrity by checking archive readability and required files.
"""

import os
import tarfile
from pathlib import Path


BACKUP_DIR = Path(os.getenv("VESTIGIA_BACKUP_DIR", "backups"))


def find_latest_backup() -> Path:
    archives = sorted(BACKUP_DIR.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not archives:
        raise FileNotFoundError("No backup archives found")
    return archives[0]


def verify_archive(path: Path) -> bool:
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        required = ["vestigia_ledger.json", "postgres_dump.sql"]
        missing = [r for r in required if not any(r in name for name in names)]
        if missing:
            raise RuntimeError(f"Missing required artifacts: {missing}")
    return True


if __name__ == "__main__":
    backup = find_latest_backup()
    print(f"Checking {backup}")
    if verify_archive(backup):
        print("Backup verified successfully")

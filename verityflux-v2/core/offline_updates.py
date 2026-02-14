#!/usr/bin/env python3
"""
Offline update manifest utilities.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class UpdateManifest:
    version: str
    created_at: str
    created_by: str
    description: str
    vulnerabilities_count: int = 0
    policies_count: int = 0
    rules_count: int = 0
    checksums: Dict[str, str] = field(default_factory=dict)
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "description": self.description,
            "vulnerabilities_count": self.vulnerabilities_count,
            "policies_count": self.policies_count,
            "rules_count": self.rules_count,
            "checksums": self.checksums,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UpdateManifest":
        return cls(
            version=data.get("version", ""),
            created_at=data.get("created_at", ""),
            created_by=data.get("created_by", ""),
            description=data.get("description", ""),
            vulnerabilities_count=int(data.get("vulnerabilities_count", 0)),
            policies_count=int(data.get("policies_count", 0)),
            rules_count=int(data.get("rules_count", 0)),
            checksums=data.get("checksums", {}) or {},
            signature=data.get("signature"),
        )

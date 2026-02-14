#!/usr/bin/env python3
"""
Vestigia Development Mode Configuration
Automatically manages hardening for dev vs production

Save as: vestigia/config.py
"""

import os
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class VestigiaMode(Enum):
    """Operating mode"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class GovernanceConfig:
    """
    Three Lines of Defense Configuration
    Maps technical tool to organizational governance
    """
    # 1st Line: Operations
    operations_team: str = "AI_Ops"
    max_autonomous_risk: float = 0.5  # Above this needs human approval
    
    # 2nd Line: Risk & Compliance
    governance_committee: str = "AI_Governance_Committee"
    monthly_review_required: bool = True
    risk_threshold_critical: float = 0.8
    
    # 3rd Line: Internal Audit
    audit_team: str = "Internal_Audit"
    quarterly_verification_required: bool = True
    
    # External Witness
    external_witness_enabled: bool = False
    external_witness_url: Optional[str] = None  # e.g., blockchain API
    
    # Human-in-the-Loop (HITL)
    hitl_required_for_critical: bool = True
    hitl_timeout_seconds: int = 300  # 5 minutes


@dataclass
class ComplianceMapping:
    """Map Vestigia features to regulatory requirements"""
    
    REGULATORY_MAPPINGS = {
        'hash_chain': [
            'GDPR Art. 5 (Integrity & Confidentiality)',
            'SOC2 CC6.1 (Logical Access Controls)',
            'ISO 27001 A.12.4.1 (Event Logging)'
        ],
        'merkle_witness': [
            'EU AI Act Art. 12 (Record-keeping for high-risk AI)',
            'SEC Rule 17a-4 (Electronic record preservation)',
            'FINRA Rule 4511 (Books and Records)'
        ],
        'tamper_detection': [
            'SOC2 CC7.2 (Monitoring Activities)',
            'HIPAA §164.312(b) (Audit Controls)',
            'PCI DSS 10.2 (Audit Trail Implementation)'
        ],
        'structured_evidence': [
            'GDPR Art. 22 (Automated Decision-Making)',
            'EU AI Act Art. 13 (Transparency)',
            'NIST AI RMF (Measure Function)'
        ],
        'retention': [
            'GDPR Art. 5(e) (Storage Limitation)',
            'SOX Section 802 (7-year retention)',
            'HIPAA §164.530(j) (6-year retention)'
        ]
    }
    
    @classmethod
    def get_compliance_report(cls) -> dict:
        """Generate compliance coverage report"""
        regulations = set()
        for reqs in cls.REGULATORY_MAPPINGS.values():
            regulations.update(reqs)
        
        return {
            'total_regulations': len(regulations),
            'covered_regulations': sorted(list(regulations)),
            'feature_mapping': cls.REGULATORY_MAPPINGS
        }


class VestigiaConfig:
    """
    Main configuration with dev mode support
    """
    
    def __init__(self, mode: Optional[VestigiaMode] = None):
        # Determine mode
        self.mode = mode or self._detect_mode()
        
        # Governance
        self.governance = GovernanceConfig()
        
        # Paths
        self.ledger_path = self._get_ledger_path()
        self.witness_path = self._get_witness_path()
        
        # Performance
        self.max_entries_before_rotation = 10000
        self.merkle_anchor_frequency = 100  # Anchor every N entries
        
        # Development settings
        self.enable_hardening = (self.mode == VestigiaMode.PRODUCTION)
        self.enable_merkle_witness = True
        self.enable_external_witness = False  # Set to True in production
        
        # Security
        self.secret_salt = os.getenv('VESTIGIA_SECRET_SALT')
        
        # Logging
        self.verbose = (self.mode == VestigiaMode.DEVELOPMENT)
    
    def _detect_mode(self) -> VestigiaMode:
        """Auto-detect operating mode from environment"""
        mode_env = os.getenv('VESTIGIA_MODE', 'development').lower()
        
        try:
            return VestigiaMode(mode_env)
        except ValueError:
            return VestigiaMode.DEVELOPMENT
    
    def _get_ledger_path(self) -> str:
        """Get ledger path based on mode"""
        if self.mode == VestigiaMode.PRODUCTION:
            return "/var/log/vestigia/production_ledger.json"
        elif self.mode == VestigiaMode.STAGING:
            return "staging/vestigia_ledger.json"
        else:
            return "data/vestigia_ledger.json"
    
    def _get_witness_path(self) -> str:
        """Get witness path based on mode"""
        if self.mode == VestigiaMode.PRODUCTION:
            return "/var/log/vestigia/witness.hash"
        elif self.mode == VestigiaMode.STAGING:
            return "staging/witness.hash"
        else:
            return "data/witness.hash"
    
    def print_config(self):
        """Print current configuration"""
        print("\n" + "=" * 70)
        print("  ⚙️  Vestigia Configuration")
        print("=" * 70 + "\n")
        
        print(f"Mode: {self.mode.value.upper()}")
        print(f"Ledger: {self.ledger_path}")
        print(f"Witness: {self.witness_path}")
        print(f"Hardening: {'✅ Enabled' if self.enable_hardening else '⚠️  Disabled (Dev Mode)'}")
        print(f"Merkle Witness: {'✅ Enabled' if self.enable_merkle_witness else '❌ Disabled'}")
        print(f"External Witness: {'✅ Enabled' if self.enable_external_witness else '❌ Disabled'}")
        
        print(f"\n🏢 Governance Configuration:")
        print(f"  1st Line (Ops): {self.governance.operations_team}")
        print(f"  2nd Line (Compliance): {self.governance.governance_committee}")
        print(f"  3rd Line (Audit): {self.governance.audit_team}")
        print(f"  HITL Required: {self.governance.hitl_required_for_critical}")
        
        print("\n" + "=" * 70)
    
    def validate_for_production(self) -> list[str]:
        """Check if configuration is production-ready"""
        issues = []
        
        if not self.secret_salt:
            issues.append("VESTIGIA_SECRET_SALT not set")
        
        if not self.enable_hardening:
            issues.append("Hardening disabled")
        
        if not self.enable_external_witness and self.mode == VestigiaMode.PRODUCTION:
            issues.append("External witness not configured")
        
        if not self.governance.hitl_required_for_critical:
            issues.append("Human-in-the-loop not required for critical events")
        
        return issues


# ============================================================================
# ENHANCED STRUCTURED EVIDENCE WITH GOVERNANCE
# ============================================================================

@dataclass
class GovernanceEvidence:
    """
    Enhanced evidence structure with governance fields
    
    Implements "Three Lines of Defense" + HITL
    """
    # Core evidence (technical)
    summary: str
    raw_payload: Optional[str] = None
    risk_score: Optional[float] = None
    mitigation: Optional[str] = None
    
    # Governance fields (organizational)
    approved_by: Optional[str] = None  # Human approver ID
    approval_timestamp: Optional[str] = None
    governance_review_required: bool = False
    audit_trail_id: Optional[str] = None  # Links to external audit system
    
    # Compliance mapping
    regulatory_impact: list[str] = None  # e.g., ["GDPR", "HIPAA"]
    data_classification: str = "INTERNAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    
    # External witness
    external_witness_hash: Optional[str] = None
    external_witness_url: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values"""
        return {k: v for k, v in self.__dict__.items() if v is not None}
    
    def requires_human_approval(self, config: GovernanceConfig) -> bool:
        """Check if this evidence needs human approval"""
        if not config.hitl_required_for_critical:
            return False
        
        # High risk score requires approval
        if self.risk_score and self.risk_score >= config.risk_threshold_critical:
            return True
        
        # Certain regulatory impacts require approval
        if self.regulatory_impact and 'HIPAA' in self.regulatory_impact:
            return True
        
        return False


# ============================================================================
# QUICK TEST & DEMO
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  🗃️  Vestigia Configuration Test")
    print("=" * 70)
    
    # Test different modes
    for mode in VestigiaMode:
        print(f"\n{'='*70}")
        print(f"  {mode.value.upper()} MODE")
        print("=" * 70)
        
        config = VestigiaConfig(mode)
        config.print_config()
        
        # Validate production readiness
        if mode == VestigiaMode.PRODUCTION:
            issues = config.validate_for_production()
            if issues:
                print("\n⚠️  Production Readiness Issues:")
                for issue in issues:
                    print(f"  • {issue}")
    
    # Test governance evidence
    print("\n" + "=" * 70)
    print("  📋 Governance Evidence Example")
    print("=" * 70 + "\n")
    
    evidence = GovernanceEvidence(
        summary="SQL Injection detected in agent_rogue_99",
        raw_payload="DROP TABLE users; --",
        risk_score=0.98,
        mitigation="BLOCKED by VerityFlux",
        approved_by="security_analyst_42",
        approval_timestamp="2025-12-30T04:35:00Z",
        governance_review_required=True,
        regulatory_impact=["GDPR", "SOC2"],
        data_classification="CONFIDENTIAL"
    )
    
    config = VestigiaConfig()
    
    print("Evidence Structure:")
    for key, value in evidence.to_dict().items():
        print(f"  {key}: {value}")
    
    print(f"\nHuman Approval Required: {evidence.requires_human_approval(config.governance)}")
    
    # Test compliance mapping
    print("\n" + "=" * 70)
    print("  📜 Compliance Coverage Report")
    print("=" * 70 + "\n")
    
    compliance = ComplianceMapping.get_compliance_report()
    
    print(f"Total Regulations Covered: {compliance['total_regulations']}")
    print("\nCovered Regulations:")
    for reg in compliance['covered_regulations'][:5]:
        print(f"  ✅ {reg}")
    
    print(f"\n... and {compliance['total_regulations'] - 5} more")
    
    print("\n✅ Configuration test complete!")

"""
VerityFlux Enterprise v3.5
AI Agent Security Platform

Features:
- Security Scanning (OWASP LLM & Agentic Top 20)
- Cognitive Firewall (Real-time protection)
- Backdoor Detection (Behavioral analysis)
- Adversarial Simulation Lab
- SOC Command Center
- HITL Approval Workflows
- Multi-Tenancy Support
- Vulnerability Database (NVD, OWASP, MITRE ATLAS)

Deployment Modes:
- SaaS (Stripe billing)
- On-Premise (License key)
- Hybrid

© 2025-2026 VerityFlux. All rights reserved.
"""

__version__ = "3.5.0"
__author__ = "VerityFlux Team"

Organization = Workspace = User = MonitoredAgent = None
SecurityScan = Vulnerability = Incident = HITLApproval = None
AuthenticationService = LicenseService = None
SubscriptionTier = ScanType = VulnerabilitySeverity = None
TIER_DEFINITIONS = None

try:
    from .core import (  # type: ignore
        Organization,
        Workspace,
        User,
        MonitoredAgent,
        SecurityScan,
        Vulnerability,
        Incident,
        HITLApproval,
        AuthenticationService,
        LicenseService,
        SubscriptionTier,
        ScanType,
        VulnerabilitySeverity,
        TIER_DEFINITIONS,
    )
except Exception:
    try:
        from core import (  # type: ignore
            Organization,
            Workspace,
            User,
            MonitoredAgent,
            SecurityScan,
            Vulnerability,
            Incident,
            HITLApproval,
            AuthenticationService,
            LicenseService,
            SubscriptionTier,
            ScanType,
            VulnerabilitySeverity,
            TIER_DEFINITIONS,
        )
    except Exception:
        # Allow import to succeed during test collection even if core exports differ.
        pass

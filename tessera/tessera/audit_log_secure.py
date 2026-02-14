"""
Compatibility wrapper for tamper-proof audit logging.
"""

from tessera.audit_logger import AuditChainLogger


class TamperProofAuditLog(AuditChainLogger):
    """Alias for legacy name used in validation checklist."""

    def export_events(self):
        return list(self.iter_events())

__all__ = ["TamperProofAuditLog"]

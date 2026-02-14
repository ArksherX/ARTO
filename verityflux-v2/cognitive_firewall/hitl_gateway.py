#!/usr/bin/env python3
"""
Human-in-the-Loop (HITL) Gateway

Manages approval queue for high-risk agent actions
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import json
import threading
import time


class ApprovalStatus(str, Enum):
    """Status of an approval request"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


@dataclass
class ApprovalRequest:
    """Represents a pending approval request"""
    request_id: str
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    reasoning_chain: List[str]
    original_goal: str
    risk_score: float
    tier: str
    violations: List[str]
    recommendations: List[str]
    
    # HITL metadata
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    # Approval tracking
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    reviewer_notes: str = ""
    
    # Learning data
    was_false_positive: bool = False
    
    def __post_init__(self):
        # Set expiration (15 minutes default)
        if self.expires_at is None:
            self.expires_at = self.requested_at + timedelta(minutes=15)
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary"""
        return {
            'request_id': self.request_id,
            'agent_id': self.agent_id,
            'tool_name': self.tool_name,
            'parameters': self.parameters,
            'reasoning_chain': self.reasoning_chain,
            'original_goal': self.original_goal,
            'risk_score': self.risk_score,
            'tier': self.tier,
            'violations': self.violations,
            'recommendations': self.recommendations,
            'status': self.status.value,
            'requested_at': self.requested_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'reviewed_by': self.reviewed_by,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewer_notes': self.reviewer_notes,
            'was_false_positive': self.was_false_positive
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ApprovalRequest':
        """Deserialize from dictionary"""
        return cls(
            request_id=data['request_id'],
            agent_id=data['agent_id'],
            tool_name=data['tool_name'],
            parameters=data['parameters'],
            reasoning_chain=data['reasoning_chain'],
            original_goal=data['original_goal'],
            risk_score=data['risk_score'],
            tier=data['tier'],
            violations=data['violations'],
            recommendations=data['recommendations'],
            status=ApprovalStatus(data['status']),
            requested_at=datetime.fromisoformat(data['requested_at']),
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            reviewed_by=data.get('reviewed_by'),
            reviewed_at=datetime.fromisoformat(data['reviewed_at']) if data.get('reviewed_at') else None,
            reviewer_notes=data.get('reviewer_notes', ''),
            was_false_positive=data.get('was_false_positive', False)
        )


class HITLGateway:
    """
    Human-in-the-Loop Gateway
    
    Manages approval queue for high-risk actions
    """
    
    def __init__(self, storage_path: str = "hitl_queue"):
        """
        Initialize HITL Gateway
        
        Args:
            storage_path: Directory to store approval requests
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # In-memory queue
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.completed_requests: Dict[str, ApprovalRequest] = {}
        
        # Load existing requests
        self._load_requests()
        
        # Start background cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()
        
        # Notification handlers
        self.notification_handlers = []
    
    def submit_for_approval(self, 
                           agent_action,  # AgentAction
                           decision,       # FirewallDecision
                           timeout_minutes: int = 15) -> str:
        """
        Submit an action for human approval
        
        Args:
            agent_action: The agent action to approve
            decision: The firewall decision
            timeout_minutes: How long to wait before auto-deny
        
        Returns:
            Request ID
        """
        # Generate unique request ID
        request_id = f"HITL-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.pending_requests)}"
        
        # Create approval request
        request = ApprovalRequest(
            request_id=request_id,
            agent_id=agent_action.agent_id,
            tool_name=agent_action.tool_name,
            parameters=agent_action.parameters,
            reasoning_chain=agent_action.reasoning_chain,
            original_goal=agent_action.original_goal,
            risk_score=decision.risk_score,
            tier=decision.context.get('tier', 'UNKNOWN'),
            violations=decision.violations,
            recommendations=decision.recommendations,
            expires_at=datetime.now() + timedelta(minutes=timeout_minutes)
        )
        
        # Add to queue
        self.pending_requests[request_id] = request
        
        # Save to disk
        self._save_request(request)
        
        # Send notifications
        self._notify_reviewers(request)
        
        return request_id
    
    def approve(self, 
                request_id: str, 
                reviewer: str,
                notes: str = "",
                mark_false_positive: bool = False) -> bool:
        """
        Approve a pending request
        
        Args:
            request_id: Request to approve
            reviewer: Name/ID of reviewer
            notes: Optional reviewer notes
            mark_false_positive: If true, mark as false positive for learning
        
        Returns:
            True if approved successfully
        """
        if request_id not in self.pending_requests:
            return False
        
        request = self.pending_requests.pop(request_id)
        
        # Update status
        request.status = ApprovalStatus.APPROVED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.now()
        request.reviewer_notes = notes
        request.was_false_positive = mark_false_positive
        
        # Move to completed
        self.completed_requests[request_id] = request
        
        # Save
        self._save_request(request)
        
        # Learn from false positive
        if mark_false_positive:
            self._learn_from_false_positive(request)
        
        return True
    
    def deny(self,
             request_id: str,
             reviewer: str,
             notes: str = "") -> bool:
        """
        Deny a pending request
        
        Args:
            request_id: Request to deny
            reviewer: Name/ID of reviewer
            notes: Optional reviewer notes
        
        Returns:
            True if denied successfully
        """
        if request_id not in self.pending_requests:
            return False
        
        request = self.pending_requests.pop(request_id)
        
        # Update status
        request.status = ApprovalStatus.DENIED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.now()
        request.reviewer_notes = notes
        
        # Move to completed
        self.completed_requests[request_id] = request
        
        # Save
        self._save_request(request)
        
        return True
    
    def wait_for_decision(self, 
                         request_id: str, 
                         poll_interval: float = 1.0) -> ApprovalStatus:
        """
        Block and wait for approval decision
        
        Args:
            request_id: Request to wait for
            poll_interval: How often to check (seconds)
        
        Returns:
            Final approval status
        """
        while True:
            # Check if completed
            if request_id in self.completed_requests:
                return self.completed_requests[request_id].status
            
            # Check if still pending
            if request_id not in self.pending_requests:
                return ApprovalStatus.EXPIRED
            
            # Check if expired
            request = self.pending_requests[request_id]
            if request.expires_at and datetime.now() > request.expires_at:
                # Auto-deny
                self._auto_deny(request_id)
                return ApprovalStatus.EXPIRED
            
            # Wait and check again
            time.sleep(poll_interval)
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests"""
        return list(self.pending_requests.values())
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a specific request"""
        if request_id in self.pending_requests:
            return self.pending_requests[request_id]
        if request_id in self.completed_requests:
            return self.completed_requests[request_id]
        return None
    
    def add_notification_handler(self, handler):
        """
        Add a notification handler
        
        Handler should be a callable: handler(request: ApprovalRequest)
        """
        self.notification_handlers.append(handler)
    
    def _notify_reviewers(self, request: ApprovalRequest) -> None:
        """Send notifications to reviewers"""
        for handler in self.notification_handlers:
            try:
                handler(request)
            except Exception as e:
                print(f"Notification handler failed: {e}")
    
    def _auto_deny(self, request_id: str) -> None:
        """Auto-deny an expired request"""
        if request_id not in self.pending_requests:
            return
        
        request = self.pending_requests.pop(request_id)
        request.status = ApprovalStatus.AUTO_DENIED
        request.reviewed_by = "system"
        request.reviewed_at = datetime.now()
        request.reviewer_notes = "Auto-denied: approval timeout exceeded"
        
        self.completed_requests[request_id] = request
        self._save_request(request)
    
    def _cleanup_expired(self) -> None:
        """Background thread to clean up expired requests"""
        while True:
            try:
                now = datetime.now()
                expired = [
                    req_id for req_id, req in self.pending_requests.items()
                    if req.expires_at and now > req.expires_at
                ]
                
                for req_id in expired:
                    self._auto_deny(req_id)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Cleanup thread error: {e}")
                time.sleep(60)
    
    def _save_request(self, request: ApprovalRequest) -> None:
        """Save request to disk"""
        file_path = self.storage_path / f"{request.request_id}.json"
        
        with open(file_path, 'w') as f:
            json.dump(request.to_dict(), f, indent=2)
    
    def _load_requests(self) -> None:
        """Load existing requests from disk"""
        for file_path in self.storage_path.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    request = ApprovalRequest.from_dict(data)
                    
                    if request.status == ApprovalStatus.PENDING:
                        self.pending_requests[request.request_id] = request
                    else:
                        self.completed_requests[request.request_id] = request
            except Exception as e:
                print(f"Failed to load {file_path}: {e}")
    
    def _learn_from_false_positive(self, request: ApprovalRequest) -> None:
        """Learn from false positive approval"""
        # Import here to avoid circular dependency
        try:
            from intent_analysis import AdaptiveIntentAnalyzer
            
            analyzer = AdaptiveIntentAnalyzer()
            analyzer.learn_from_false_positive(
                reasoning_chain=request.reasoning_chain,
                parameters=request.parameters,
                reviewer_notes=request.reviewer_notes
            )
            
            print(f"✅ Learned from false positive: {request.request_id}")
        except Exception as e:
            print(f"Failed to learn from false positive: {e}")
    
    def get_statistics(self) -> Dict:
        """Get HITL statistics"""
        total_requests = len(self.pending_requests) + len(self.completed_requests)
        
        if total_requests == 0:
            return {
                'total_requests': 0,
                'pending': 0,
                'approved': 0,
                'denied': 0,
                'expired': 0
            }
        
        completed = list(self.completed_requests.values())
        
        return {
            'total_requests': total_requests,
            'pending': len(self.pending_requests),
            'approved': sum(1 for r in completed if r.status == ApprovalStatus.APPROVED),
            'denied': sum(1 for r in completed if r.status == ApprovalStatus.DENIED),
            'auto_denied': sum(1 for r in completed if r.status == ApprovalStatus.AUTO_DENIED),
            'false_positives': sum(1 for r in completed if r.was_false_positive),
            'avg_review_time_minutes': self._calculate_avg_review_time(completed)
        }
    
    def _calculate_avg_review_time(self, requests: List[ApprovalRequest]) -> float:
        """Calculate average review time in minutes"""
        reviewed = [r for r in requests if r.reviewed_at and r.requested_at]
        
        if not reviewed:
            return 0.0
        
        times = [(r.reviewed_at - r.requested_at).total_seconds() / 60 for r in reviewed]
        return sum(times) / len(times)

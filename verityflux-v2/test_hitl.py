#!/usr/bin/env python3
"""
Test HITL (Human-in-the-Loop) System
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from cognitive_firewall import EnhancedCognitiveFirewall, AgentAction
from cognitive_firewall.hitl_gateway import ApprovalStatus
import time


def test_hitl_approval_required():
    """Test that high-risk actions require approval"""
    print("\n" + "="*70)
    print("TEST 1: High-Risk Action Requires Approval")
    print("="*70)
    
    firewall = EnhancedCognitiveFirewall()
    firewall.load_vulnerabilities()
    
    # Create high-risk action
    action = AgentAction(
        agent_id="test_agent",
        tool_name="run_sql_query",
        parameters={"query": "DELETE FROM users"},  # No WHERE clause!
        reasoning_chain=["Cleaning database", "Removing old records"],
        original_goal="Database maintenance"
    )
    
    # Evaluate
    decision = firewall.evaluate(action)
    
    print(f"\n📊 Results:")
    print(f"  Decision: {decision.action.value.upper()}")
    print(f"  Risk: {decision.risk_score:.0f}/100")
    print(f"  HITL Status: {decision.context.get('hitl_status', 'N/A')}")
    
    if decision.context.get('hitl_request_id'):
        print(f"  Request ID: {decision.context['hitl_request_id']}")
        print("\n✅ PASS - Action submitted for approval")
        return True, decision.context['hitl_request_id']
    else:
        print("\n❌ FAIL - No approval request created")
        return False, None


def test_hitl_approval_flow():
    """Test complete approval workflow"""
    print("\n" + "="*70)
    print("TEST 2: Complete Approval Workflow")
    print("="*70)
    
    # Step 1: Create request
    passed, request_id = test_hitl_approval_required()
    
    if not passed:
        return False
    
    # Step 2: Check pending queue
    from cognitive_firewall.hitl_gateway import HITLGateway
    
    gateway = HITLGateway()
    pending = gateway.get_pending_requests()
    
    print(f"\n📋 Pending Requests: {len(pending)}")
    
    if request_id not in [r.request_id for r in pending]:
        print("❌ FAIL - Request not in pending queue")
        return False
    
    # Step 3: Approve the request
    print(f"\n👤 Approving request {request_id}...")
    
    success = gateway.approve(
        request_id=request_id,
        reviewer="test_reviewer",
        notes="Test approval - verified action is safe",
        mark_false_positive=False
    )
    
    if not success:
        print("❌ FAIL - Approval failed")
        return False
    
    # Step 4: Verify approval
    request = gateway.get_request(request_id)
    
    if request.status != ApprovalStatus.APPROVED:
        print(f"❌ FAIL - Status is {request.status}, expected APPROVED")
        return False
    
    print(f"\n✅ PASS - Request approved successfully")
    print(f"  Reviewer: {request.reviewed_by}")
    print(f"  Notes: {request.reviewer_notes}")
    
    return True


def test_hitl_auto_deny():
    """Test auto-deny on timeout"""
    print("\n" + "="*70)
    print("TEST 3: Auto-Deny on Timeout")
    print("="*70)
    
    from cognitive_firewall.hitl_gateway import HITLGateway
    from cognitive_firewall.hitl_gateway import ApprovalRequest
    from datetime import datetime, timedelta
    
    gateway = HITLGateway()
    
    # Create expired request
    expired_request = ApprovalRequest(
        request_id="TEST-EXPIRED",
        agent_id="test_agent",
        tool_name="dangerous_tool",
        parameters={"danger": "high"},
        reasoning_chain=["Testing"],
        original_goal="Test",
        risk_score=90.0,
        tier="CRITICAL",
        violations=["Test violation"],
        recommendations=["Don't do this"],
        expires_at=datetime.now() - timedelta(seconds=1)  # Already expired
    )
    
    gateway.pending_requests[expired_request.request_id] = expired_request
    
    # Trigger cleanup
    print("\n⏰ Waiting for auto-deny (5 seconds)...")
    time.sleep(5)
    
    # Check if auto-denied
    request = gateway.get_request("TEST-EXPIRED")
    
    if not request:
        print("❌ FAIL - Request disappeared")
        return False
    
    if request.status == ApprovalStatus.AUTO_DENIED:
        print("\n✅ PASS - Request auto-denied")
        print(f"  Reviewed By: {request.reviewed_by}")
        print(f"  Notes: {request.reviewer_notes}")
        return True
    else:
        print(f"\n❌ FAIL - Status is {request.status}, expected AUTO_DENIED")
        return False


def test_hitl_statistics():
    """Test HITL statistics"""
    print("\n" + "="*70)
    print("TEST 4: HITL Statistics")
    print("="*70)
    
    from cognitive_firewall.hitl_gateway import HITLGateway
    
    gateway = HITLGateway()
    stats = gateway.get_statistics()
    
    print(f"\n📊 HITL Statistics:")
    print(f"  Total Requests: {stats['total_requests']}")
    print(f"  Pending: {stats['pending']}")
    print(f"  Approved: {stats['approved']}")
    print(f"  Denied: {stats['denied']}")
    print(f"  Auto-Denied: {stats['auto_denied']}")
    print(f"  False Positives: {stats['false_positives']}")
    print(f"  Avg Review Time: {stats['avg_review_time_minutes']:.1f} min")
    
    print("\n✅ PASS - Statistics retrieved successfully")
    return True


def main():
    print("="*70)
    print("🧪 HITL SYSTEM TEST SUITE")
    print("="*70)
    
    results = []
    
    results.append(test_hitl_approval_flow())
    results.append(test_hitl_auto_deny())
    results.append(test_hitl_statistics())
    
    print("\n" + "="*70)
    print("📊 FINAL RESULTS")
    print("="*70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"\nTests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.0f}%")
    
    if passed == total:
        print("\n🎉 ALL HITL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

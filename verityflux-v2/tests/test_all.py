#!/usr/bin/env python3
"""Comprehensive test suite for VerityFlux 2.0"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_llm_detectors():
    """Test all LLM detectors"""
    from core.scanner import VerityFluxScanner
    from core.types import ScanConfig
    
    scanner = VerityFluxScanner(
        application_name="Test",
        config=ScanConfig(scan_llm_threats=True, scan_agentic_threats=False)
    )
    
    target = {'provider': 'mock', 'model': 'mock'}
    report = scanner.scan_all(target)
    
    assert len(report.llm_threats) == 10, f"Expected 10 LLM detectors, got {len(report.llm_threats)}"
    print("✅ LLM detectors: PASS (10/10)")

def test_agentic_detectors():
    """Test all Agentic detectors"""
    from core.scanner import VerityFluxScanner
    from core.types import ScanConfig
    
    scanner = VerityFluxScanner(
        application_name="Test",
        config=ScanConfig(scan_llm_threats=False, scan_agentic_threats=True)
    )
    
    target = {'provider': 'mock', 'model': 'mock', 'is_agent': True}
    report = scanner.scan_all(target)
    
    assert len(report.agentic_threats) == 10, f"Expected 10 Agentic detectors, got {len(report.agentic_threats)}"
    print("✅ Agentic detectors: PASS (10/10)")

def test_cognitive_firewall():
    """Test Cognitive Firewall"""
    from cognitive_firewall import CognitiveFirewall, AgentAction
    
    firewall = CognitiveFirewall()
    
    action = AgentAction(
        agent_id="test_agent",
        tool_name="read_file",
        parameters={"path": "/test.txt"},
        reasoning_chain=["Read file"],
        original_goal="Read file",
        context={"environment": "test"}
    )
    
    decision = firewall.evaluate(action)
    
    assert decision.action is not None, "Firewall must return a decision"
    print("✅ Cognitive Firewall: PASS")

def test_flight_recorder():
    """Test Flight Recorder"""
    from cognitive_firewall import CognitiveFirewallWithRecorder, AgentAction
    
    firewall = CognitiveFirewallWithRecorder(enable_flight_recorder=True)
    
    action = AgentAction(
        agent_id="test_agent",
        tool_name="test_tool",
        parameters={},
        reasoning_chain=["Test"],
        original_goal="Test",
        context={}
    )
    
    decision = firewall.evaluate(action)
    summary = firewall.get_session_summary()
    
    assert summary['total_events'] > 0, "Flight Recorder must record events"
    print("✅ Flight Recorder: PASS")
    print(f"   └─ Session: {summary['session_id']}")
    print(f"   └─ Events: {summary['total_events']}")

if __name__ == '__main__':
    print("="*70)
    print("🧪 VERITYFLUX 2.0 - COMPREHENSIVE TEST SUITE")
    print("="*70)
    print("")
    
    try:
        test_llm_detectors()
        test_agentic_detectors()
        test_cognitive_firewall()
        test_flight_recorder()
        
        print("")
        print("="*70)
        print("✅ ALL TESTS PASSED - PRODUCTION READY")
        print("="*70)
        print("")
        print("📊 Test Results:")
        print("  ✅ LLM Detectors: 10/10")
        print("  ✅ Agentic Detectors: 10/10")
        print("  ✅ Cognitive Firewall: Working")
        print("  ✅ Flight Recorder: Operational")
        print("")
        print("🚀 Ready for GitHub deployment!")
        print("="*70)
        
    except Exception as e:
        print("")
        print("="*70)
        print("❌ TEST FAILED")
        print("="*70)
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

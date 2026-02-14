import pytest

from cognitive_firewall.firewall import (
    EnhancedCognitiveFirewall,
    AgentAction,
    FirewallAction,
    Vulnerability,
    VulnerabilitySeverity,
)
from core.types import LLMThreat, AgenticThreat


def _make_firewall():
    return EnhancedCognitiveFirewall()


def test_hard_block_on_sql_injection():
    fw = _make_firewall()
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT password FROM admin_users"},
        reasoning_chain=["routine query"],
        original_goal="generate report",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.BLOCK


def test_hard_block_on_web_shell_write():
    fw = _make_firewall()
    action = AgentAction(
        agent_id="tester",
        tool_name="write_file",
        parameters={"path": "/var/www/shell.php", "content": "<?php system($_GET['cmd']); ?>"},
        reasoning_chain=["create log file"],
        original_goal="store logs",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.BLOCK


def test_allow_benign_query():
    fw = _make_firewall()
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT COUNT(*) FROM users"},
        reasoning_chain=["dashboard metrics"],
        original_goal="update dashboard",
    )
    decision = fw.evaluate(action)
    assert decision.action in (FirewallAction.ALLOW, FirewallAction.LOG_ONLY)


def test_owasp_critical_forces_block(monkeypatch):
    fw = _make_firewall()
    critical = Vulnerability(
        id="LLM01",
        name="Prompt Injection",
        description="Test critical vuln",
        severity=VulnerabilitySeverity.CRITICAL,
        pattern=".*",
        components=["llm"],
    )
    monkeypatch.setattr(fw, "_check_vulnerability_database", lambda *_: [critical])
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT 1"},
        reasoning_chain=["test"],
        original_goal="test",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.BLOCK


def test_owasp_high_requires_approval(monkeypatch):
    fw = _make_firewall()
    high = Vulnerability(
        id="LLM02",
        name="Sensitive Data",
        description="Test high vuln",
        severity=VulnerabilitySeverity.HIGH,
        pattern=".*",
        components=["llm"],
    )
    monkeypatch.setattr(fw, "_check_vulnerability_database", lambda *_: [high])
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT 1"},
        reasoning_chain=["test"],
        original_goal="test",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.REQUIRE_APPROVAL


@pytest.mark.parametrize("threat_id", [t.value for t in LLMThreat])
def test_all_llm_top10_critical_blocks(monkeypatch, threat_id):
    fw = _make_firewall()
    critical = Vulnerability(
        id=threat_id,
        name=threat_id,
        description="LLM critical",
        severity=VulnerabilitySeverity.CRITICAL,
        pattern=".*",
        components=["llm"],
    )
    monkeypatch.setattr(fw, "_check_vulnerability_database", lambda *_: [critical])
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT 1"},
        reasoning_chain=["test"],
        original_goal="test",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.BLOCK


@pytest.mark.parametrize("threat_id", [t.value for t in AgenticThreat])
def test_all_agentic_top10_high_requires_approval(monkeypatch, threat_id):
    fw = _make_firewall()
    high = Vulnerability(
        id=threat_id,
        name=threat_id,
        description="Agentic high",
        severity=VulnerabilitySeverity.HIGH,
        pattern=".*",
        components=["agentic"],
    )
    monkeypatch.setattr(fw, "_check_vulnerability_database", lambda *_: [high])
    action = AgentAction(
        agent_id="tester",
        tool_name="run_sql_query",
        parameters={"query": "SELECT 1"},
        reasoning_chain=["test"],
        original_goal="test",
    )
    decision = fw.evaluate(action)
    assert decision.action == FirewallAction.REQUIRE_APPROVAL

from __future__ import annotations

import pytest


@pytest.mark.regression
def test_legacy_core_endpoints_still_return_expected_shapes(suite):
    governance = suite.governance_metrics()
    interop = suite.interoperability_report()
    cards = suite.threat_cards()
    coverage = suite.threat_coverage()

    assert 'incidents_total' in governance
    assert 'recent_timelines' in governance
    assert 'protocol_counts' in interop
    assert 'recent_handoffs' in interop
    assert cards.get('total', 0) >= 5
    assert 'coverage_pct' in coverage


@pytest.mark.regression
def test_tessera_basic_register_request_validate_flow_remains_working(suite):
    agent_id = suite.unique('core-agent')
    session_id = suite.unique('core-session')

    registered = suite.register_agent(agent_id, allowed_tools=['read_file'], allowed_roles=['analyst'])
    assert registered.status == 200, registered.body
    assert registered.body.get('agent_id') == agent_id

    token = suite.request_token(agent_id, 'read_file', role='analyst', session_id=session_id, memory_state='core-state')
    assert token.status == 200 and token.body.get('success') is True, token.body
    assert token.body.get('token')

    validated = suite.validate_token(token.body['token'], 'read_file')
    assert validated.status == 200, validated.body
    assert validated.body.get('valid') is True, validated.body


@pytest.mark.regression
def test_verityflux_basic_endpoint_shapes_remain_stable(suite):
    reasoning = suite.reasoning_intercept(
        suite.unique('vf-safe-agent'),
        session_id=suite.unique('vf-safe-session'),
        thinking_block='Summarize the request and check whether the tool is necessary.',
        original_goal='Review a benign handoff',
    )
    assert reasoning.status == 200, reasoning.body
    assert {'action', 'risk_score', 'violations'}.issubset(reasoning.body.keys())

    protocol = suite.protocol_integrity_analyze({
        'protocol': 'mcp',
        'agent_id': suite.unique('vf-protocol-agent'),
        'tool_name': 'browser_fetch',
        'arguments': {'query': 'status page'},
        'session_id': suite.unique('vf-protocol-session'),
        'schema_version': '1',
        'contract_id': 'safe-contract',
        'route': [{'agent_id': 'hop-1', 'authenticated': True, 'schema_version': '1', 'contract_id': 'safe-contract', 'signature_required': False}],
        'metadata': {'framework_tags': ['mcp'], 'standards_tags': ['mcp']},
        'identity_valid': True,
        'has_sender_binding': True,
    })
    assert protocol.status == 200, protocol.body
    assert {'finding_count', 'overall_severity', 'overall_risk_score'}.issubset(protocol.body.keys())

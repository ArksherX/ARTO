from tessera.registry import TesseraRegistry


def test_trust_score_degrades_on_dependency_failure():
    registry = TesseraRegistry()
    agent = registry.get_agent("mock_test")
    if agent is None:
        return
    agent.trust_dependencies.append("dep_1")
    registry.record_dependency_failure(agent.agent_id, "dep_1", amount=10.0)
    assert agent.trust_score <= 90.0

from tessera.registry import TesseraRegistry


def test_registry_loads_agents():
    registry = TesseraRegistry()
    agents = registry.list_agents()
    assert len(agents) > 0

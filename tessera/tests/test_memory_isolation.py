from tessera.memory_isolation import MemoryIsolationManager


def test_memory_isolation_sessions():
    manager = MemoryIsolationManager()
    s1 = manager.create_session("agent_1")
    s2 = manager.create_session("agent_1")

    manager.store_memory(s1, "k", "v1")
    manager.store_memory(s2, "k", "v2")

    assert manager.get_memory(s1, "k") == "v1"
    assert manager.get_memory(s2, "k") == "v2"
    assert manager.verify_integrity(s1) is True

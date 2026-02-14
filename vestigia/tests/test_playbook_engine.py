import json
from pathlib import Path

from core.playbook_engine import PlaybookEngine, PlaybookStore, PlaybookExecutionStore


def test_playbook_match_and_execute(tmp_path):
    playbook_path = tmp_path / "playbooks.yml"
    playbook_path.write_text(
        """
        - name: test_playbook
          description: "Test playbook"
          trigger:
            min_risk: 90
          steps:
            - alert_security
        """
    )

    execution_path = tmp_path / "executions.json"
    store = PlaybookStore(path=str(playbook_path))
    exec_store = PlaybookExecutionStore(path=str(execution_path))
    engine = PlaybookEngine(store=store, execution_store=exec_store)

    event = {"actor_id": "agent-1", "action_type": "SECURITY_SCAN", "status": "WARNING"}
    matches = engine.match(event, risk_score=95)
    assert len(matches) == 1

    payload = engine.execute(matches[0], event, risk_score=95)
    assert payload["playbook_name"] == "test_playbook"

    stored = json.loads(execution_path.read_text())
    assert stored["executions"]

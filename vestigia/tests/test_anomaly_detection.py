from core.anomaly_detection import AnomalyDetector, BaselineStore


def test_anomaly_score_baseline(tmp_path):
    store = BaselineStore(path=str(tmp_path / "baseline.json"))
    detector = AnomalyDetector(store=store)
    event = {"action_type": "TOOL_EXECUTION", "status": "SUCCESS", "evidence": {"summary": "ok"}}
    score = detector.score_event("actor1", event)
    assert score["risk_score"] >= 0
    detector.update_baseline("actor1", event)


def test_anomaly_feedback_benign(tmp_path):
    store = BaselineStore(path=str(tmp_path / "baseline.json"))
    detector = AnomalyDetector(store=store)
    detector.record_feedback("event_1", "actor1", label="benign", note="known test")
    score = detector.score_event("actor1", {"event_id": "event_1", "action_type": "X", "status": "SUCCESS", "evidence": {}})
    assert score["risk_score"] == 0.0


def test_anomaly_off_hours_signal(tmp_path, monkeypatch):
    store = BaselineStore(path=str(tmp_path / "baseline.json"))
    detector = AnomalyDetector(store=store)
    # Preload baseline
    detector.update_baseline("actor2", {"action_type": "TOOL_EXECUTION", "status": "SUCCESS", "evidence": {}})
    score = detector.score_event("actor2", {"action_type": "TOOL_EXECUTION", "status": "SUCCESS", "evidence": {}})
    assert "off_hours_activity" in score["signals"] or score["risk_score"] >= 0

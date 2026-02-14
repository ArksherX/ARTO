from core.risk_forecasting import RiskHistoryStore, RiskForecaster


def test_risk_forecast_with_history(tmp_path):
    store = RiskHistoryStore(path=str(tmp_path / "risk.json"))
    for i in range(10):
        store.append("agent-1", f"evt-{i}", risk_score=10 + i * 5, signals=["test"])

    forecaster = RiskForecaster(store=store)
    forecast = forecaster.forecast("agent-1", horizon_hours=24)
    assert forecast["predicted_risk"] > 0
    assert forecast["confidence_interval"][1] >= forecast["confidence_interval"][0]

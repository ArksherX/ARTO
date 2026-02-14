#!/usr/bin/env python3
"""
Example usage of the Vestigia Python SDK.
"""

from sdk.python.vestigia_client import VestigiaClient


def main():
    client = VestigiaClient(base_url="http://localhost:8000", api_key="YOUR_API_KEY")

    event = client.create_event(
        actor_id="agent-42",
        action_type="TOOL_EXECUTION",
        status="SUCCESS",
        evidence={"summary": "Ran analysis", "metadata": {"tool": "analyze_csv"}},
    )
    print("Event:", event)

    results = client.nl_query("high risk events for agent-42 last week")
    print("NL Query results:", results.get("total"))

    forecast = client.risk_forecast("agent-42", horizon_hours=24)
    print("Risk forecast:", forecast)


if __name__ == "__main__":
    main()

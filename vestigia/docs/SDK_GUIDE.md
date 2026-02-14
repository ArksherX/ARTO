# Vestigia SDK Guide

## Python SDK

```python
from sdk.python.vestigia_client import VestigiaClient

client = VestigiaClient(
    base_url="http://localhost:8000",
    api_key="YOUR_API_KEY"
)

client.create_event(
    actor_id="agent-1",
    action_type="TOOL_EXECUTION",
    status="SUCCESS",
    evidence={"summary": "Completed job"}
)
```

### Multi-Tenant Provisioning (Platform Admin)
```python
client = VestigiaClient(
    base_url="http://localhost:8000",
    platform_admin_key="PLATFORM_ADMIN_KEY"
)
tenant = client.create_tenant(
    name="Acme Corp",
    plan="enterprise",
    admin_email="security@acme.com"
)
```

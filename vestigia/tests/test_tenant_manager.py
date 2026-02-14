from core.tenant_manager import TenantStore, PLAN_LIMITS


def test_tenant_limits_and_usage(tmp_path):
    store = TenantStore(path=str(tmp_path / "tenants.json"))
    tenant = store.create_tenant("TestCo", plan="free")
    limits = store.get_plan_limits(tenant["tenant_id"])
    assert limits["events_per_day"] == PLAN_LIMITS["free"]["events_per_day"]

    store.record_usage(tenant["tenant_id"], events=5)
    assert store.get_usage(tenant["tenant_id"]) >= 5


def test_create_user_invalid_role(tmp_path):
    store = TenantStore(path=str(tmp_path / "tenants.json"))
    tenant = store.create_tenant("TestCo", plan="free")
    user = store.create_user(tenant["tenant_id"], email="a@test.co", role="badrole")
    assert user["role"] == "viewer"

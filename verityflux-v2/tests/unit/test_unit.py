#!/usr/bin/env python3
"""
VerityFlux Enterprise - Unit Tests
Comprehensive tests for core modules
"""

import pytest
import asyncio
import time
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

class TestRateLimiting:
    """Test rate limiting module."""
    
    def test_token_bucket_allows_within_limit(self):
        """Test that requests within limit are allowed."""
        from verityflux_enterprise.core.rate_limiting import InMemoryRateLimiter, RateLimitConfig
        
        config = RateLimitConfig(default_requests_per_minute=10)
        limiter = InMemoryRateLimiter(config)
        
        # Should allow first 10 requests
        for i in range(10):
            allowed, headers = limiter.is_allowed(f"user-{i % 2}")
            # First requests should be allowed
            assert "X-RateLimit-Limit" in headers
    
    def test_token_bucket_blocks_over_limit(self):
        """Test that requests over limit are blocked."""
        from verityflux_enterprise.core.rate_limiting import InMemoryRateLimiter, RateLimitConfig
        
        config = RateLimitConfig(
            default_requests_per_minute=5,
            burst_multiplier=1.0  # No burst
        )
        limiter = InMemoryRateLimiter(config)
        
        # Exhaust the limit
        for _ in range(5):
            limiter.is_allowed("test-user")
        
        # Next request should be blocked
        allowed, headers = limiter.is_allowed("test-user")
        assert not allowed
        assert "Retry-After" in headers
    
    def test_different_users_have_separate_limits(self):
        """Test that different users have independent limits."""
        from verityflux_enterprise.core.rate_limiting import InMemoryRateLimiter, RateLimitConfig
        
        config = RateLimitConfig(default_requests_per_minute=2, burst_multiplier=1.0)
        limiter = InMemoryRateLimiter(config)
        
        # User A uses their limit
        limiter.is_allowed("user-a")
        limiter.is_allowed("user-a")
        allowed_a, _ = limiter.is_allowed("user-a")
        
        # User B should still have their limit
        allowed_b, _ = limiter.is_allowed("user-b")
        
        assert not allowed_a  # User A blocked
        assert allowed_b  # User B allowed
    
    def test_endpoint_specific_limits(self):
        """Test endpoint-specific rate limits."""
        from verityflux_enterprise.core.rate_limiting import InMemoryRateLimiter, RateLimitConfig
        
        config = RateLimitConfig(
            default_requests_per_minute=100,
            auth_requests_per_minute=5,
            burst_multiplier=1.0
        )
        limiter = InMemoryRateLimiter(config)
        
        # Auth endpoint should have lower limit
        for _ in range(5):
            limiter.is_allowed("user", endpoint="/api/v1/auth/login")
        
        allowed, headers = limiter.is_allowed("user", endpoint="/api/v1/auth/login")
        assert not allowed
        
        # Regular endpoint should still work
        allowed, _ = limiter.is_allowed("user", endpoint="/api/v1/agents")
        assert allowed


# =============================================================================
# OBSERVABILITY TESTS
# =============================================================================

class TestMetrics:
    """Test metrics module."""
    
    def test_counter_increment(self):
        """Test counter increments correctly."""
        from verityflux_enterprise.core.observability import MetricsRegistry
        
        registry = MetricsRegistry()
        
        registry.counter_inc("test_counter")
        registry.counter_inc("test_counter")
        registry.counter_inc("test_counter", 5)
        
        output = registry.export_prometheus()
        assert "test_counter 7" in output
    
    def test_counter_with_labels(self):
        """Test counter with labels."""
        from verityflux_enterprise.core.observability import MetricsRegistry
        
        registry = MetricsRegistry()
        
        registry.counter_inc("requests", labels={"method": "GET", "status": "200"})
        registry.counter_inc("requests", labels={"method": "POST", "status": "201"})
        registry.counter_inc("requests", labels={"method": "GET", "status": "200"})
        
        output = registry.export_prometheus()
        assert 'requests{method="GET",status="200"} 2' in output
        assert 'requests{method="POST",status="201"} 1' in output
    
    def test_gauge_set(self):
        """Test gauge setting."""
        from verityflux_enterprise.core.observability import MetricsRegistry
        
        registry = MetricsRegistry()
        
        registry.gauge_set("temperature", 25.5)
        registry.gauge_set("temperature", 30.0)
        
        output = registry.export_prometheus()
        assert "temperature 30.0" in output
    
    def test_histogram_observe(self):
        """Test histogram observations."""
        from verityflux_enterprise.core.observability import MetricsRegistry
        
        registry = MetricsRegistry()
        
        registry.histogram_observe("request_duration", 0.1)
        registry.histogram_observe("request_duration", 0.5)
        registry.histogram_observe("request_duration", 1.5)
        
        output = registry.export_prometheus()
        assert "request_duration_count 3" in output
        assert "request_duration_sum 2.1" in output
    
    def test_prometheus_format(self):
        """Test Prometheus export format."""
        from verityflux_enterprise.core.observability import MetricsRegistry
        
        registry = MetricsRegistry()
        registry.counter_inc("http_requests_total", labels={"path": "/api"})
        
        output = registry.export_prometheus()
        assert "# TYPE http_requests_total counter" in output


class TestHealthChecker:
    """Test health checker."""
    
    @pytest.mark.asyncio
    async def test_health_check_registration(self):
        """Test registering and running health checks."""
        from verityflux_enterprise.core.observability import HealthChecker, HealthCheckResult
        
        checker = HealthChecker()
        
        def always_healthy():
            return True
        
        def always_unhealthy():
            return HealthCheckResult(name="db", healthy=False, message="Connection failed")
        
        checker.register("service1", always_healthy)
        checker.register("service2", always_unhealthy)
        
        results = await checker.run_all()
        
        assert not results["healthy"]  # Overall unhealthy
        assert len(results["checks"]) == 2
    
    @pytest.mark.asyncio
    async def test_health_check_handles_exceptions(self):
        """Test that health checks handle exceptions gracefully."""
        from verityflux_enterprise.core.observability import HealthChecker
        
        checker = HealthChecker()
        
        def failing_check():
            raise Exception("Database connection failed")
        
        checker.register("database", failing_check)
        
        results = await checker.run_all()
        
        assert not results["healthy"]
        assert "Database connection failed" in results["checks"][0]["message"]


# =============================================================================
# SDK TESTS
# =============================================================================

class TestVerityFluxSDK:
    """Test Python SDK."""
    
    def test_client_initialization(self):
        """Test client initializes correctly."""
        from verityflux_enterprise.sdk.python.verityflux_sdk import VerityFluxClient
        
        client = VerityFluxClient(
            base_url="http://localhost:8000",
            api_key="vf_test_key",
            agent_name="test-agent",
            auto_register=False,
        )
        
        assert client.base_url == "http://localhost:8000"
        assert client.api_key == "vf_test_key"
        assert client.agent_name == "test-agent"
    
    def test_approval_required_exception(self):
        """Test ApprovalRequired exception."""
        from verityflux_enterprise.sdk.python.verityflux_sdk import ApprovalRequired
        
        exc = ApprovalRequired("apr-123", "Test action requires approval")
        
        assert exc.approval_id == "apr-123"
        assert "apr-123" in str(exc)
    
    def test_action_denied_exception(self):
        """Test ActionDenied exception."""
        from verityflux_enterprise.sdk.python.verityflux_sdk import ActionDenied
        
        exc = ActionDenied("Policy violation", ["rule1", "rule2"])
        
        assert exc.reason == "Policy violation"
        assert len(exc.violations) == 2


# =============================================================================
# INTEGRATION TESTS (Mock API)
# =============================================================================

class TestLangChainIntegration:
    """Test LangChain integration."""
    
    def test_callback_handler_initialization(self):
        """Test callback handler initializes."""
        try:
            from verityflux_enterprise.sdk.integrations.langchain_integration import (
                VerityFluxCallbackHandler,
                LANGCHAIN_AVAILABLE
            )
            
            if not LANGCHAIN_AVAILABLE:
                pytest.skip("LangChain not installed")
            
            handler = VerityFluxCallbackHandler(
                api_url="http://localhost:8000",
                api_key="vf_test",
                agent_name="test-agent",
            )
            
            assert handler.agent_name == "test-agent"
        except ImportError:
            pytest.skip("LangChain integration not available")


# =============================================================================
# OFFLINE UPDATES TESTS
# =============================================================================

class TestOfflineUpdates:
    """Test offline update system."""
    
    def test_update_manifest_serialization(self):
        """Test manifest serialization."""
        from verityflux_enterprise.core.offline_updates import UpdateManifest
        
        manifest = UpdateManifest(
            version="1.0.0",
            created_at="2025-01-29T00:00:00",
            created_by="system",
            description="Test update",
            vulnerabilities_count=10,
        )
        
        data = manifest.to_dict()
        
        assert data["version"] == "1.0.0"
        assert data["vulnerabilities_count"] == 10
    
    def test_update_manifest_deserialization(self):
        """Test manifest deserialization."""
        from verityflux_enterprise.core.offline_updates import UpdateManifest
        
        data = {
            "version": "2.0.0",
            "created_at": "2025-01-29T12:00:00",
            "created_by": "admin",
            "description": "Major update",
            "vulnerabilities_count": 20,
            "policies_count": 5,
            "rules_count": 10,
            "checksums": {"vulns.json": "abc123"},
            "signature": "sig123",
        }
        
        manifest = UpdateManifest.from_dict(data)
        
        assert manifest.version == "2.0.0"
        assert manifest.vulnerabilities_count == 20
        assert manifest.checksums["vulns.json"] == "abc123"


# =============================================================================
# API ENDPOINT TESTS (using TestClient)
# =============================================================================

class TestAPIEndpoints:
    """Test API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi.testclient import TestClient
        from verityflux_enterprise.api.v2 import app
        return TestClient(app)
    
    def test_health_endpoint(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_ready_endpoint(self, client):
        """Test readiness endpoint."""
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["ready"] == True
    
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "VerityFlux" in data["name"]
    
    def test_login_endpoint(self, client):
        """Test login endpoint."""
        response = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
    
    def test_unauthorized_access(self, client):
        """Test unauthorized access is rejected."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
    
    def test_vulnerabilities_list(self, client):
        """Test listing vulnerabilities."""
        # First login
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        # Get vulnerabilities
        response = client.get(
            "/api/v1/vulnerabilities",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0
    
    def test_owasp_llm_top_10(self, client):
        """Test OWASP LLM Top 10 endpoint."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.get(
            "/api/v1/vulnerabilities/owasp/llm",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 10
        assert any(v["id"] == "LLM01" for v in data)
    
    def test_owasp_agentic_top_10(self, client):
        """Test OWASP Agentic Top 10 endpoint."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.get(
            "/api/v1/vulnerabilities/owasp/agentic",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 10
        assert any(v["id"] == "ASI01" for v in data)
    
    def test_create_scan(self, client):
        """Test creating a scan."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.post(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "target_type": "custom",
                "name": "test-agent"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "created"
    
    def test_create_approval(self, client):
        """Test creating an approval request."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.post(
            "/api/v1/approvals",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "agent_id": "agent-test",
                "agent_name": "test-agent",
                "tool_name": "file_write",
                "action": "write",
                "parameters": {"path": "/test"},
                "risk_score": 50.0
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["status"] == "pending"
    
    def test_auto_approve_low_risk(self, client):
        """Test auto-approval for low-risk actions."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.post(
            "/api/v1/approvals",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "agent_id": "agent-test",
                "agent_name": "test-agent",
                "tool_name": "calculator",
                "action": "calculate",
                "parameters": {},
                "risk_score": 5.0  # Very low risk
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "auto_approved"
    
    def test_ingest_event(self, client):
        """Test ingesting a security event."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.post(
            "/api/v1/soc/events",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "agent_id": "agent-test",
                "agent_name": "test-agent",
                "event_type": "tool_call",
                "severity": "info",
                "decision": "allow",
                "risk_score": 10.0
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
    
    def test_soc_metrics(self, client):
        """Test SOC metrics endpoint."""
        login_resp = client.post("/api/v1/auth/login", json={
            "email": "admin@verityflux.local",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        
        response = client.get(
            "/api/v1/soc/metrics",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert "alerts" in data
        assert "agents" in data


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

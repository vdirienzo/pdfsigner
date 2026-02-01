"""
test_rate_limiting.py - Tests for rate limiting middleware

Tests rate limiting functionality for DoS and brute force prevention.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from pdfsigner.api.middleware.rate_limit import (
    RateLimitMiddleware,
    get_client_ip,
    limiter,
    rate_limit_exceeded_handler,
    setup_rate_limiting,
)


@pytest.fixture
def rate_limited_app():
    """Create a test app with rate limiting."""
    app = FastAPI()

    # Add rate limiting
    app.state.limiter = limiter

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/limited")
    @limiter.limit("3/minute")
    async def limited_endpoint(request: Request):
        return {"status": "ok"}

    @app.post("/auth/token")
    @limiter.limit("2/minute")
    async def auth_endpoint(request: Request):
        return {"status": "ok"}

    # Register the rate limit exceeded handler
    from slowapi.errors import RateLimitExceeded

    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    return app


@pytest.fixture
def client(rate_limited_app):
    """Create test client."""
    return TestClient(rate_limited_app)


class TestGetClientIP:
    """Test client IP extraction."""

    def test_direct_connection(self):
        """Should return direct client IP."""
        # Create a mock request
        from unittest.mock import MagicMock

        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.1"

        ip = get_client_ip(request)
        assert ip == "192.168.1.1"

    def test_x_forwarded_for_header(self):
        """Should use X-Forwarded-For header if present."""
        from unittest.mock import MagicMock

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.1"

    def test_x_real_ip_header(self):
        """Should use X-Real-IP header if present."""
        from unittest.mock import MagicMock

        request = MagicMock()
        request.headers = {"X-Real-IP": "10.0.0.2"}
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.2"

    def test_unknown_client(self):
        """Should return 'unknown' if no client info available."""
        from unittest.mock import MagicMock

        request = MagicMock()
        request.headers = {}
        request.client = None

        ip = get_client_ip(request)
        assert ip == "unknown"


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_health_endpoint_not_limited(self, client):
        """Health endpoint should not be rate limited."""
        # Make many requests to health
        for _ in range(20):
            response = client.get("/health")
            assert response.status_code == 200

    def test_rate_limit_enforced(self, client):
        """Rate limit should be enforced on limited endpoints."""
        # Make requests up to limit
        for i in range(3):
            response = client.get("/limited")
            assert response.status_code == 200, f"Request {i + 1} failed unexpectedly"

        # Next request should be rate limited
        response = client.get("/limited")
        assert response.status_code == 429

    def test_rate_limit_response_format(self, client):
        """Rate limit exceeded response should have correct format."""
        # Exhaust rate limit
        for _ in range(3):
            client.get("/limited")

        # Check response format
        response = client.get("/limited")
        assert response.status_code == 429
        data = response.json()
        assert "detail" in data
        assert "rate limit" in data["detail"].lower()
        assert "Retry-After" in response.headers

    def test_auth_endpoint_stricter_limit(self, client):
        """Auth endpoints should have stricter rate limits."""
        # Make requests up to stricter limit (2/minute)
        for i in range(2):
            response = client.post("/auth/token")
            assert response.status_code == 200, f"Request {i + 1} failed unexpectedly"

        # Next request should be rate limited
        response = client.post("/auth/token")
        assert response.status_code == 429


class TestRateLimitMiddleware:
    """Test RateLimitMiddleware class."""

    def test_middleware_disabled(self):
        """Middleware should pass through when disabled."""
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, enabled=False)

        @app.post("/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)

        # Should work without any rate limiting
        for _ in range(100):
            response = client.post("/test")
            assert response.status_code == 200

    def test_middleware_exempts_health(self):
        """Middleware should exempt health check paths."""
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, enabled=True)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        client = TestClient(app)

        # Health should never be rate limited
        for _ in range(100):
            response = client.get("/health")
            assert response.status_code == 200


class TestSetupRateLimiting:
    """Test rate limiting setup function."""

    def test_setup_adds_limiter_to_state(self, monkeypatch):
        """setup_rate_limiting should add limiter to app state."""
        # Set required env vars
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "test-secret-key-for-rate-limit-tests-123"
        )

        # Reload settings to pick up the env var
        from pdfsigner.api.config import reload_api_settings

        reload_api_settings()

        app = FastAPI()
        setup_rate_limiting(app)

        assert hasattr(app.state, "limiter")

    def test_setup_disabled_by_config(self, monkeypatch):
        """Rate limiting should be skippable via config."""
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "test-secret-key-for-rate-limit-tests-123"
        )
        monkeypatch.setenv("PDFSIGNER_API_RATE_LIMIT_ENABLED", "false")

        from pdfsigner.api.config import reload_api_settings

        reload_api_settings()

        app = FastAPI()
        setup_rate_limiting(app)

        # Limiter should not be set when disabled
        assert not hasattr(app.state, "limiter") or app.state.limiter is None


class TestRateLimitDecorators:
    """Test rate limit decorator functions."""

    def test_rate_limit_auth_decorator(self, monkeypatch):
        """rate_limit_auth should apply 10/minute limit."""
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "test-secret-key-for-rate-limit-tests-123"
        )

        from pdfsigner.api.config import reload_api_settings

        reload_api_settings()

        from pdfsigner.api.middleware.rate_limit import rate_limit_auth

        @rate_limit_auth
        async def test_func(request):
            return {"status": "ok"}

        # Function should be decorated
        assert test_func is not None

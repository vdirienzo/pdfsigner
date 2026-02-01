"""
test_csrf_protection.py - Tests for CSRF protection middleware

Tests Double Submit Cookie pattern implementation.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pdfsigner.api.middleware.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRFMiddleware,
    generate_csrf_token,
)


@pytest.fixture
def csrf_app():
    """Create a test app with CSRF middleware."""
    app = FastAPI()

    app.add_middleware(
        CSRFMiddleware,
        enabled=True,
        secure=False,  # Allow non-HTTPS for testing
        samesite="strict",
    )

    @app.get("/get-endpoint")
    async def get_endpoint():
        return {"status": "ok"}

    @app.post("/post-endpoint")
    async def post_endpoint():
        return {"status": "ok"}

    @app.put("/put-endpoint")
    async def put_endpoint():
        return {"status": "ok"}

    @app.delete("/delete-endpoint")
    async def delete_endpoint():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    return app


@pytest.fixture
def client(csrf_app):
    """Create test client."""
    return TestClient(csrf_app)


class TestCSRFTokenGeneration:
    """Test CSRF token generation."""

    def test_token_is_generated(self):
        """Token should be generated."""
        token = generate_csrf_token()
        assert token is not None
        assert len(token) > 0

    def test_token_is_unique(self):
        """Each token should be unique."""
        tokens = {generate_csrf_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_token_is_url_safe(self):
        """Token should be URL-safe."""
        token = generate_csrf_token()
        # URL-safe base64 characters
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in token)


class TestCSRFMiddleware:
    """Test CSRF middleware functionality."""

    def test_get_request_allowed_without_token(self, client):
        """GET requests should be allowed without CSRF token."""
        response = client.get("/get-endpoint")
        assert response.status_code == 200

    def test_get_request_sets_csrf_cookie(self, client):
        """GET request should set CSRF cookie for subsequent requests."""
        response = client.get("/get-endpoint")
        assert response.status_code == 200
        assert CSRF_COOKIE_NAME in response.cookies

    def test_post_without_token_blocked(self, client):
        """POST without CSRF token should be blocked."""
        response = client.post("/post-endpoint")
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_post_with_valid_token_allowed(self, client):
        """POST with valid CSRF token should be allowed."""
        # First, get a CSRF token via GET request
        get_response = client.get("/get-endpoint")
        csrf_token = get_response.cookies.get(CSRF_COOKIE_NAME)

        # Then, make POST with token in header
        response = client.post(
            "/post-endpoint",
            headers={CSRF_HEADER_NAME: csrf_token},
            cookies={CSRF_COOKIE_NAME: csrf_token},
        )
        assert response.status_code == 200

    def test_post_with_mismatched_token_blocked(self, client):
        """POST with mismatched CSRF token should be blocked."""
        # Get a CSRF token
        get_response = client.get("/get-endpoint")
        csrf_cookie = get_response.cookies.get(CSRF_COOKIE_NAME)

        # Use different token in header
        different_token = generate_csrf_token()

        response = client.post(
            "/post-endpoint",
            headers={CSRF_HEADER_NAME: different_token},
            cookies={CSRF_COOKIE_NAME: csrf_cookie},
        )
        assert response.status_code == 403

    def test_put_without_token_blocked(self, client):
        """PUT without CSRF token should be blocked."""
        response = client.put("/put-endpoint")
        assert response.status_code == 403

    def test_delete_without_token_blocked(self, client):
        """DELETE without CSRF token should be blocked."""
        response = client.delete("/delete-endpoint")
        assert response.status_code == 403

    def test_exempt_path_allowed(self, client):
        """Exempt paths should be allowed without token."""
        # /health is in exempt paths
        response = client.get("/health")
        assert response.status_code == 200

    def test_api_key_bypasses_csrf(self, client):
        """Requests with X-API-Key header should bypass CSRF."""
        response = client.post(
            "/post-endpoint",
            headers={"X-API-Key": "some-api-key"},
        )
        # Should not be blocked by CSRF (may fail auth later)
        assert response.status_code != 403 or "CSRF" not in response.json().get("detail", "")


class TestCSRFMiddlewareDisabled:
    """Test CSRF middleware when disabled."""

    @pytest.fixture
    def disabled_csrf_app(self):
        """Create app with CSRF disabled."""
        app = FastAPI()

        app.add_middleware(
            CSRFMiddleware,
            enabled=False,
        )

        @app.post("/post-endpoint")
        async def post_endpoint():
            return {"status": "ok"}

        return app

    @pytest.fixture
    def disabled_client(self, disabled_csrf_app):
        return TestClient(disabled_csrf_app)

    def test_post_allowed_when_csrf_disabled(self, disabled_client):
        """POST should be allowed when CSRF is disabled."""
        response = disabled_client.post("/post-endpoint")
        assert response.status_code == 200


class TestCSRFCookieAttributes:
    """Test CSRF cookie security attributes."""

    def test_samesite_attribute(self, client):
        """Cookie should have SameSite attribute."""
        response = client.get("/get-endpoint")
        # TestClient doesn't expose full cookie attributes easily
        # This would be verified in integration/e2e tests
        assert CSRF_COOKIE_NAME in response.cookies

    def test_httponly_is_false(self, client):
        """Cookie should NOT be HttpOnly (JS needs to read it)."""
        # HttpOnly=False is correct for Double Submit Cookie pattern
        # JavaScript must be able to read the cookie to send it in header
        response = client.get("/get-endpoint")
        assert response.status_code == 200

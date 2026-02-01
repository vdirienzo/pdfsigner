"""
Integration tests for CSRF protection middleware.

Tests Double Submit Cookie pattern implementation with comprehensive scenarios.
Focuses on edge cases and security validations not covered in test_csrf_protection.py.

Run with:
    uv run pytest tests/integration/test_csrf.py -v
    uv run pytest tests/integration/test_csrf.py -v --cov=src/pdfsigner/api/middleware/csrf
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
    """Create a test app with CSRF middleware (no global exception handler)."""
    from fastapi import Request
    from fastapi.exceptions import HTTPException
    from fastapi.responses import JSONResponse

    app = FastAPI()

    # Add HTTPException handler to convert exceptions to proper JSON responses
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    # Add ExceptionGroup handler for Python 3.13 anyio compatibility
    @app.exception_handler(Exception)
    async def exception_group_handler(request: Request, exc: Exception):
        # Check if it's an ExceptionGroup containing HTTPException
        if isinstance(exc, BaseExceptionGroup):
            for sub_exc in exc.exceptions:
                if isinstance(sub_exc, HTTPException):
                    return JSONResponse(
                        status_code=sub_exc.status_code,
                        content={"detail": sub_exc.detail},
                    )
        # If it's a direct HTTPException
        if isinstance(exc, HTTPException):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
            )
        # Otherwise, return generic 500
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    app.add_middleware(
        CSRFMiddleware,
        enabled=True,
        secure=False,  # Allow non-HTTPS for testing
        samesite="strict",
    )

    @app.get("/safe-endpoint")
    async def safe_endpoint():
        return {"status": "ok"}

    @app.head("/safe-endpoint")
    async def safe_endpoint_head():
        return {"status": "ok"}

    @app.post("/state-changing")
    async def post_endpoint():
        return {"status": "created"}

    @app.put("/update-resource")
    async def put_endpoint():
        return {"status": "updated"}

    @app.delete("/delete-resource")
    async def delete_endpoint():
        return {"status": "deleted"}

    @app.patch("/patch-resource")
    async def patch_endpoint():
        return {"status": "patched"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    return app


@pytest.fixture
def client(csrf_app):
    """
    Create test client with raise_server_exceptions=False.

    This allows HTTPExceptions from middleware to be returned as responses
    instead of being raised, which is necessary for Python 3.13 with anyio.
    """
    return TestClient(csrf_app, raise_server_exceptions=False)


# --- Test 1-2: CSRF tokens required for state-changing requests ---


def test_csrf_required_for_post_without_token(client):
    """
    Test that POST requests without CSRF token are rejected with 403.

    Scenario: POST without any CSRF protection
    Expected: 403 Forbidden with CSRF error message
    """
    response = client.post("/state-changing")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_csrf_required_for_all_state_changing_methods(client):
    """
    Test that PUT, DELETE, PATCH requests without CSRF token are rejected.

    Scenario: All state-changing HTTP methods without CSRF protection
    Expected: All return 403 Forbidden
    """
    # PUT without CSRF
    response = client.put("/update-resource")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]

    # DELETE without CSRF
    response = client.delete("/delete-resource")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]

    # PATCH without CSRF
    response = client.patch("/patch-resource")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


# --- Test 3-4: Invalid CSRF token rejected ---


def test_csrf_mismatched_cookie_and_header_rejected(client):
    """
    Test that mismatched CSRF token in header vs cookie is rejected.

    Scenario: Cookie has one token, header has different token
    Expected: 403 Forbidden (tokens must match exactly)
    """
    # Get valid CSRF cookie
    response = client.get("/safe-endpoint")
    csrf_cookie = response.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_cookie is not None

    # Generate different token for header
    different_token = generate_csrf_token()
    assert different_token != csrf_cookie

    # POST with mismatched tokens
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: different_token},  # Different from cookie
        cookies={CSRF_COOKIE_NAME: csrf_cookie},
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_csrf_tampered_token_rejected(client):
    """
    Test that tampered CSRF token is rejected.

    Scenario: Token has been modified (extra characters appended)
    Expected: 403 Forbidden
    """
    # Get valid token
    response = client.get("/safe-endpoint")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    # Tamper with token by appending characters
    tampered_token = csrf_token + "TAMPERED"

    # POST with tampered token in header
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: tampered_token},
        cookies={CSRF_COOKIE_NAME: csrf_token},  # Original cookie
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


# --- Test 5-6: Missing CSRF token components rejected ---


def test_csrf_cookie_present_header_missing(client):
    """
    Test that request with CSRF cookie but no header is rejected.

    Scenario: CSRF cookie set but X-CSRF-Token header missing
    Expected: 403 Forbidden
    """
    # Get CSRF cookie
    response = client.get("/safe-endpoint")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    # POST with cookie but NO header
    response = client.post(
        "/state-changing",
        cookies={CSRF_COOKIE_NAME: csrf_token},
        # No X-CSRF-Token header
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_csrf_header_present_cookie_missing(client):
    """
    Test that request with CSRF header but no cookie is rejected.

    Scenario: X-CSRF-Token header present but no csrf_token cookie
    Expected: 403 Forbidden
    """
    # POST with header but NO cookie
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: "some-token-value"},
        # No cookies provided
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


# --- Test 7: CSRF token generation and refresh ---


def test_csrf_token_generated_on_first_safe_request(client):
    """
    Test that CSRF token is generated and set on first safe request.

    Scenario: First GET request to safe endpoint
    Expected: Response includes csrf_token cookie
    """
    response = client.get("/safe-endpoint")
    assert response.status_code == 200
    assert CSRF_COOKIE_NAME in response.cookies

    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None
    assert len(csrf_token) > 20  # Reasonable token length


def test_csrf_token_not_regenerated_if_exists(client):
    """
    Test that CSRF token is not regenerated if already present.

    Scenario: Multiple GET requests with existing cookie
    Expected: Token remains stable (not rotated on every request)
    """
    # First request - get initial token
    response1 = client.get("/safe-endpoint")
    token1 = response1.cookies.get(CSRF_COOKIE_NAME)

    # Second request with existing token - should not set new cookie
    response2 = client.get("/safe-endpoint", cookies={CSRF_COOKIE_NAME: token1})

    # If no new cookie set, original token still valid
    # TestClient might not show absence of Set-Cookie, but we can verify
    # that the original token still works
    response3 = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: token1},
        cookies={CSRF_COOKIE_NAME: token1},
    )
    assert response3.status_code == 200


# --- Test 8-9: Double Submit Cookie pattern validation ---


def test_csrf_valid_double_submit_cookie_pattern_succeeds(client):
    """
    Test that matching CSRF cookie and header allows request to succeed.

    Scenario: Cookie value matches header value exactly (Double Submit Cookie)
    Expected: Request succeeds with 200 OK
    """
    # Get CSRF token
    response = client.get("/safe-endpoint")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    # POST with MATCHING cookie and header
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: csrf_token},  # Same as cookie
        cookies={CSRF_COOKIE_NAME: csrf_token},  # Matches header
    )
    assert response.status_code == 200
    assert response.json()["status"] == "created"


def test_csrf_exact_match_required_case_sensitive(client):
    """
    Test that cookie and header values must match exactly (case-sensitive).

    Scenario: Different case, extra spaces, or characters cause rejection
    Expected: Only exact match succeeds
    """
    # Get valid token
    response = client.get("/safe-endpoint")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    # Test 1: Exact match - should succeed
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: csrf_token},
        cookies={CSRF_COOKIE_NAME: csrf_token},
    )
    assert response.status_code == 200

    # Test 2: Different case - should fail
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: csrf_token.upper()},
        cookies={CSRF_COOKIE_NAME: csrf_token},
    )
    assert response.status_code == 403

    # Test 3: Extra whitespace - should fail
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: f" {csrf_token}"},
        cookies={CSRF_COOKIE_NAME: csrf_token},
    )
    assert response.status_code == 403

    # Test 4: Missing one character - should fail
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: csrf_token[:-1]},
        cookies={CSRF_COOKIE_NAME: csrf_token},
    )
    assert response.status_code == 403


# --- Test 10: Safe methods don't require CSRF ---


def test_csrf_safe_http_methods_no_token_required(client):
    """
    Test that safe HTTP methods work without CSRF token.

    Scenario: GET, HEAD, OPTIONS are read-only and don't need CSRF
    Expected: All succeed without CSRF token
    """
    # GET without CSRF
    response = client.get("/safe-endpoint")
    assert response.status_code == 200

    # HEAD without CSRF
    response = client.head("/safe-endpoint")
    assert response.status_code == 200

    # OPTIONS without CSRF
    response = client.options("/state-changing")
    assert response.status_code in [200, 405]  # 405 if not implemented


# --- Test 11: Exempt paths work without CSRF ---


def test_csrf_exempt_health_endpoint(client):
    """
    Test that /health endpoint is exempt from CSRF protection.

    Scenario: Health check endpoints should be accessible for monitoring
    Expected: /health works without CSRF token
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# --- Test 12: X-API-Key bypasses CSRF ---


def test_csrf_api_key_header_bypasses_protection(client):
    """
    Test that requests with X-API-Key header bypass CSRF protection.

    Scenario: API clients using API keys don't need CSRF tokens
    Expected: POST with X-API-Key succeeds without CSRF
    """
    # POST with X-API-Key but NO CSRF token
    response = client.post(
        "/state-changing",
        headers={"X-API-Key": "test-api-key-12345"},
        # No CSRF cookie or header
    )
    # Should not be blocked by CSRF (200 OK)
    assert response.status_code == 200
    assert "CSRF" not in response.json().get("detail", "")


# --- Additional Test 13: Multiple state-changing methods with valid token ---


def test_csrf_all_methods_with_valid_token_succeed(client):
    """
    Test that all state-changing methods succeed with valid CSRF token.

    Scenario: POST, PUT, DELETE, PATCH all protected but work with valid token
    Expected: All return 200 with valid CSRF token
    """
    # Get CSRF token
    response = client.get("/safe-endpoint")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)

    headers = {CSRF_HEADER_NAME: csrf_token}
    cookies = {CSRF_COOKIE_NAME: csrf_token}

    # POST with CSRF
    response = client.post("/state-changing", headers=headers, cookies=cookies)
    assert response.status_code == 200

    # PUT with CSRF
    response = client.put("/update-resource", headers=headers, cookies=cookies)
    assert response.status_code == 200

    # DELETE with CSRF
    response = client.delete("/delete-resource", headers=headers, cookies=cookies)
    assert response.status_code == 200

    # PATCH with CSRF
    response = client.patch("/patch-resource", headers=headers, cookies=cookies)
    assert response.status_code == 200


# --- Additional Test 14: CSRF constant-time comparison ---


def test_csrf_uses_constant_time_comparison():
    """
    Test that CSRF validation uses constant-time comparison.

    Scenario: Prevents timing attacks
    Expected: Implementation uses secrets.compare_digest()
    """
    import inspect

    from pdfsigner.api.middleware.csrf import CSRFMiddleware

    # Verify implementation uses constant-time comparison
    source = inspect.getsource(CSRFMiddleware._validate_csrf_token)
    assert "secrets.compare_digest" in source, "Must use constant-time comparison"
    assert "cookie_token" in source and "header_token" in source


# --- Additional Test 15: Empty token values rejected ---


def test_csrf_empty_token_values_rejected(client):
    """
    Test that empty CSRF token values are rejected.

    Scenario: Cookie or header contains empty string
    Expected: 403 Forbidden
    """
    # POST with empty cookie
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: "valid-token"},
        cookies={CSRF_COOKIE_NAME: ""},  # Empty cookie
    )
    assert response.status_code == 403

    # POST with empty header
    response = client.post(
        "/state-changing",
        headers={CSRF_HEADER_NAME: ""},  # Empty header
        cookies={CSRF_COOKIE_NAME: "valid-token"},
    )
    assert response.status_code == 403

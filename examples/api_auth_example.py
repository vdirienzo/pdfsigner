"""
API Authentication Usage Example.

This example shows how to use JWT and API key authentication in PDFSigner API routes.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from pdfsigner.api.middleware.auth import (
    User,
    get_current_active_user,
    get_current_user_or_api_key,
    require_admin_user,
    verify_api_key,
)

# Example router
router = APIRouter(prefix="/examples", tags=["examples"])


# --- Response Models ---


class ProtectedResponse(BaseModel):
    """Example protected endpoint response."""

    message: str
    user: str
    role: str


# --- Example 1: JWT Only Authentication ---


@router.get("/jwt-protected")
async def jwt_protected_route(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> ProtectedResponse:
    """
    Route protected with JWT authentication only.

    **Usage:**
    ```bash
    # 1. Get token
    curl -X POST http://localhost:8000/api/v1/auth/token \\
      -H "Content-Type: application/json" \\
      -d '{"username": "user", "password": "pass"}'

    # 2. Use token
    curl http://localhost:8000/api/v1/examples/jwt-protected \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    return ProtectedResponse(
        message="You are authenticated with JWT",
        user=current_user.username,
        role=current_user.role,
    )


# --- Example 2: API Key Only Authentication ---


@router.get("/api-key-protected")
async def api_key_protected_route(
    current_user: Annotated[User, Depends(verify_api_key)],
) -> ProtectedResponse:
    """
    Route protected with API key authentication only.

    **Usage:**
    ```bash
    # Configure API key in environment
    export PDFSIGNER_API_API_KEYS='["your-api-key-123"]'

    # Use API key
    curl http://localhost:8000/api/v1/examples/api-key-protected \\
      -H "X-API-Key: your-api-key-123"
    ```
    """
    return ProtectedResponse(
        message="You are authenticated with API Key",
        user=current_user.username,
        role=current_user.role,
    )


# --- Example 3: JWT OR API Key Authentication ---


@router.get("/flexible-protected")
async def flexible_protected_route(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ProtectedResponse:
    """
    Route that accepts EITHER JWT token OR API key.

    **Usage:**
    ```bash
    # Option 1: Use JWT token
    curl http://localhost:8000/api/v1/examples/flexible-protected \\
      -H "Authorization: Bearer YOUR_TOKEN"

    # Option 2: Use API key
    curl http://localhost:8000/api/v1/examples/flexible-protected \\
      -H "X-API-Key: your-api-key-123"
    ```
    """
    return ProtectedResponse(
        message="You are authenticated with JWT or API Key",
        user=current_user.username,
        role=current_user.role,
    )


# --- Example 4: Admin Only Route ---


@router.get("/admin-only")
async def admin_only_route(
    current_user: Annotated[User, Depends(require_admin_user)],
) -> ProtectedResponse:
    """
    Route that requires admin role.

    **Usage:**
    ```bash
    # Login as admin (username must be "admin" in demo mode)
    curl -X POST http://localhost:8000/api/v1/auth/token \\
      -H "Content-Type: application/json" \\
      -d '{"username": "admin", "password": "pass"}'

    # Use admin token
    curl http://localhost:8000/api/v1/examples/admin-only \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
    ```
    """
    return ProtectedResponse(
        message="You are an admin user",
        user=current_user.username,
        role=current_user.role,
    )


# --- Example 5: Public Route (No Authentication) ---


@router.get("/public")
async def public_route() -> dict[str, str]:
    """
    Public route that doesn't require authentication.

    **Usage:**
    ```bash
    curl http://localhost:8000/api/v1/examples/public
    ```
    """
    return {"message": "This is a public endpoint"}


# --- Configuration Examples ---


def configuration_examples() -> None:
    """
    Environment variable configuration examples.

    Add these to your .env file or export them:

    ```bash
    # JWT Configuration
    PDFSIGNER_API_JWT_SECRET_KEY="your-super-secret-key-change-in-production"
    PDFSIGNER_API_JWT_ALGORITHM="HS256"
    PDFSIGNER_API_JWT_EXPIRE_MINUTES="30"

    # API Key Configuration
    PDFSIGNER_API_API_KEY_HEADER="X-API-Key"
    PDFSIGNER_API_API_KEYS='["key1","key2","key3"]'

    # CORS (for web frontend)
    PDFSIGNER_API_CORS_ORIGINS='["http://localhost:3000","https://app.example.com"]'
    ```

    **IMPORTANT SECURITY NOTES:**
    - ALWAYS change JWT_SECRET_KEY in production
    - Use strong, random API keys (32+ characters)
    - Never commit API keys to version control
    - Use HTTPS in production
    - Enable proper CORS origins
    - In production, replace demo auth with real user database
    """


# --- Testing Examples ---


def testing_examples() -> None:
    """
    Examples for testing with pytest.

    ```python
    import pytest
    from fastapi.testclient import TestClient
    from pdfsigner.api.main import app

    client = TestClient(app)

    def test_login():
        response = client.post(
            "/api/v1/auth/token",
            json={"username": "user", "password": "pass"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_protected_route_with_token():
        # Get token
        login_response = client.post(
            "/api/v1/auth/token",
            json={"username": "user", "password": "pass"}
        )
        token = login_response.json()["access_token"]

        # Access protected route
        response = client.get(
            "/api/v1/examples/jwt-protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    def test_protected_route_without_token():
        response = client.get("/api/v1/examples/jwt-protected")
        assert response.status_code == 401

    def test_api_key_authentication():
        response = client.get(
            "/api/v1/examples/api-key-protected",
            headers={"X-API-Key": "test-key"}
        )
        # Will return 401 if key not in config.api_keys
        assert response.status_code in [200, 401]
    ```
    """


if __name__ == "__main__":
    print(__doc__)
    print("\n" + "=" * 60)
    print("JWT Authentication Flow:")
    print("=" * 60)
    print("""
    1. POST /api/v1/auth/token with username/password
    2. Receive JWT token in response
    3. Include token in Authorization header: "Bearer TOKEN"
    4. Token expires after 30 minutes (default)
    5. Refresh with POST /api/v1/auth/refresh
    """)

    print("\n" + "=" * 60)
    print("API Key Authentication Flow:")
    print("=" * 60)
    print("""
    1. Configure API keys in environment variables
    2. Include key in X-API-Key header
    3. No expiration (revoke by removing from config)
    """)

    print("\n" + "=" * 60)
    print("Security Best Practices:")
    print("=" * 60)
    print("""
    - Use environment variables for secrets
    - Rotate API keys regularly
    - Use short token expiration times
    - Implement rate limiting
    - Log authentication attempts
    - Use HTTPS in production
    - Replace demo auth with real user database
    """)

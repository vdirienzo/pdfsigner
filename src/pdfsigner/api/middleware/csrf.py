"""
csrf.py - CSRF Protection Middleware

Implements Double Submit Cookie pattern for CSRF protection.
OWASP: Cross-Site Request Forgery Prevention Cheat Sheet

Security considerations:
- Uses cryptographically secure random tokens
- SameSite=Strict cookie attribute
- Secure cookie in HTTPS mode
- Token validation on state-changing methods (POST, PUT, DELETE, PATCH)
"""

import secrets
from collections.abc import Callable

from fastapi import HTTPException, Request, Response, status
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

# Safe methods that don't require CSRF protection (read-only)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

# Paths exempt from CSRF (e.g., API key auth, webhooks)
CSRF_EXEMPT_PATHS = {
    "/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}

# Header name for CSRF token
CSRF_HEADER_NAME = "X-CSRF-Token"

# Cookie name for CSRF token
CSRF_COOKIE_NAME = "csrf_token"


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection using Double Submit Cookie pattern.

    How it works:
    1. Server sets a random CSRF token in a cookie
    2. Client must send the same token in the X-CSRF-Token header
    3. Server validates that cookie value matches header value

    This works because:
    - Attacker cannot read the cookie value (same-origin policy)
    - Attacker cannot set custom headers in cross-origin requests

    Usage:
        app.add_middleware(CSRFMiddleware, enabled=True, secure=True)
    """

    def __init__(
        self,
        app,
        enabled: bool = True,
        secure: bool = True,
        samesite: str = "strict",
        exempt_paths: set[str] | None = None,
    ):
        """
        Initialize CSRF middleware.

        Args:
            app: FastAPI application
            enabled: Whether to enable CSRF protection
            secure: Set Secure flag on cookie (requires HTTPS)
            samesite: SameSite cookie attribute (strict, lax, none)
            exempt_paths: Additional paths to exempt from CSRF
        """
        super().__init__(app)
        self.enabled = enabled
        self.secure = secure
        self.samesite = samesite
        self.exempt_paths = CSRF_EXEMPT_PATHS.copy()
        if exempt_paths:
            self.exempt_paths.update(exempt_paths)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with CSRF validation."""
        if not self.enabled:
            return await call_next(request)

        # Skip CSRF for safe methods
        if request.method in SAFE_METHODS:
            response = await call_next(request)
            # Ensure CSRF cookie is set for subsequent requests
            self._set_csrf_cookie_if_missing(request, response)
            return response

        # Skip CSRF for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Skip CSRF for API key authentication (X-API-Key header present)
        if request.headers.get("X-API-Key"):
            return await call_next(request)

        # Validate CSRF token
        if not self._validate_csrf_token(request):
            logger.warning(f"CSRF validation failed for {request.method} {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed",
            )

        response = await call_next(request)
        return response

    def _validate_csrf_token(self, request: Request) -> bool:
        """
        Validate CSRF token from cookie matches header.

        Returns:
            True if valid, False otherwise
        """
        # Get token from cookie
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        if not cookie_token:
            logger.debug("CSRF cookie not found")
            return False

        # Get token from header
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not header_token:
            logger.debug("CSRF header not found")
            return False

        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(cookie_token, header_token)

    def _set_csrf_cookie_if_missing(self, request: Request, response: Response) -> None:
        """Set CSRF cookie if not already present."""
        if CSRF_COOKIE_NAME not in request.cookies:
            token = generate_csrf_token()
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=token,
                httponly=False,  # JavaScript needs to read this
                secure=self.secure,
                samesite=self.samesite,
                path="/",
            )


def get_csrf_token(request: Request) -> str:
    """
    Get or create CSRF token for current request.

    Use this in templates or API responses to provide the token to clients.
    """
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = generate_csrf_token()
    return token


# Dependency for getting CSRF token in routes
async def csrf_token_dependency(request: Request) -> str:
    """FastAPI dependency to get CSRF token."""
    return get_csrf_token(request)

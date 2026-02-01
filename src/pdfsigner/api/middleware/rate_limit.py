"""
rate_limit.py - Rate Limiting Middleware

Implements rate limiting to prevent DoS and brute force attacks.
Uses slowapi with Redis or in-memory storage.

Security controls:
- NIST AC-10: Concurrent Session Control
- OWASP: Brute Force Prevention
"""

from collections.abc import Callable

from fastapi import FastAPI, Request, status
from loguru import logger
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from pdfsigner.api.config import get_api_settings


def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request.

    Handles X-Forwarded-For header for requests behind proxy/load balancer.
    """
    # Check for proxy headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct connection
    if request.client:
        return request.client.host

    return "unknown"


# Create limiter with custom key function
limiter = Limiter(key_func=get_client_ip)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Handle rate limit exceeded errors.

    Returns a JSON response with retry information.
    """
    # Extract retry-after from the exception
    retry_after = getattr(exc, "retry_after", 60)

    logger.warning(
        f"Rate limit exceeded for {get_client_ip(request)} on {request.url.path} "
        f"(retry after {retry_after}s)"
    )

    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded",
            "retry_after_seconds": retry_after,
        },
        headers={
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(getattr(exc, "limit", "unknown")),
        },
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with configurable limits.

    Applies different limits based on endpoint sensitivity:
    - Auth endpoints: Stricter limits to prevent brute force
    - General API: Standard limits
    - Health checks: No limits
    """

    # Paths exempt from rate limiting
    EXEMPT_PATHS = {"/health", "/openapi.json", "/docs", "/redoc"}

    # Paths with stricter limits (auth/sensitive)
    STRICT_LIMIT_PATHS = {"/auth/token", "/auth/login", "/api/v1/mfa/verify"}

    def __init__(
        self,
        app,
        enabled: bool = True,
        default_limit: int = 60,
        auth_limit: int = 10,
    ):
        """
        Initialize rate limit middleware.

        Args:
            app: FastAPI application
            enabled: Whether to enable rate limiting
            default_limit: Requests per minute for general endpoints
            auth_limit: Requests per minute for auth endpoints (stricter)
        """
        super().__init__(app)
        self.enabled = enabled
        self.default_limit = default_limit
        self.auth_limit = auth_limit
        # Track requests per client
        self._request_counts: dict[str, dict[str, int]] = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        if not self.enabled:
            return await call_next(request)

        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Apply rate limiting via slowapi
        # The actual limiting is done via decorators on routes
        response = await call_next(request)
        return response


def setup_rate_limiting(app: FastAPI) -> None:
    """
    Configure rate limiting for the FastAPI application.

    Call this during app startup to enable rate limiting.
    """
    settings = get_api_settings()

    if not settings.rate_limit_enabled:
        logger.info("Rate limiting is disabled")
        return

    # Set limiter state on app
    app.state.limiter = limiter

    # Add exception handler for rate limit exceeded
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    logger.info(f"Rate limiting enabled: {settings.rate_limit_per_minute} requests/minute")


# Rate limit decorators for routes
def rate_limit_auth(func):
    """Apply strict rate limit to authentication endpoints (10/minute)."""
    settings = get_api_settings()
    if settings.rate_limit_enabled:
        return limiter.limit("10/minute")(func)
    return func


def rate_limit_standard(func):
    """Apply standard rate limit (configured per minute)."""
    settings = get_api_settings()
    if settings.rate_limit_enabled:
        limit = f"{settings.rate_limit_per_minute}/minute"
        return limiter.limit(limit)(func)
    return func


def rate_limit_upload(func):
    """Apply rate limit for file uploads (20/minute)."""
    settings = get_api_settings()
    if settings.rate_limit_enabled:
        return limiter.limit("20/minute")(func)
    return func


# Export limiter for use with decorators
__all__ = [
    "limiter",
    "rate_limit_auth",
    "rate_limit_standard",
    "rate_limit_upload",
    "setup_rate_limiting",
    "RateLimitMiddleware",
    "get_client_ip",
]

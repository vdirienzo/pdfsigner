"""
TLS/HTTPS enforcement middleware for REST API.

Provides:
- HTTP to HTTPS redirect
- TLS version validation
- mTLS (mutual TLS) support
- SSL context configuration

Author: Homero Thompson del Lago del Terror
"""

import ssl
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

if TYPE_CHECKING:
    from pdfsigner.api.config import APISettings


class TLSRedirectMiddleware(BaseHTTPMiddleware):
    """
    Redirect HTTP requests to HTTPS when TLS is enabled.

    Handles:
    - X-Forwarded-Proto header for proxy scenarios
    - Preserves query parameters and path
    """

    def __init__(self, app, tls_redirect_enabled: bool = True):
        """
        Initialize TLS redirect middleware.

        Args:
            app: ASGI application
            tls_redirect_enabled: Whether to redirect HTTP to HTTPS
        """
        super().__init__(app)
        self.tls_redirect_enabled = tls_redirect_enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and redirect to HTTPS if needed.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware in chain

        Returns:
            Response (redirect or normal)
        """
        if not self.tls_redirect_enabled:
            return await call_next(request)

        # Check if request is already HTTPS
        is_https = False

        # Check X-Forwarded-Proto header (for proxies/load balancers)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https":
            is_https = True

        # Check URL scheme
        if request.url.scheme == "https":
            is_https = True

        # Redirect HTTP to HTTPS
        if not is_https:
            # Build HTTPS URL
            https_url = request.url.replace(scheme="https")
            logger.debug(f"Redirecting HTTP to HTTPS: {request.url} -> {https_url}")
            return RedirectResponse(url=str(https_url), status_code=301)

        return await call_next(request)


class TLSRequirementMiddleware(BaseHTTPMiddleware):
    """
    Reject non-TLS connections when strict mode enabled.

    Used when TLS is required and HTTP should not be accepted at all
    (not even for redirect).
    """

    def __init__(self, app, require_tls: bool = False):
        """
        Initialize TLS requirement middleware.

        Args:
            app: ASGI application
            require_tls: Whether to reject non-HTTPS requests
        """
        super().__init__(app)
        self.require_tls = require_tls

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and reject if not HTTPS.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware in chain

        Returns:
            Response (error or normal)
        """
        if not self.require_tls:
            return await call_next(request)

        # Check if request is HTTPS
        is_https = False

        # Check X-Forwarded-Proto header (for proxies/load balancers)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https":
            is_https = True

        # Check URL scheme
        if request.url.scheme == "https":
            is_https = True

        # Reject non-HTTPS requests
        if not is_https:
            from fastapi import status
            from fastapi.responses import JSONResponse

            client_host = request.client.host if request.client else "unknown"
            logger.warning(f"Rejected non-HTTPS request from {client_host}: {request.url}")
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "detail": "HTTPS required. This server requires secure connections.",
                    "error": "upgrade_required",
                },
                headers={"Upgrade": "TLS/1.2, HTTP/1.1"},
            )

        return await call_next(request)


def get_ssl_context(settings: "APISettings") -> ssl.SSLContext | None:
    """
    Create SSL context from settings.

    Args:
        settings: API settings with TLS configuration

    Returns:
        SSLContext configured according to settings, or None if TLS disabled

    Raises:
        FileNotFoundError: If certificate or key file not found
        ssl.SSLError: If SSL configuration is invalid
    """
    if not settings.tls_enabled:
        return None

    # Validate certificate and key paths
    cert_path = Path(settings.tls_cert_path)
    key_path = Path(settings.tls_key_path)

    if not cert_path.exists():
        raise FileNotFoundError(f"TLS certificate not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"TLS key not found: {key_path}")

    # Create SSL context with appropriate protocol version
    if settings.tls_min_version == "TLSv1.3":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    else:  # TLSv1.2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load certificate and private key
    try:
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except ssl.SSLError as e:
        raise ssl.SSLError(f"Failed to load TLS certificate/key: {e}") from e

    # Configure client certificate verification (mTLS)
    if settings.tls_require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
        # Load CA certificates for client verification
        if settings.tls_ca_cert_path:
            ca_path = Path(settings.tls_ca_cert_path)
            if not ca_path.exists():
                raise FileNotFoundError(f"TLS CA certificate not found: {ca_path}")
            context.load_verify_locations(cafile=str(ca_path))
        else:
            # Use system default CA bundle
            context.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)
    else:
        context.verify_mode = ssl.CERT_NONE

    # Set cipher suites (secure defaults)
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")

    logger.info(
        f"SSL context created: min_version={settings.tls_min_version}, "
        f"mTLS={settings.tls_require_client_cert}"
    )

    return context


def validate_tls_config(settings: "APISettings") -> tuple[bool, list[str]]:
    """
    Validate TLS configuration.

    Args:
        settings: API settings with TLS configuration

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []

    if not settings.tls_enabled:
        return True, []  # No validation needed if TLS disabled

    # Check certificate path
    if not settings.tls_cert_path:
        errors.append("TLS enabled but tls_cert_path not configured")
    else:
        cert_path = Path(settings.tls_cert_path)
        if not cert_path.exists():
            errors.append(f"TLS certificate file not found: {cert_path}")
        elif not cert_path.is_file():
            errors.append(f"TLS certificate path is not a file: {cert_path}")

    # Check key path
    if not settings.tls_key_path:
        errors.append("TLS enabled but tls_key_path not configured")
    else:
        key_path = Path(settings.tls_key_path)
        if not key_path.exists():
            errors.append(f"TLS key file not found: {key_path}")
        elif not key_path.is_file():
            errors.append(f"TLS key path is not a file: {key_path}")

    # Check minimum TLS version
    if settings.tls_min_version not in ("TLSv1.2", "TLSv1.3"):
        errors.append(
            f"Invalid tls_min_version: {settings.tls_min_version}. Must be 'TLSv1.2' or 'TLSv1.3'"
        )

    # Check mTLS configuration
    if settings.tls_require_client_cert:
        if settings.tls_ca_cert_path:
            ca_path = Path(settings.tls_ca_cert_path)
            if not ca_path.exists():
                errors.append(f"TLS CA certificate file not found: {ca_path}")
            elif not ca_path.is_file():
                errors.append(f"TLS CA certificate path is not a file: {ca_path}")

    # Validate that redirect and requirement are not both disabled
    if not settings.tls_redirect_http and settings.tls_enabled:
        logger.warning(
            "TLS enabled but HTTP redirect disabled. HTTP requests will be processed without TLS."
        )

    is_valid = len(errors) == 0
    return is_valid, errors


__all__ = [
    "TLSRedirectMiddleware",
    "TLSRequirementMiddleware",
    "get_ssl_context",
    "validate_tls_config",
]

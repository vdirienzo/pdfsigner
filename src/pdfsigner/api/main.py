"""
PDFSigner REST API - Main application.

This module creates and configures the FastAPI application with:
- CORS middleware
- Lifespan context for startup/shutdown
- Health check endpoint
- API routes (commented out until implemented)

Run with: uvicorn pdfsigner.api.main:app --reload
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.routes import (
    auth_router,
    backup_router,
    breach_router,
    certificates_router,
    compliance_router,
    consent_router,
    emergency_router,
    evidence_router,
    gdpr_router,
    mfa_router,
    phi_router,
    redact_router,
    retention_router,
    sessions_router,
    sign_router,
    users_router,
    validate_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Lifespan context manager for startup and shutdown events.

    Handles:
    - Startup: Initialize resources, check dependencies
    - Shutdown: Cleanup resources, close connections
    """
    settings = get_api_settings()

    # Startup
    logger.info("Starting PDFSigner API")
    logger.info(f"API Version: {settings.api_version}")
    logger.info(f"API Prefix: {settings.api_prefix}")
    logger.info(f"Temp Directory: {settings.temp_dir}")
    logger.info(f"Max Upload Size: {settings.max_upload_size_mb} MB")

    # Validate TLS configuration if enabled
    if settings.tls_enabled:
        from pdfsigner.api.middleware.tls import validate_tls_config

        is_valid, errors = validate_tls_config(settings)
        if not is_valid:
            logger.error("TLS configuration validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            raise RuntimeError(f"Invalid TLS configuration. Fix these errors: {', '.join(errors)}")
        logger.info(
            f"TLS enabled: min_version={settings.tls_min_version}, "
            f"mTLS={settings.tls_require_client_cert}, "
            f"redirect={settings.tls_redirect_http}"
        )

    # Ensure temp directory exists
    settings.temp_dir.mkdir(parents=True, exist_ok=True)

    # TODO: Initialize other resources
    # - Database connections
    # - Token manager
    # - Background task scheduler

    yield

    # Shutdown
    logger.info("Shutting down PDFSigner API")
    # TODO: Cleanup resources
    # - Close database connections
    # - Cancel background tasks
    # - Cleanup temporary files


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.

    Returns:
        Configured FastAPI app instance
    """
    settings = get_api_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description=settings.api_description,
        docs_url=settings.docs_url,
        redoc_url=settings.redoc_url,
        openapi_url=settings.openapi_url,
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    # Configure TLS middleware
    if settings.tls_enabled:
        from pdfsigner.api.middleware.tls import TLSRedirectMiddleware, TLSRequirementMiddleware

        # Add strict TLS requirement if enabled (rejects HTTP entirely)
        if settings.tls_strict_mode:
            app.add_middleware(TLSRequirementMiddleware, require_tls=True)
            logger.info("TLS strict mode enabled: HTTP requests will be rejected")
        # Add HTTP to HTTPS redirect if enabled (and not in strict mode)
        elif settings.tls_redirect_http:
            app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=True)
            logger.info("TLS redirect enabled: HTTP requests will redirect to HTTPS")

    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, str]:
        """
        Health check endpoint.

        Returns:
            Status and version information
        """
        return {
            "status": "healthy",
            "version": settings.api_version,
        }

    # Include API routers
    app.include_router(auth_router)
    app.include_router(validate_router)
    app.include_router(certificates_router)
    app.include_router(users_router)
    app.include_router(sessions_router)
    app.include_router(emergency_router)
    app.include_router(sign_router)
    app.include_router(redact_router)
    app.include_router(phi_router)
    app.include_router(compliance_router)
    app.include_router(evidence_router)
    app.include_router(mfa_router)
    app.include_router(backup_router)
    app.include_router(retention_router)
    app.include_router(gdpr_router)
    app.include_router(breach_router)
    app.include_router(consent_router)

    # Vulnerability management (conditional - only if no import errors)
    try:
        from pdfsigner.api.routes.vulnerabilities import router as vulnerabilities_router

    except Exception as e:
        logger.warning(f"Could not load vulnerabilities router: {e}")

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    """
    Run with: python -m pdfsigner.api.main
    Better: uvicorn pdfsigner.api.main:app --reload

    For TLS/HTTPS:
        uvicorn pdfsigner.api.main:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem
    """
    import uvicorn

    settings = get_api_settings()

    # Configure SSL if TLS is enabled
    ssl_keyfile = None
    ssl_certfile = None
    ssl_ca_certs = None

    if settings.tls_enabled:
        # Uvicorn uses separate parameters for SSL files
        ssl_keyfile = settings.tls_key_path
        ssl_certfile = settings.tls_cert_path
        if settings.tls_require_client_cert and settings.tls_ca_cert_path:
            ssl_ca_certs = settings.tls_ca_cert_path

        logger.info(f"Starting with TLS enabled on port {settings.port}")

    uvicorn.run(
        "pdfsigner.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower(),
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        ssl_ca_certs=ssl_ca_certs,
    )

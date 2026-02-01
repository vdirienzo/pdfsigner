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
from pdfsigner.api.routes import auth_router, certificates_router, sign_router, validate_router


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

    app.include_router(sign_router)

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    """
    Run with: python -m pdfsigner.api.main
    Better: uvicorn pdfsigner.api.main:app --reload
    """
    import uvicorn

    settings = get_api_settings()
    uvicorn.run(
        "pdfsigner.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower(),
    )

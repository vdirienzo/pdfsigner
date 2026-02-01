"""
API configuration using pydantic-settings.

Settings can be loaded from:
1. Environment variables (PDFSIGNER_API_*)
2. .env file
3. Defaults defined here
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class APISettings(BaseSettings):
    """PDFSigner API configuration."""

    model_config = SettingsConfigDict(
        env_prefix="PDFSIGNER_API_",
        env_file=".env",
        extra="ignore",
    )

    # --- API Metadata ---
    api_title: str = Field(
        default="PDFSigner API",
        description="API title shown in OpenAPI docs",
    )
    api_version: str = Field(
        default="1.0.0",
        description="API version",
    )
    api_description: str = Field(
        default="REST API for digital PDF signing with PKCS#11/NSS token support",
        description="API description shown in OpenAPI docs",
    )
    api_prefix: str = Field(
        default="/api/v1",
        description="API route prefix",
    )

    # --- CORS Configuration ---
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins",
    )
    cors_allow_credentials: bool = Field(
        default=True,
        description="Allow credentials in CORS requests",
    )
    cors_allow_methods: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed HTTP methods for CORS",
    )
    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed HTTP headers for CORS",
    )

    # --- Authentication ---
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR"),
        description="Secret key for JWT token signing (MUST be changed in production)",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT algorithm",
    )
    jwt_expire_minutes: int = Field(
        default=30,
        ge=5,
        le=1440,
        description="JWT token expiration time in minutes",
    )

    # --- API Key Authentication ---
    api_key_header: str = Field(
        default="X-API-Key",
        description="HTTP header name for API key authentication",
    )
    api_keys: list[str] = Field(
        default_factory=list,
        description="Valid API keys (load from environment for production)",
    )

    # --- Rate Limiting ---
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=1,
        le=10000,
        description="Maximum requests per minute per client",
    )

    # --- Upload Limits ---
    max_upload_size_mb: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum upload size in megabytes",
    )
    max_batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of files in batch operation",
    )

    # --- File Storage ---
    temp_dir: Path = Field(
        default_factory=lambda: Path("/tmp/pdfsigner-api"),
        description="Temporary directory for uploaded files",
    )
    temp_file_retention_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours to retain temporary files before cleanup",
    )

    # --- Server Configuration ---
    host: str = Field(
        default="127.0.0.1",
        description="Server host",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Server port",
    )
    reload: bool = Field(
        default=False,
        description="Enable auto-reload for development",
    )
    workers: int = Field(
        default=1,
        ge=1,
        le=32,
        description="Number of worker processes",
    )

    # --- Logging ---
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level",
    )
    log_json: bool = Field(
        default=False,
        description="Log in JSON format for structured logging",
    )
    log_requests: bool = Field(
        default=True,
        description="Log HTTP requests",
    )

    # --- OpenAPI Documentation ---
    docs_url: str | None = Field(
        default="/docs",
        description="OpenAPI Swagger UI path (None to disable)",
    )
    redoc_url: str | None = Field(
        default="/redoc",
        description="ReDoc documentation path (None to disable)",
    )
    openapi_url: str | None = Field(
        default="/openapi.json",
        description="OpenAPI JSON schema path (None to disable)",
    )

    # --- TLS/HTTPS Configuration ---
    tls_enabled: bool = Field(
        default=False,
        description="Enable TLS/HTTPS for API server (requires cert/key paths)",
    )
    tls_cert_path: str = Field(
        default="",
        description="Path to TLS certificate file (PEM format)",
    )
    tls_key_path: str = Field(
        default="",
        description="Path to TLS private key file (PEM format)",
    )
    tls_min_version: Literal["TLSv1.2", "TLSv1.3"] = Field(
        default="TLSv1.2",
        description="Minimum TLS version (TLSv1.2 or TLSv1.3)",
    )
    tls_require_client_cert: bool = Field(
        default=False,
        description="Require client certificate for mTLS (mutual TLS)",
    )
    tls_ca_cert_path: str = Field(
        default="",
        description=(
            "Path to CA certificate for client cert verification (mTLS). Empty = use system CAs"
        ),
    )
    tls_redirect_http: bool = Field(
        default=True,
        description="Redirect HTTP requests to HTTPS when TLS is enabled",
    )
    tls_strict_mode: bool = Field(
        default=False,
        description=(
            "Reject non-HTTPS requests entirely (no redirect). For high-security deployments."
        ),
    )

    @field_validator("temp_dir")
    @classmethod
    def validate_temp_dir(cls, v: Path) -> Path:
        """Ensure temp directory exists."""
        v.mkdir(parents=True, exist_ok=True)
        return v

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, v: SecretStr) -> SecretStr:
        """Warn if using default JWT secret."""
        if v.get_secret_value() == "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR":
            import warnings

            warnings.warn(
                "Using default JWT secret key. "
                "Set PDFSIGNER_API_JWT_SECRET_KEY environment variable.",
                UserWarning,
                stacklevel=2,
            )
        return v

    @field_validator("tls_cert_path", "tls_key_path", "tls_ca_cert_path")
    @classmethod
    def validate_tls_paths(cls, v: str, info) -> str:
        """Validate TLS file paths if TLS is enabled."""
        # Don't validate at model creation - will be validated at runtime by validate_tls_config()
        # This allows the settings to be loaded even if files don't exist yet
        return v


# Configuration singleton
_api_settings: APISettings | None = None


def get_api_settings() -> APISettings:
    """Get API configuration instance (singleton)."""
    global _api_settings
    if _api_settings is None:
        _api_settings = APISettings()
    return _api_settings


def reload_api_settings() -> APISettings:
    """Reload API configuration."""
    global _api_settings
    _api_settings = APISettings()
    return _api_settings

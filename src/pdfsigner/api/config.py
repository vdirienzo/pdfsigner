"""
API configuration using pydantic-settings.

Settings can be loaded from:
1. Environment variables (PDFSIGNER_API_*)
2. .env file
3. Defaults defined here
"""

import warnings
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
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed HTTP methods for CORS",
    )
    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["Content-Type", "Authorization", "X-CSRF-Token", "X-API-Key"],
        description="Allowed HTTP headers for CORS",
    )

    # --- Authentication ---
    jwt_secret_key: SecretStr | None = Field(
        default=None,
        description=(
            "Secret key for JWT token signing (REQUIRED - set via PDFSIGNER_API_JWT_SECRET_KEY)"
        ),
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
    # Disabled by default for production security. Set via env vars for development:
    # PDFSIGNER_API_DOCS_URL=/docs PDFSIGNER_API_REDOC_URL=/redoc PDFSIGNER_API_OPENAPI_URL=/openapi.json
    docs_url: str | None = Field(
        default=None,
        description="OpenAPI Swagger UI path (None to disable)",
    )
    redoc_url: str | None = Field(
        default=None,
        description="ReDoc documentation path (None to disable)",
    )
    openapi_url: str | None = Field(
        default=None,
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

    @field_validator("temp_dir", mode="before")
    @classmethod
    def validate_temp_dir(cls, v: str | Path | None) -> Path:
        """Ensure temp directory exists with secure permissions."""
        import tempfile

        path = Path(v) if v else Path(tempfile.mkdtemp(prefix="pdfsigner-api-"))
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
        return path

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, v: SecretStr | None) -> SecretStr:
        """
        Validate JWT secret key is provided.

        Security: JWT secret MUST be explicitly configured via environment variable.
        Using a default/hardcoded secret is a critical security vulnerability.
        """
        if v is None:
            raise ValueError(
                "JWT secret key is required. "
                "Set PDFSIGNER_API_JWT_SECRET_KEY environment variable with a secure random value. "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        secret_value = v.get_secret_value()

        # Reject obviously weak secrets
        if len(secret_value) < 32:
            raise ValueError(
                "JWT secret key must be at least 32 characters. "
                "Generate a secure one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )

        # Reject common/default values
        weak_secrets = {
            "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR",
            "secret",
            "change_me",
            "your-secret-key",
            "jwt-secret",
        }
        if secret_value in weak_secrets:
            raise ValueError(
                "JWT secret key appears to be a default/weak value. "
                "Set a secure random value via PDFSIGNER_API_JWT_SECRET_KEY."
            )

        return v

    @field_validator("tls_cert_path", "tls_key_path", "tls_ca_cert_path")
    @classmethod
    def validate_tls_paths(cls, v: str, info) -> str:
        """Validate TLS file paths if TLS is enabled."""
        # Don't validate at model creation - will be validated at runtime by validate_tls_config()
        # This allows the settings to be loaded even if files don't exist yet
        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: list[str]) -> list[str]:
        """
        Validate CORS origins configuration.

        Security: Using wildcard "*" with credentials is insecure per the CORS spec.
        Browsers will reject the response if Access-Control-Allow-Origin is "*"
        and Access-Control-Allow-Credentials is true.
        """
        if "*" in v:
            warnings.warn(
                "CORS origins contains wildcard '*' which is insecure when "
                "cors_allow_credentials is enabled. "
                "Consider explicitly listing allowed origins: "
                "['http://localhost:3000', 'http://localhost:8000']",
                UserWarning,
                stacklevel=2,
            )
        return v

    @field_validator("cors_allow_methods")
    @classmethod
    def validate_cors_methods(cls, v: list[str]) -> list[str]:
        """
        Validate CORS allowed methods configuration.

        Security: Using wildcard "*" for CORS methods is insecure and should be avoided.
        Explicitly list allowed methods instead.
        """
        if "*" in v:
            warnings.warn(
                "CORS allow_methods contains wildcard '*' which is insecure. "
                "Consider explicitly listing allowed methods: "
                "['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']",
                UserWarning,
                stacklevel=2,
            )
        return v

    @field_validator("cors_allow_headers")
    @classmethod
    def validate_cors_headers(cls, v: list[str]) -> list[str]:
        """
        Validate CORS allowed headers configuration.

        Security: Using wildcard "*" for CORS headers is insecure and should be avoided.
        Explicitly list allowed headers instead.
        """
        if "*" in v:
            warnings.warn(
                "CORS allow_headers contains wildcard '*' which is insecure. "
                "Consider explicitly listing allowed headers: "
                "['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-API-Key']",
                UserWarning,
                stacklevel=2,
            )
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

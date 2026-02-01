"""
settings.py - Centralized PDFSigner configuration

Author: Homero Thompson del Lago del Terror

Uses pydantic-settings to load configuration from:
1. Environment variables
2. File ~/.config/pdfsigner/config.toml
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

# TOML config file path
TOML_CONFIG_PATH = Path.home() / ".config" / "pdfsigner" / "config.toml"


class Settings(BaseSettings):
    """PDFSigner configuration from file and environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="PDFSIGNER_",
        env_file=".env",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customize settings sources to include TOML file."""
        from pydantic_settings import TomlConfigSettingsSource

        # Priority: init > env > dotenv > toml > secrets
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=TOML_CONFIG_PATH),
            file_secret_settings,
        )

    # --- NSS Database ---
    nss_db_path: Path = Field(
        default=Path.home() / ".nss",
        description="Path to NSS database with token",
    )

    # --- TSA (Timestamp Authority) ---
    tsa_url: str = Field(
        default="",
        description="Timestamp server URL (required for PAdES-LTV)",
    )
    tsa_username: str | None = Field(
        default=None,
        description="Username for TSA authentication (if applicable)",
    )
    tsa_password: str | None = Field(
        default=None,
        description="Password for TSA authentication (if applicable)",
    )

    # --- Visible Signature ---
    default_visible: bool = Field(
        default=False,
        description="If signature is visible by default",
    )
    signature_width_mm: int = Field(
        default=50,
        ge=20,
        le=100,
        description="Signature stamp width in mm",
    )
    signature_height_mm: int = Field(
        default=20,
        ge=10,
        le=50,
        description="Signature stamp height in mm",
    )
    signature_image_path: Path | None = Field(
        default=None,
        description="Custom image for visible signature (PNG/JPG)",
    )
    default_page: Literal["last", "first", "all"] = Field(
        default="last",
        description="Default page for visible signature",
    )

    # --- QR Verification Code ---
    qr_enabled: bool = Field(
        default=False,
        description="Include QR verification code in visible signature",
    )
    qr_position: Literal["left", "right"] = Field(
        default="left",
        description="QR code position in stamp (left or right)",
    )

    # --- Signature Template ---
    signature_template: str = Field(
        default="",
        description="Name of signature template (empty = default text stamp)",
    )
    custom_template_path: Path | None = Field(
        default=None,
        description="Path to custom template JSON file",
    )

    # --- Signature Metadata ---
    default_signature_reason: str = Field(
        default="",
        description="Default signature reason (e.g., 'I approve this document')",
    )
    default_signature_location: str = Field(
        default="",
        description="Default signature location (e.g., 'Buenos Aires, Argentina')",
    )
    default_signature_contact: str = Field(
        default="",
        description="Default signature contact info (e.g., 'email@company.com')",
    )

    # --- Output ---
    output_suffix: str = Field(
        default="_signed",
        description="Suffix for signed files",
    )

    # --- Logging ---
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level",
    )
    log_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "pdfsigner" / "logs",
        description="Logs directory",
    )

    # --- PIN Cache ---
    pin_cache_enabled: bool = Field(
        default=False,
        description="Cache PIN during batch signing",
    )
    pin_cache_timeout_seconds: int = Field(
        default=300,
        ge=60,
        le=3600,
        description="PIN cache timeout in seconds",
    )

    # --- Dry Run Mode ---
    dry_run: bool = Field(
        default=False,
        description="Simulation mode without real token",
    )

    # --- Audit Trail ---
    audit_enabled: bool = Field(
        default=True,
        description="Enable audit logging for security and compliance",
    )
    audit_retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Days to retain audit logs (1-3650)",
    )

    # --- System Notifications ---
    system_notifications_enabled: bool = Field(
        default=True,
        description="Enable system notifications for background events",
    )

    # --- Revocation Checking ---
    revocation_check_enabled: bool = Field(
        default=False,
        description="Check certificate revocation status during validation (OCSP/CRL)",
    )
    revocation_check_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description="Timeout for revocation checks in seconds",
    )
    revocation_cache_ttl: int = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Cache TTL for revocation results in seconds",
    )
    revocation_prefer_ocsp: bool = Field(
        default=True,
        description="Prefer OCSP over CRL for revocation checks",
    )

    # --- LTV (Long Term Validation) ---
    ltv_enabled: bool = Field(
        default=True,
        description="Enable PAdES-LTV signature with embedded validation info (DSS)",
    )
    ltv_ocsp_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description="Timeout for OCSP requests during LTV embedding in seconds",
    )
    ltv_crl_timeout: int = Field(
        default=30,
        ge=10,
        le=120,
        description="Timeout for CRL downloads during LTV embedding in seconds",
    )
    ltv_prefer_ocsp: bool = Field(
        default=True,
        description="Prefer OCSP over CRL for LTV validation info",
    )
    ltv_fail_open: bool = Field(
        default=True,
        description="Continue signing if LTV embedding fails (signature still valid, just not LTV)",
    )

    # --- Archive Timestamp settings (for PAdES B-LTA) ---
    archive_ts_enabled: bool = Field(
        default=False, description="Enable archive timestamp embedding for long-term validation"
    )
    archive_ts_auto: bool = Field(
        default=False,
        description="Auto-add archive timestamp after DSS (requires archive_ts_enabled)",
    )
    archive_ts_tsa_urls: list[str] = Field(
        default_factory=list,
        description="Additional TSA URLs for archive timestamps (fallback order)",
    )

    # --- Appearance ---
    theme: Literal["system", "light", "dark"] = Field(
        default="system",
        description="Application theme (system, light, dark)",
    )
    accent_color: str = Field(
        default="blue",
        description="Accent color for UI elements",
    )
    language: str = Field(
        default="",
        description="UI language (empty = system default)",
    )

    # --- Recent Files ---
    recent_files_enabled: bool = Field(
        default=True,
        description="Track recently opened/signed PDF files",
    )
    recent_files_limit: int = Field(
        default=10,
        ge=5,
        le=50,
        description="Maximum number of recent files to show",
    )

    @field_validator("nss_db_path")
    @classmethod
    def validate_nss_path(cls, v: Path) -> Path:
        """Validate NSS path format (existence checked at runtime by NSSChecker)."""
        # Don't validate existence here - NSS may not exist on first run
        # The NSSSetupWizard handles creating it
        return v

    @field_validator("signature_image_path")
    @classmethod
    def validate_image_path(cls, v: Path | None) -> Path | None:
        """Validate that signature image exists if specified."""
        if v is not None and not v.exists():
            raise ValueError(f"Signature image does not exist: {v}")
        return v

    @field_validator("output_suffix")
    @classmethod
    def validate_output_suffix(cls, v: str) -> str:
        """Validate output suffix to prevent path traversal."""
        from pdfsigner.core.security.path_sanitizer import (
            PathTraversalError,
            sanitize_output_suffix,
        )

        try:
            return sanitize_output_suffix(v)
        except PathTraversalError as e:
            raise ValueError(str(e)) from e

    @field_validator("signature_template")
    @classmethod
    def validate_signature_template(cls, v: str) -> str:
        """Validate signature template name to prevent path traversal."""
        if not v:
            return v  # Empty string is valid (means default template)

        from pdfsigner.core.security.path_sanitizer import (
            PathTraversalError,
            sanitize_filename,
        )

        try:
            return sanitize_filename(v, allow_subdirs=False)
        except PathTraversalError as e:
            raise ValueError(str(e)) from e


# Configuration singleton
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get configuration instance (singleton)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Reload configuration from disk."""
    global _settings
    _settings = Settings()
    return _settings

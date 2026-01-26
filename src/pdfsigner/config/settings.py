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
    default_organization: str = Field(
        default="",
        description="Organization name to use if certificate lacks one",
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

"""
settings.py - Centralized PDFSigner configuration

Author: Homero Thompson del Lago del Terror

Uses pydantic-settings to load configuration from:
1. Environment variables
2. File ~/.config/pdfsigner/config.toml

Field groups are defined in settings_defaults.py (mixins).
Validators are defined in settings_validators.py.
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from pdfsigner.config.settings_defaults import (
    DEFAULT_LOG_DIR,
    DEFAULT_NSS_PATH,
    TOML_CONFIG_PATH,
    ComplianceFieldsMixin,
    EidasFieldsMixin,
    HealthcareFieldsMixin,
    SecurityFieldsMixin,
)
from pdfsigner.config.settings_validators import (
    validate_image_path as _validate_image_path,
)
from pdfsigner.config.settings_validators import (
    validate_nss_path as _validate_nss_path,
)
from pdfsigner.config.settings_validators import (
    validate_output_suffix as _validate_output_suffix,
)
from pdfsigner.config.settings_validators import (
    validate_signature_template as _validate_signature_template,
)


class Settings(
    SecurityFieldsMixin,
    HealthcareFieldsMixin,
    ComplianceFieldsMixin,
    EidasFieldsMixin,
    BaseSettings,
):
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
        default=DEFAULT_NSS_PATH,
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
    tsa_password: SecretStr | None = Field(
        default=None,
        description="TSA password (use PDFSIGNER_TSA_PASSWORD env var)",
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
        description="Default signature location (e.g., 'New York, NY')",
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
        default=DEFAULT_LOG_DIR,
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

    # --- Field Validators (delegate to settings_validators.py) ---
    @field_validator("nss_db_path")
    @classmethod
    def validate_nss_path(cls, v: Path) -> Path:
        return _validate_nss_path(v)

    @field_validator("signature_image_path")
    @classmethod
    def validate_image_path(cls, v: Path | None) -> Path | None:
        return _validate_image_path(v)

    @field_validator("output_suffix")
    @classmethod
    def validate_output_suffix(cls, v: str) -> str:
        return _validate_output_suffix(v)

    @field_validator("signature_template")
    @classmethod
    def validate_signature_template(cls, v: str) -> str:
        return _validate_signature_template(v)


# Configuration singleton
import threading

_settings: Settings | None = None
_settings_lock = threading.Lock()


def get_settings() -> Settings:
    """Get configuration instance (singleton)."""
    global _settings
    with _settings_lock:
        if _settings is None:
            _settings = Settings()
        return _settings


def reload_settings() -> Settings:
    """Reload configuration from disk."""
    global _settings
    with _settings_lock:
        _settings = Settings()
        return _settings

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
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """PDFSigner configuration from file and environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="PDFSIGNER_",
        env_file=".env",
        toml_file=Path.home() / ".config" / "pdfsigner" / "config.toml",
        extra="ignore",
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
        default=True,
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

    # --- Nautilus Integration ---
    nautilus_mode: Literal["gui", "quick"] = Field(
        default="gui",
        description="Nautilus mode: 'gui' opens app, 'quick' signs directly",
    )
    nautilus_visible_stamp: bool = Field(
        default=False,
        description="Add visible stamp in quick mode",
    )
    nautilus_stamp_position: Literal[
        "bottom_right", "bottom_left", "top_right", "top_left",
        "bottom_center", "top_center"
    ] = Field(
        default="bottom_right",
        description="Stamp position for quick mode",
    )
    nautilus_stamp_page: Literal["last", "first", "all"] = Field(
        default="last",
        description="Page for stamp in quick mode",
    )
    nautilus_show_name: bool = Field(
        default=True,
        description="Show signer name in stamp",
    )
    nautilus_show_date: bool = Field(
        default=True,
        description="Show date in stamp",
    )

    @field_validator("nss_db_path")
    @classmethod
    def validate_nss_path(cls, v: Path) -> Path:
        """Validate that NSS path exists."""
        if not v.exists():
            raise ValueError(f"NSS directory does not exist: {v}")
        return v

    @field_validator("signature_image_path")
    @classmethod
    def validate_image_path(cls, v: Path | None) -> Path | None:
        """Validate that signature image exists if specified."""
        if v is not None and not v.exists():
            raise ValueError(f"Signature image does not exist: {v}")
        return v


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

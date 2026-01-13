"""
settings.py - Configuración centralizada de PDFSigner

Autor: Homero Thompson del Lago del Terror

Usa pydantic-settings para cargar configuración desde:
1. Variables de entorno
2. Archivo ~/.config/pdfsigner/config.toml
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración de PDFSigner desde archivo y variables de entorno."""

    model_config = SettingsConfigDict(
        env_prefix="PDFSIGNER_",
        env_file=".env",
        toml_file=Path.home() / ".config" / "pdfsigner" / "config.toml",
        extra="ignore",
    )

    # --- NSS Database ---
    nss_db_path: Path = Field(
        default=Path.home() / ".nss",
        description="Ruta a la base de datos NSS con el token",
    )

    # --- TSA (Timestamp Authority) ---
    tsa_url: str = Field(
        default="",
        description="URL del servidor de timestamp (requerido para PAdES-LTV)",
    )
    tsa_username: str | None = Field(
        default=None,
        description="Usuario para autenticación TSA (si aplica)",
    )
    tsa_password: str | None = Field(
        default=None,
        description="Password para autenticación TSA (si aplica)",
    )

    # --- Firma Visible ---
    default_visible: bool = Field(
        default=False,
        description="Si la firma es visible por defecto",
    )
    signature_width_mm: int = Field(
        default=50,
        ge=20,
        le=100,
        description="Ancho del sello de firma en mm",
    )
    signature_height_mm: int = Field(
        default=20,
        ge=10,
        le=50,
        description="Alto del sello de firma en mm",
    )
    signature_image_path: Path | None = Field(
        default=None,
        description="Imagen personalizada para firma visible (PNG/JPG)",
    )
    default_page: Literal["last", "first", "all"] = Field(
        default="last",
        description="Página por defecto para firma visible",
    )

    # --- Output ---
    output_suffix: str = Field(
        default="_firmado",
        description="Sufijo para archivos firmados",
    )

    # --- Logging ---
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Nivel de logging",
    )
    log_dir: Path = Field(
        default=Path.home() / ".local" / "share" / "pdfsigner" / "logs",
        description="Directorio de logs",
    )

    # --- PIN Cache ---
    pin_cache_enabled: bool = Field(
        default=True,
        description="Cachear PIN durante firma en lote",
    )
    pin_cache_timeout_seconds: int = Field(
        default=300,
        ge=60,
        le=3600,
        description="Timeout de cache de PIN en segundos",
    )

    # --- Dry Run Mode ---
    dry_run: bool = Field(
        default=False,
        description="Modo simulación sin token real",
    )

    @field_validator("nss_db_path")
    @classmethod
    def validate_nss_path(cls, v: Path) -> Path:
        """Valida que el path de NSS exista."""
        if not v.exists():
            raise ValueError(f"Directorio NSS no existe: {v}")
        return v

    @field_validator("signature_image_path")
    @classmethod
    def validate_image_path(cls, v: Path | None) -> Path | None:
        """Valida que la imagen de firma exista si se especifica."""
        if v is not None and not v.exists():
            raise ValueError(f"Imagen de firma no existe: {v}")
        return v


# Singleton de configuración
_settings: Settings | None = None


def get_settings() -> Settings:
    """Obtiene la instancia de configuración (singleton)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Recarga la configuración desde disco."""
    global _settings
    _settings = Settings()
    return _settings

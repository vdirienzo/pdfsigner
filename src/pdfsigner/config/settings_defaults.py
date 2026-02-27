"""
settings_defaults.py - Default constants and field group mixins for Settings

Extracted from settings.py to reduce file size.
Contains:
- TOML_CONFIG_PATH and default value constants
- Field group mixin classes (SecurityFieldsMixin, EidasFieldsMixin)

HealthcareFieldsMixin and ComplianceFieldsMixin are in their own modules
and re-exported here for backward compatibility.

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr

# Re-export extracted mixins for backward compatibility
from pdfsigner.config.settings_compliance import ComplianceFieldsMixin
from pdfsigner.config.settings_healthcare import HealthcareFieldsMixin

# --- Default value constants ---
TOML_CONFIG_PATH = Path.home() / ".config" / "pdfsigner" / "config.toml"
DEFAULT_NSS_PATH = Path.home() / ".nss"
DEFAULT_LOG_DIR = Path.home() / ".local" / "share" / "pdfsigner" / "logs"

__all__ = [
    "TOML_CONFIG_PATH",
    "DEFAULT_NSS_PATH",
    "DEFAULT_LOG_DIR",
    "SecurityFieldsMixin",
    "HealthcareFieldsMixin",
    "ComplianceFieldsMixin",
    "EidasFieldsMixin",
]


class SecurityFieldsMixin:
    """Security, authentication, and key management fields."""

    # --- SIEM Integration ---
    siem_enabled: bool = Field(
        default=False,
        description="Enable SIEM export for audit events (government compliance)",
    )
    siem_format: Literal["cef", "leef", "json", "syslog"] = Field(
        default="cef",
        description="SIEM export format (cef=ArcSight/Splunk, leef=QRadar, json=Generic)",
    )
    siem_syslog_host: str = Field(
        default="",
        description="Syslog server hostname or IP address",
    )
    siem_syslog_port: int = Field(
        default=514,
        ge=1,
        le=65535,
        description="Syslog server port (default: 514)",
    )
    siem_syslog_protocol: Literal["udp", "tcp", "tls"] = Field(
        default="udp",
        description="Syslog transport protocol (udp, tcp, tls)",
    )
    siem_file_path: str = Field(
        default="",
        description="Path to SIEM export file (empty = disabled)",
    )
    siem_file_rotation_mb: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="File rotation size in MB (1-1000)",
    )
    siem_file_retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Days to retain rotated SIEM files (1-3650)",
    )
    siem_tls_cert_path: str = Field(
        default="",
        description="Path to TLS certificate for secure syslog (empty = system certs)",
    )
    siem_tls_verify: bool = Field(
        default=True,
        description="Verify TLS certificate for secure syslog",
    )

    # --- Key Management ---
    key_storage_path: str = Field(
        default="",
        description="Path to encrypted key storage database (empty = ~/.config/pdfsigner/keys.db)",
    )
    key_storage_master_password: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "Master password for key encryption "
            "(should be set via PDFSIGNER_KEY_STORAGE_MASTER_PASSWORD env var)"
        ),
    )
    key_default_expiry_days: int = Field(
        default=365,
        ge=30,
        le=3650,
        description="Default key expiration in days (30-3650)",
    )
    key_auto_rotate_days: int = Field(
        default=90,
        ge=30,
        le=365,
        description="Auto-rotate keys older than this many days (30-365)",
    )

    # --- Multi-Factor Authentication (MFA) ---
    mfa_enabled: bool = Field(
        default=False,
        description="Enable MFA feature globally (TOTP-based)",
    )
    mfa_required_for_roles: list[str] = Field(
        default_factory=lambda: ["ADMIN"],
        description="User roles that require MFA (e.g., ['ADMIN', 'AUDITOR'])",
    )
    mfa_backup_codes_count: int = Field(
        default=10,
        ge=5,
        le=20,
        description="Number of backup codes to generate (5-20)",
    )
    mfa_issuer_name: str = Field(
        default="PDFSigner",
        description="Issuer name shown in authenticator apps",
    )

    # --- Password Policy (NIST 800-53 IA-5) ---
    password_min_length: int = Field(
        default=12,
        ge=8,
        le=128,
        description="Minimum password length (NIST recommends 12+)",
    )
    password_max_age_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Password expiration in days (0 = never expire)",
    )
    password_history_count: int = Field(
        default=12,
        ge=0,
        le=50,
        description="Number of previous passwords to prevent reuse",
    )
    password_lockout_threshold: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Failed login attempts before account lockout",
    )
    password_lockout_duration_minutes: int = Field(
        default=30,
        ge=1,
        le=1440,
        description="Account lockout duration in minutes",
    )
    password_require_special: bool = Field(
        default=True,
        description="Require special characters in passwords",
    )
    password_min_unique_chars: int = Field(
        default=8,
        ge=1,
        le=128,
        description="Minimum unique characters in password",
    )

    # --- FIPS 140-2 Compliance ---
    fips_mode_enabled: bool = Field(
        default=False,
        description=(
            "Enable FIPS 140-2 compliant cryptography mode. "
            "When enabled, only FIPS-validated algorithms are allowed "
            "(SHA-256/384/512, AES-128/256, RSA-2048+)."
        ),
    )
    fips_strict_mode: bool = Field(
        default=True,
        description="Raise exception vs warning for non-FIPS algorithms. "
        "When True, non-FIPS algorithms will cause immediate failure. "
        "When False, a warning is logged but operation continues.",
    )


class EidasFieldsMixin:
    """eIDAS, electronic seals, and remote signing fields."""

    # --- Electronic Seals (eIDAS Article 35-40) ---
    seal_enabled: bool = Field(
        default=False,
        description="Enable electronic seal feature for organizations (eIDAS compliance)",
    )
    seal_default_type: Literal["basic", "advanced", "qualified"] = Field(
        default="advanced",
        description="Default seal type: basic (simple), advanced (AdESeal), qualified (QESeal)",
    )
    seal_appearance: Literal["invisible", "stamp", "banner", "logo"] = Field(
        default="stamp",
        description=(
            "Default seal appearance: invisible, stamp (circular), banner (rectangular), logo"
        ),
    )
    seal_include_timestamp: bool = Field(
        default=True,
        description="Include trusted timestamp in seals by default",
    )
    seal_logo_path: str = Field(
        default="",
        description="Path to organization logo for seal appearance (PNG/SVG, empty = no logo)",
    )
    seal_background_color: str = Field(
        default="#1a365d",
        description="Background color for seal stamp (hex color code)",
    )
    seal_text_color: str = Field(
        default="#ffffff",
        description="Text color for seal stamp (hex color code)",
    )

    # --- Remote Signing (CSC API v2) ---
    remote_signing_enabled: bool = Field(
        default=False,
        description="Enable remote signing via CSC API v2",
    )
    remote_signing_qtsp_preset: str = Field(
        default="",
        description="Pre-configured QTSP preset name (empty = manual config)",
    )
    remote_signing_service_url: str = Field(
        default="",
        description="CSC API v2 service URL",
    )
    remote_signing_authorize_url: str = Field(
        default="",
        description="OAuth2 authorization endpoint URL",
    )
    remote_signing_token_url: str = Field(
        default="",
        description="OAuth2 token endpoint URL",
    )
    remote_signing_client_id: str = Field(
        default="",
        description="OAuth2 client ID for CSC API",
    )
    remote_signing_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Timeout for remote signing requests in seconds",
    )
    remote_signing_verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates for remote signing connections",
    )

    # --- eIDAS TSP Validation (Qualified Trust Service Providers) ---
    eidas_enabled: bool = Field(
        default=False,
        description="Enable eIDAS compliance validation for Qualified Electronic Signatures (QES)",
    )
    eidas_enforce_qualified: bool = Field(
        default=False,
        description="Reject signatures from non-qualified TSPs (requires eidas_enabled)",
    )
    eidas_cache_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description=(
            "Days to cache EU Trusted Service Provider List (1-30, eIDAS requires weekly updates)"
        ),
    )
    eidas_auto_update: bool = Field(
        default=True,
        description="Automatically update TSL when cache expires",
    )
    eidas_eutl_territories: list[str] = Field(
        default_factory=list,
        description="EU/EEA territory codes to fetch from EUTL (empty = all)",
    )
    eidas_validation_mode: str = Field(
        default="eutl",
        description="eIDAS validation mode: eutl (EU Trusted List), custom, or offline",
    )
    eidas_eutl_cache_dir: str = Field(
        default="",
        description="Directory for EUTL cache files (empty = default cache dir)",
    )
    eidas_prefer_qualified_tsa: bool = Field(
        default=True,
        description="Auto-select qualified TSA from EUTL for timestamping (requires eidas_enabled)",
    )
    eidas_preferred_tsa_country: str = Field(
        default="",
        description="Prefer TSAs from this ISO 3166-1 alpha-2 country code (e.g., 'DE', 'FR')",
    )

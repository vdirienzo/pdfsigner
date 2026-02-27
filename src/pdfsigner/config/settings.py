"""
settings.py - Centralized PDFSigner configuration

Author: Homero Thompson del Lago del Terror

Uses pydantic-settings to load configuration from:
1. Environment variables
2. File ~/.config/pdfsigner/config.toml
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
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

    # --- Healthcare Compliance Mode (HIPAA) ---
    healthcare_mode: bool = Field(
        default=False,
        description="Enable healthcare compliance features (RBAC, sessions, emergency access). "
        "When disabled, the app works normally without additional complexity.",
    )
    healthcare_session_timeout_minutes: int = Field(
        default=15,
        ge=5,
        le=60,
        description="Auto-logoff timeout in minutes (HIPAA §164.312(a)(2)(iii))",
    )
    healthcare_max_sessions: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum concurrent sessions per user",
    )
    healthcare_emergency_duration_hours: int = Field(
        default=4,
        ge=1,
        le=24,
        description="Emergency access duration in hours",
    )
    healthcare_emergency_require_approval: bool = Field(
        default=True,
        description="Require admin approval for emergency access",
    )

    # --- Encryption (HIPAA Compliance) ---
    encryption_default_strength: Literal["aes128", "aes256"] = Field(
        default="aes256", description="Default encryption strength (aes256 recommended for HIPAA)"
    )
    encryption_output_suffix: str = Field(
        default="_encrypted", description="Suffix added to encrypted file names"
    )
    encryption_store_in_keyring: bool = Field(
        default=True, description="Store encryption passwords in system keyring"
    )
    encryption_hipaa_mode: bool = Field(
        default=False, description="Enforce HIPAA-compliant encryption defaults"
    )
    encryption_default_allow_print: bool = Field(
        default=True, description="Allow printing by default in encrypted PDFs"
    )
    encryption_default_allow_copy: bool = Field(
        default=False, description="Allow content copying by default in encrypted PDFs"
    )

    # --- PHI Detection Settings (HIPAA §164.514) ---
    phi_detection_enabled: bool = Field(
        default=False,
        description="Enable PHI scanning before signing to detect protected health information",
    )
    phi_detection_min_confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="Minimum confidence level for PHI detection (low=70%, medium=85%, high=95%)",
    )
    phi_detection_block_unencrypted: bool = Field(
        default=False,
        description=(
            "Block signing if PHI detected without encryption (requires phi_detection_enabled)"
        ),
    )

    # --- Encryption Policy Settings (HIPAA §164.312(a)(2)(iv)) ---
    encryption_policy_enabled: bool = Field(
        default=False,
        description="Enable mandatory encryption policies for document security",
    )
    encryption_policy_encrypt_phi: bool = Field(
        default=True,
        description="Auto-encrypt documents with detected PHI (requires phi_detection_enabled)",
    )

    # --- Temp File Security Settings (HIPAA §164.310(d)(1)) ---
    temp_secure_delete: bool = Field(
        default=True,
        description="Securely delete temp files using DoD 5220.22-M standard (3-pass overwrite)",
    )
    temp_retention_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours to retain temp files before cleanup (1-168 = 1 hour to 7 days)",
    )
    temp_cleanup_interval_minutes: int = Field(
        default=15,
        ge=5,
        le=60,
        description="Interval between temp cleanup runs in minutes (5-60)",
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

    # --- GDPR Compliance (Data Retention & Erasure) ---
    gdpr_enabled: bool = Field(
        default=False,
        description="Enable GDPR compliance features (data retention, erasure, portability)",
    )
    gdpr_retention_days: int = Field(
        default=365,
        ge=30,
        le=3650,
        description="Days to retain user data after deletion request (30-3650)",
    )
    gdpr_deletion_grace_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Grace period before actual deletion in days (1-365)",
    )
    gdpr_anonymize_audit_logs: bool = Field(
        default=True,
        description="Anonymize audit log references when user is deleted",
    )

    # --- Compliance Reporting ---
    compliance_report_dir: str = Field(
        default="~/.pdfsigner/reports",
        description="Directory to store generated compliance reports",
    )
    compliance_auto_check_enabled: bool = Field(
        default=False,
        description="Enable automatic compliance checks at regular intervals",
    )
    compliance_check_interval_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours between automatic compliance checks (1-168, i.e., 1 hour to 7 days)",
    )

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

    # --- Argentina Compliance (Ley 25.506) ---
    argentine_compliance_enabled: bool = Field(
        default=False,
        description="Enable Argentine digital signature law compliance validation (Ley 25.506)",
    )
    argentine_strict_mode: bool = Field(
        default=False,
        description="Only accept certificates from licensed Argentine certifiers "
        "(AFIP, RENAPER, FDR, etc. - requires argentine_compliance_enabled)",
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

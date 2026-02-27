"""
settings_defaults.py - Default constants and field group mixins for Settings

Extracted from settings.py to reduce file size.
Contains:
- TOML_CONFIG_PATH and default value constants
- Field group mixin classes (SecurityFieldsMixin, HealthcareFieldsMixin,
  ComplianceFieldsMixin, EidasFieldsMixin) that define pydantic Field groups

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr

# --- Default value constants ---
TOML_CONFIG_PATH = Path.home() / ".config" / "pdfsigner" / "config.toml"
DEFAULT_NSS_PATH = Path.home() / ".nss"
DEFAULT_LOG_DIR = Path.home() / ".local" / "share" / "pdfsigner" / "logs"


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


class HealthcareFieldsMixin:
    """Healthcare compliance (HIPAA), encryption, and PHI fields."""

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


class ComplianceFieldsMixin:
    """GDPR, compliance reporting, revocation, LTV, and Argentina fields."""

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

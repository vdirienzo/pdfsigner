"""
settings_compliance.py - Compliance field group mixin (GDPR, LTV, Revocation, Argentina)

Extracted from settings_defaults.py to reduce file size.
Contains ComplianceFieldsMixin with revocation, LTV, GDPR, compliance reporting,
and Argentina compliance fields.

Author: Homero Thompson del Lago del Terror
"""

from pydantic import Field


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

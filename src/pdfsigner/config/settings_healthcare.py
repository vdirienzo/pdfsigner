"""
settings_healthcare.py - Healthcare compliance (HIPAA) field group mixin

Extracted from settings_defaults.py to reduce file size.
Contains HealthcareFieldsMixin with healthcare, encryption, PHI, and temp security fields.

Author: Homero Thompson del Lago del Terror
"""

from typing import Literal

from pydantic import Field


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

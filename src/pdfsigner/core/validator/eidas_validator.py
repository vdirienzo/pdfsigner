"""
eidas_validator.py - Standardized eIDAS signature validation

Implements the EU standardized validation procedure per:
- CIR (EU) 2025/1945: Validation of qualified electronic signatures
- ETSI EN 319 102-1 V1.4.1: AdES creation and validation procedures
- ETSI TS 119 172-4 V1.1.1: Validation policy using trusted lists

Key requirements:
- Revocation freshness: max 24 hours for signing certificates
- "eitherCheck" for non-trust-anchor certificates
- Algorithm strength per SOGIS Agreed Cryptographic Mechanisms
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any


class ValidationStatus(str, Enum):
    """Signature validation status per ETSI EN 319 102-1."""

    TOTAL_PASSED = "TOTAL-PASSED"
    TOTAL_FAILED = "TOTAL-FAILED"
    INDETERMINATE = "INDETERMINATE"


class QualificationLevel(str, Enum):
    """eIDAS qualification level."""

    QES = "QES"  # Qualified Electronic Signature
    ADES_QC = "AdES-QC"  # Advanced with Qualified Certificate
    ADES = "AdES"  # Advanced Electronic Signature
    BASIC = "Basic"  # Basic signature
    NOT_DETERMINED = "not-determined"


@dataclass
class RevocationFreshnessCheck:
    """Result of revocation data freshness check per CIR 2025/1945."""

    is_fresh: bool
    method: str  # "OCSP" or "CRL"
    checked_at: datetime | None = None
    max_age: timedelta = field(default_factory=lambda: timedelta(hours=24))
    age: timedelta | None = None
    message: str = ""


@dataclass
class AlgorithmCheck:
    """Algorithm strength assessment result."""

    is_compliant: bool
    hash_algorithm: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class EidasValidationReport:
    """Comprehensive eIDAS validation report per ETSI TS 119 102-2.

    This report captures all validation steps and their results
    for a single signature within a PDF document.
    """

    # Overall result
    status: ValidationStatus = ValidationStatus.INDETERMINATE
    qualification_level: QualificationLevel = QualificationLevel.NOT_DETERMINED

    # Signature details
    signer_name: str = ""
    signing_time: datetime | None = None
    pades_level: str = ""  # "B-B", "B-T", "B-LT", "B-LTA"

    # Validation sub-results
    crypto_valid: bool = False
    certificate_qualified: bool = False
    qscd_used: bool = False
    tsp_qualified: bool = False
    tsp_name: str | None = None
    tsp_country: str | None = None

    # CIR 2025/1945 specific
    revocation_freshness: RevocationFreshnessCheck | None = None
    algorithm_check: AlgorithmCheck | None = None

    # Issues and recommendations
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Timestamps
    validation_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "qualification_level": self.qualification_level.value,
            "signer_name": self.signer_name,
            "signing_time": self.signing_time.isoformat() if self.signing_time else None,
            "pades_level": self.pades_level,
            "crypto_valid": self.crypto_valid,
            "certificate_qualified": self.certificate_qualified,
            "qscd_used": self.qscd_used,
            "tsp_qualified": self.tsp_qualified,
            "tsp_name": self.tsp_name,
            "tsp_country": self.tsp_country,
            "revocation_fresh": (
                self.revocation_freshness.is_fresh if self.revocation_freshness else None
            ),
            "algorithm_compliant": (
                self.algorithm_check.is_compliant if self.algorithm_check else None
            ),
            "issues": self.issues,
            "recommendations": self.recommendations,
            "validation_time": self.validation_time.isoformat(),
        }


REVOCATION_MAX_AGE = timedelta(hours=24)  # CIR 2025/1945 requirement


def check_revocation_freshness(
    checked_at: datetime | None,
    max_age: timedelta = REVOCATION_MAX_AGE,
) -> RevocationFreshnessCheck:
    """Check if revocation data meets CIR 2025/1945 freshness requirement.

    CIR 2025/1945 requires revocation data to be no older than 24 hours
    for signing certificates (non-trust-anchor).

    Args:
        checked_at: When the revocation check was performed
        max_age: Maximum allowed age (default: 24 hours)

    Returns:
        RevocationFreshnessCheck with result
    """
    if checked_at is None:
        return RevocationFreshnessCheck(
            is_fresh=False,
            method="unknown",
            message="No revocation data available",
        )

    now = datetime.now(UTC)
    # Ensure checked_at is timezone-aware
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=UTC)

    age = now - checked_at
    is_fresh = age <= max_age

    return RevocationFreshnessCheck(
        is_fresh=is_fresh,
        method="OCSP/CRL",
        checked_at=checked_at,
        max_age=max_age,
        age=age,
        message=(
            f"Revocation data age: {age}"
            if is_fresh
            else f"Revocation data too old: {age} > {max_age}"
        ),
    )

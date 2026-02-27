"""
revocation_types.py - Data types for certificate revocation checking

Author: Homero Thompson del Lago del Terror

Contains the data types (enums, dataclasses) used by OCSP and CRL
revocation checkers. Extracted from revocation_checker.py to keep
each module under 400 lines.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from cryptography import x509


class RevocationStatus(Enum):
    """Certificate revocation status."""

    GOOD = "good"  # Certificate is valid and not revoked
    REVOKED = "revoked"  # Certificate has been revoked
    UNKNOWN = "unknown"  # Revocation status cannot be determined
    ERROR = "error"  # Error occurred during check


@dataclass
class RevocationResult:
    """
    Result of a revocation check.

    Attributes:
        status: The revocation status
        checked_at: Timestamp when the check was performed
        method: Method used for check (OCSP or CRL)
        responder_url: URL of the OCSP responder or CRL distribution point
        error_message: Error message if status is ERROR
        revocation_time: When the certificate was revoked (if applicable)
        revocation_reason: Reason for revocation (if applicable)
    """

    status: RevocationStatus
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    method: str = ""
    responder_url: str = ""
    error_message: str | None = None
    revocation_time: datetime | None = None
    revocation_reason: str | None = None

    @property
    def is_valid(self) -> bool:
        """Check if certificate is valid (not revoked)."""
        return self.status == RevocationStatus.GOOD

    @property
    def is_revoked(self) -> bool:
        """Check if certificate is revoked."""
        return self.status == RevocationStatus.REVOKED


@dataclass
class CachedOCSPResponse:
    """Cached OCSP response with expiry."""

    result: RevocationResult
    expires_at: datetime


@dataclass
class CachedCRL:
    """Cached CRL with expiry."""

    crl: x509.CertificateRevocationList
    downloaded_at: datetime
    next_update: datetime | None

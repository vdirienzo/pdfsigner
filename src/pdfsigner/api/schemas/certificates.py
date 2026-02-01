"""Schemas for certificate endpoints.

This module contains models for X.509 certificate operations:
- CertificateInfo: Details about a single certificate
- CertificateChain: Complete certificate chain with validation status

Used for certificate discovery, inspection, and chain validation.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    """X.509 certificate information.

    Attributes:
        id: Unique identifier (typically SHA-1 or SHA-256 fingerprint)
        subject: Distinguished Name of certificate subject
        issuer: Distinguished Name of issuing CA
        serial_number: Certificate serial number (hex format)
        not_before: Certificate validity start date
        not_after: Certificate validity end date
        is_expired: Whether certificate has expired
        days_until_expiry: Number of days until expiration (negative if expired)
        key_usage: Key usage extensions (e.g., "digitalSignature", "keyEncipherment")
        is_ca: Whether this is a Certificate Authority certificate
    """

    id: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    is_expired: bool
    days_until_expiry: int
    key_usage: list[str] = Field(default_factory=list)
    is_ca: bool = False


class CertificateChain(BaseModel):
    """Certificate chain from end-entity to root CA.

    Attributes:
        certificates: Ordered list of certificates (leaf to root)
        is_complete: Whether chain reaches a trusted root CA
        validation_errors: List of chain validation errors/warnings
    """

    certificates: list[CertificateInfo]
    is_complete: bool
    validation_errors: list[str] = Field(default_factory=list)

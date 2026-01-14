"""
mock_certificate.py - Mock certificate classes for dry-run mode

Author: Homero Thompson del Lago del Terror

Simulates certificate information without real hardware.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class MockCertificateInfo:
    """Simulated certificate information."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    pkcs11_id: bytes = b"MOCK_CERT_ID"


@dataclass
class MockCertificate:
    """Simulated certificate for dry-run."""

    info: MockCertificateInfo
    display_name: str
    days_until_expiry: int
    is_expiring_soon: bool = False


def create_mock_certificate(name: str = "Test User") -> MockCertificate:
    """
    Creates a mock certificate for testing.

    Args:
        name: Name of the certificate holder

    Returns:
        Simulated certificate
    """
    now = datetime.now()
    info = MockCertificateInfo(
        subject=f"CN={name}, O=Test Organization, C=AR",
        issuer="CN=Test CA, O=Certificate Authority, C=AR",
        serial_number="1234567890ABCDEF",
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=365),
    )

    return MockCertificate(
        info=info,
        display_name=name,
        days_until_expiry=365,
        is_expiring_soon=False,
    )

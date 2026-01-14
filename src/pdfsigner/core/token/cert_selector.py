"""
cert_selector.py - Token certificate selector

Author: Homero Thompson del Lago del Terror

Filters and selects valid certificates for digital signature
from the SafeNet USB token.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import CertificateExpiredError, CertificateNotFoundError


@dataclass
class ValidCertificate:
    """Validated certificate ready to use."""

    info: CertificateInfo
    days_until_expiry: int
    is_expiring_soon: bool  # Less than 30 days

    @property
    def display_name(self) -> str:
        """Display name for user."""
        # Extract CN from subject
        subject = self.info.subject
        cn_parts = [p for p in subject.split(",") if p.strip().startswith("CN=")]
        if cn_parts:
            return cn_parts[0].split("=")[1].strip()
        return self.info.label


class CertificateSelector:
    """
    Certificate selector for signing.

    Filters valid certificates (not expired, with correct keyUsage)
    and allows user selection if there are multiple.
    """

    EXPIRING_SOON_DAYS = 30

    def __init__(self, nss_handler: NSSHandler):
        """
        Initialize selector.

        Args:
            nss_handler: Authenticated NSS handler
        """
        self.nss_handler = nss_handler

    def get_valid_certificates(self) -> list[ValidCertificate]:
        """
        Get valid certificates for signing.

        Returns:
            List of valid certificates sorted by expiration date

        Raises:
            CertificateNotFoundError: If no valid certificates found
        """
        all_certs = self.nss_handler.list_certificates()
        valid_certs = []
        now = datetime.now(UTC)

        for cert_info in all_certs:
            # Filter only signing certificates
            if not cert_info.can_sign:
                logger.debug(f"Certificate '{cert_info.label}' cannot sign, ignored")
                continue

            # Check expiration
            try:
                not_after = datetime.fromisoformat(cert_info.not_after)
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=UTC)

                if not_after < now:
                    logger.warning(f"Certificate '{cert_info.label}' expired")
                    continue

                days_until_expiry = (not_after - now).days
                is_expiring_soon = days_until_expiry <= self.EXPIRING_SOON_DAYS

                if is_expiring_soon:
                    logger.warning(
                        f"Certificate '{cert_info.label}' expires in {days_until_expiry} days"
                    )

                valid_cert = ValidCertificate(
                    info=cert_info,
                    days_until_expiry=days_until_expiry,
                    is_expiring_soon=is_expiring_soon,
                )
                valid_certs.append(valid_cert)

            except (ValueError, TypeError) as e:
                logger.warning(f"Error processing certificate date: {e}")
                continue

        if not valid_certs:
            raise CertificateNotFoundError("No valid certificates for signing")

        # Sort by expiration date (furthest first)
        valid_certs.sort(key=lambda c: c.days_until_expiry, reverse=True)

        logger.info(f"Found {len(valid_certs)} valid certificates for signing")
        return valid_certs

    def get_default_certificate(self) -> ValidCertificate:
        """
        Get default certificate (the one with longest validity).

        Returns:
            Default certificate

        Raises:
            CertificateNotFoundError: If no valid certificates found
        """
        valid_certs = self.get_valid_certificates()
        return valid_certs[0]

    def select_by_label(self, label: str) -> ValidCertificate:
        """
        Select a certificate by its label.

        Args:
            label: Certificate label

        Returns:
            Selected certificate

        Raises:
            CertificateNotFoundError: If certificate not found
        """
        valid_certs = self.get_valid_certificates()

        for cert in valid_certs:
            if cert.info.label == label:
                return cert

        raise CertificateNotFoundError(f"Certificate '{label}' not found or invalid")

    def validate_certificate(self, cert: ValidCertificate, allow_expiring: bool = True) -> None:
        """
        Validate a certificate before using it.

        Args:
            cert: Certificate to validate
            allow_expiring: Allow certificates about to expire

        Raises:
            CertificateExpiredError: If certificate expired
            CertificateNotFoundError: If certificate not valid for signing
        """
        if cert.days_until_expiry <= 0:
            raise CertificateExpiredError(cert.display_name, cert.info.not_after)

        if not allow_expiring and cert.is_expiring_soon:
            raise CertificateExpiredError(
                cert.display_name,
                f"expires in {cert.days_until_expiry} days ({cert.info.not_after})",
            )

        if not cert.info.can_sign:
            raise CertificateNotFoundError(
                f"Certificate '{cert.display_name}' does not have signing permission"
            )

        logger.debug(f"Certificate '{cert.display_name}' validated correctly")

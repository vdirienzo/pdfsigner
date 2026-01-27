"""
cert_selector.py - Token certificate selector

Author: Homero Thompson del Lago del Terror

Filters and selects valid certificates for digital signature
from the SafeNet USB token.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography import x509
from loguru import logger

from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import CertificateExpiredError, CertificateNotFoundError

if TYPE_CHECKING:
    from pdfsigner.core.certificate.revocation_checker import RevocationChecker


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
    Optionally checks revocation status via OCSP/CRL.
    """

    EXPIRING_SOON_DAYS = 30

    def __init__(
        self, nss_handler: NSSHandler, revocation_checker: "RevocationChecker | None" = None
    ):
        """
        Initialize selector.

        Args:
            nss_handler: Authenticated NSS handler
            revocation_checker: Optional revocation checker for OCSP/CRL validation
        """
        self.nss_handler = nss_handler
        self._revocation_checker = revocation_checker

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

    def validate_certificate(
        self,
        cert: ValidCertificate,
        allow_expiring: bool = True,
        check_revocation: bool = False,
        cert_x509: x509.Certificate | None = None,
        issuer_cert_x509: x509.Certificate | None = None,
    ) -> None:
        """
        Validate a certificate before using it.

        Args:
            cert: Certificate to validate
            allow_expiring: Allow certificates about to expire
            check_revocation: Check revocation status via OCSP/CRL (requires revocation_checker)
            cert_x509: Optional x509.Certificate object for revocation check
            issuer_cert_x509: Optional issuer x509.Certificate for OCSP check

        Raises:
            CertificateExpiredError: If certificate expired
            CertificateNotFoundError: If certificate not valid for signing or revoked
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

        # Check revocation status if requested and checker is available
        if check_revocation and self._revocation_checker:
            if not cert_x509:
                logger.warning(
                    f"Revocation check requested but no x509 certificate provided for "
                    f"'{cert.display_name}' - skipping revocation check"
                )
            else:
                logger.info(f"Checking revocation status for '{cert.display_name}'...")
                try:
                    from pdfsigner.core.certificate.revocation_checker import RevocationStatus

                    result = self._revocation_checker.check_revocation(cert_x509, issuer_cert_x509)

                    if result.status == RevocationStatus.REVOKED:
                        error_msg = f"Certificate '{cert.display_name}' has been revoked"
                        if result.revocation_time:
                            error_msg += f" on {result.revocation_time}"
                        if result.revocation_reason:
                            error_msg += f" (reason: {result.revocation_reason})"
                        logger.error(error_msg)
                        raise CertificateNotFoundError(error_msg)
                    elif result.status == RevocationStatus.GOOD:
                        logger.info(
                            f"Certificate '{cert.display_name}' revocation status: GOOD "
                            f"(checked via {result.method})"
                        )
                    else:
                        logger.warning(
                            f"Certificate '{cert.display_name}' revocation status: "
                            f"{result.status.value} - {result.error_message or 'unknown'}"
                        )
                except Exception as e:
                    logger.warning(
                        f"Error checking revocation for '{cert.display_name}': {e} "
                        f"- continuing without revocation check"
                    )
        elif check_revocation and not self._revocation_checker:
            logger.warning(
                "Revocation check requested but no RevocationChecker configured - skipping"
            )

        logger.debug(f"Certificate '{cert.display_name}' validated correctly")

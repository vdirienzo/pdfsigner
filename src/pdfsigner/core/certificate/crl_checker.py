"""
crl_checker.py - CRL certificate revocation checker

Author: Homero Thompson del Lago del Terror

Downloads and parses CRLs to verify certificate revocation status
with intelligent caching based on CRL nextUpdate field.
"""

from datetime import UTC, datetime

import requests
from cryptography import x509
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID
from loguru import logger

from pdfsigner.core.certificate.revocation_types import (
    CachedCRL,
    RevocationResult,
    RevocationStatus,
)


class CRLChecker:
    """
    CRL (Certificate Revocation List) checker.

    Downloads and parses CRLs to verify certificate revocation status
    with intelligent caching based on CRL nextUpdate field.
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize CRL checker.

        Args:
            timeout: HTTP request timeout in seconds (CRLs can be large)
        """
        self.timeout = timeout
        self._cache: dict[str, CachedCRL] = {}

    def check(self, cert: x509.Certificate) -> RevocationResult:
        """
        Check certificate revocation status via CRL.

        Args:
            cert: Certificate to check

        Returns:
            RevocationResult with status and details
        """
        try:
            # Extract CRL distribution points
            crl_urls = self._get_crl_urls(cert)
            if not crl_urls:
                return RevocationResult(
                    status=RevocationStatus.UNKNOWN,
                    method="CRL",
                    error_message="No CRL distribution points found in certificate",
                )

            # Try each CRL URL
            for crl_url in crl_urls:
                try:
                    result = self._check_with_crl(cert, crl_url)
                    if result.status != RevocationStatus.ERROR:
                        return result
                except Exception as e:
                    logger.warning(f"CRL check failed for {crl_url}: {e}")
                    continue

            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="CRL",
                error_message="All CRL distribution points failed",
            )

        except Exception as e:
            logger.error(f"CRL check error: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="CRL",
                error_message=f"CRL check error: {str(e)}",
            )

    def _check_with_crl(self, cert: x509.Certificate, crl_url: str) -> RevocationResult:
        """Check certificate against a specific CRL."""
        # Check cache
        cached_crl = self._cache.get(crl_url)
        if cached_crl:
            if cached_crl.next_update and cached_crl.next_update > datetime.now(UTC):
                logger.debug(f"CRL cache hit for {crl_url}")
                return self._check_cert_in_crl(cert, cached_crl.crl, crl_url)

        # Download CRL
        # SSRF protection: validate URL before making request
        from pdfsigner.core.security.url_validator import SSRFError, validate_crl_url

        try:
            validated_url = validate_crl_url(crl_url)
        except SSRFError as e:
            logger.warning(f"CRL URL validation failed: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="CRL",
                responder_url=crl_url,
                error_message=f"SSRF protection: {e}",
            )

        logger.debug(f"Downloading CRL from {validated_url}")
        response = requests.get(validated_url, timeout=self.timeout)
        response.raise_for_status()

        # Parse CRL
        crl = x509.load_der_x509_crl(response.content)

        # Cache CRL
        self._cache[crl_url] = CachedCRL(
            crl=crl,
            downloaded_at=datetime.now(UTC),
            next_update=crl.next_update_utc,
        )

        return self._check_cert_in_crl(cert, crl, crl_url)

    def _check_cert_in_crl(
        self, cert: x509.Certificate, crl: x509.CertificateRevocationList, crl_url: str
    ) -> RevocationResult:
        """Check if certificate is in the revoked list."""
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)

        if revoked_cert:
            revocation_time = revoked_cert.revocation_date_utc
            revocation_reason = None

            # Try to extract revocation reason
            try:
                reason_ext = revoked_cert.extensions.get_extension_for_oid(
                    CRLEntryExtensionOID.CRL_REASON
                )
                reason_value = reason_ext.value
                # Type assertion: value is CRLReason
                if isinstance(reason_value, x509.CRLReason):
                    revocation_reason = str(reason_value.reason.name)
            except x509.ExtensionNotFound:
                pass

            logger.info(f"Certificate {cert.serial_number} found in CRL (revoked)")
            return RevocationResult(
                status=RevocationStatus.REVOKED,
                method="CRL",
                responder_url=crl_url,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            )

        logger.info(f"Certificate {cert.serial_number} not found in CRL (good)")
        return RevocationResult(
            status=RevocationStatus.GOOD,
            method="CRL",
            responder_url=crl_url,
        )

    def _get_crl_urls(self, cert: x509.Certificate) -> list[str]:
        """Extract CRL distribution point URLs from certificate."""
        urls: list[str] = []
        try:
            crl_dist_points_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            crl_dist_points = crl_dist_points_ext.value

            # Iterate over distribution points (duck typing for mock compatibility)
            for dist_point in crl_dist_points:  # type: ignore[attr-defined]
                if dist_point.full_name:
                    for general_name in dist_point.full_name:
                        if isinstance(general_name, x509.UniformResourceIdentifier):
                            urls.append(general_name.value)

        except x509.ExtensionNotFound:
            logger.debug("No CRL distribution points extension found")
        except Exception as e:
            logger.error(f"Error extracting CRL URLs: {e}")

        return urls

    def clear_cache(self) -> None:
        """Clear the CRL cache."""
        self._cache.clear()
        logger.debug("CRL cache cleared")

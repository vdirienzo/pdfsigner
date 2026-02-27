"""
revocation_checker.py - Certificate revocation checking via OCSP and CRL

Author: Homero Thompson del Lago del Terror

Provides comprehensive certificate revocation status verification using
OCSP and CRL with intelligent caching and fallback mechanisms.

OCSPChecker and CRLChecker are in separate modules; this file re-exports
them and provides the RevocationChecker facade.
"""

from cryptography import x509
from loguru import logger

# Re-export classes for backward compatibility
from pdfsigner.core.certificate.crl_checker import CRLChecker  # noqa: F401
from pdfsigner.core.certificate.ocsp_checker import OCSPChecker  # noqa: F401
from pdfsigner.core.certificate.revocation_types import (  # noqa: F401
    CachedCRL,
    CachedOCSPResponse,
    RevocationResult,
    RevocationStatus,
)


class RevocationChecker:
    """
    Main revocation checker with OCSP and CRL support.

    Attempts OCSP first for speed, falls back to CRL if OCSP fails.
    Provides configurable timeout and caching behavior.
    """

    def __init__(
        self,
        ocsp_timeout: int = 10,
        crl_timeout: int = 30,
        ocsp_cache_ttl: int = 3600,
        prefer_ocsp: bool = True,
    ):
        """
        Initialize revocation checker.

        Args:
            ocsp_timeout: OCSP request timeout in seconds
            crl_timeout: CRL download timeout in seconds
            ocsp_cache_ttl: OCSP cache TTL in seconds
            prefer_ocsp: Try OCSP before CRL (default: True)
        """
        self.prefer_ocsp = prefer_ocsp
        self.ocsp_checker = OCSPChecker(timeout=ocsp_timeout, cache_ttl_seconds=ocsp_cache_ttl)
        self.crl_checker = CRLChecker(timeout=crl_timeout)

    def check_revocation(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate | None = None,
    ) -> RevocationResult:
        """
        Check certificate revocation status.

        Tries OCSP first (if prefer_ocsp=True), then falls back to CRL.
        If OCSP requires issuer certificate but it's not provided, skips to CRL.

        Args:
            cert: Certificate to check
            issuer_cert: Issuer certificate (required for OCSP)

        Returns:
            RevocationResult with status and method used
        """
        logger.info(f"Checking revocation for certificate: {cert.subject}")

        if self.prefer_ocsp:
            return self._check_ocsp_then_crl(cert, issuer_cert)
        else:
            return self._check_crl_then_ocsp(cert, issuer_cert)

    def _check_ocsp_then_crl(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate | None,
    ) -> RevocationResult:
        """Try OCSP first, fall back to CRL."""
        if issuer_cert:
            logger.debug("Attempting OCSP check")
            result = self.ocsp_checker.check(cert, issuer_cert)

            if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                return result

            logger.debug(f"OCSP check unsuccessful: {result.error_message}, falling back to CRL")
        else:
            logger.debug("No issuer certificate provided, skipping OCSP")

        logger.debug("Attempting CRL check")
        result = self.crl_checker.check(cert)

        if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
            return result

        logger.warning("Both OCSP and CRL checks failed")
        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method="OCSP+CRL",
            error_message="Both OCSP and CRL checks failed or unavailable",
        )

    def _check_crl_then_ocsp(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate | None,
    ) -> RevocationResult:
        """Try CRL first, fall back to OCSP."""
        logger.debug("Attempting CRL check")
        result = self.crl_checker.check(cert)

        if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
            return result

        if issuer_cert:
            logger.debug("CRL check unsuccessful, falling back to OCSP")
            result = self.ocsp_checker.check(cert, issuer_cert)

            if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                return result
        else:
            logger.debug("No issuer certificate provided, cannot try OCSP")

        logger.warning("Both CRL and OCSP checks failed")
        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method="CRL+OCSP",
            error_message="Both CRL and OCSP checks failed or unavailable",
        )

    def clear_caches(self) -> None:
        """Clear all caches (OCSP and CRL)."""
        self.ocsp_checker.clear_cache()
        self.crl_checker.clear_cache()
        logger.info("All revocation caches cleared")

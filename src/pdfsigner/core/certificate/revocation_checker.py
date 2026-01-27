"""
revocation_checker.py - Certificate revocation checking via OCSP and CRL

Author: Homero Thompson del Lago del Terror

Provides comprehensive certificate revocation status verification using
OCSP (Online Certificate Status Protocol) and CRL (Certificate Revocation Lists)
with intelligent caching and fallback mechanisms.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CRLEntryExtensionOID,
    ExtensionOID,
)

logger = logging.getLogger(__name__)


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


class OCSPChecker:
    """
    OCSP (Online Certificate Status Protocol) checker.

    Queries OCSP responders to verify certificate revocation status
    with in-memory caching to reduce network requests.
    """

    def __init__(self, timeout: int = 10, cache_ttl_seconds: int = 3600):
        """
        Initialize OCSP checker.

        Args:
            timeout: HTTP request timeout in seconds
            cache_ttl_seconds: Cache time-to-live in seconds (default: 1 hour)
        """
        self.timeout = timeout
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, CachedOCSPResponse] = {}

    def check(self, cert: x509.Certificate, issuer_cert: x509.Certificate) -> RevocationResult:
        """
        Check certificate revocation status via OCSP.

        Args:
            cert: Certificate to check
            issuer_cert: Issuer certificate

        Returns:
            RevocationResult with status and details
        """
        try:
            # Extract OCSP responder URL
            responder_url = self._get_ocsp_responder_url(cert)
            if not responder_url:
                return RevocationResult(
                    status=RevocationStatus.UNKNOWN,
                    method="OCSP",
                    error_message="No OCSP responder URL found in certificate",
                )

            # Check cache
            cache_key = self._get_cache_key(cert)
            cached = self._cache.get(cache_key)
            if cached and cached.expires_at > datetime.now(UTC):
                logger.debug(f"OCSP cache hit for {cache_key}")
                return cached.result

            # Build OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
            ocsp_request = builder.build()

            # Send request
            ocsp_request_der = ocsp_request.public_bytes(Encoding.DER)
            headers = {"Content-Type": "application/ocsp-request"}

            logger.debug(f"Sending OCSP request to {responder_url}")
            response = requests.post(
                responder_url,
                data=ocsp_request_der,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()

            # Parse response
            ocsp_response = ocsp.load_der_ocsp_response(response.content)

            # Check response status
            if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                return RevocationResult(
                    status=RevocationStatus.ERROR,
                    method="OCSP",
                    responder_url=responder_url,
                    error_message=f"OCSP response status: {ocsp_response.response_status.name}",
                )

            # Extract certificate status
            cert_status = ocsp_response.certificate_status

            if cert_status == ocsp.OCSPCertStatus.GOOD:
                result = RevocationResult(
                    status=RevocationStatus.GOOD,
                    method="OCSP",
                    responder_url=responder_url,
                )
            elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                revocation_time = getattr(ocsp_response, "revocation_time", None)
                revocation_reason = getattr(ocsp_response, "revocation_reason", None)
                result = RevocationResult(
                    status=RevocationStatus.REVOKED,
                    method="OCSP",
                    responder_url=responder_url,
                    revocation_time=revocation_time,
                    revocation_reason=str(revocation_reason) if revocation_reason else None,
                )
            else:
                result = RevocationResult(
                    status=RevocationStatus.UNKNOWN,
                    method="OCSP",
                    responder_url=responder_url,
                )

            # Cache result
            self._cache[cache_key] = CachedOCSPResponse(
                result=result,
                expires_at=datetime.now(UTC) + timedelta(seconds=self.cache_ttl_seconds),
            )

            logger.info(f"OCSP check completed: {result.status.value} for {cache_key}")
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"OCSP request timeout for {responder_url}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                responder_url=responder_url,
                error_message="OCSP request timeout",
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"OCSP request failed: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                responder_url=responder_url,
                error_message=f"OCSP request failed: {str(e)}",
            )
        except Exception as e:
            logger.error(f"OCSP check error: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message=f"OCSP check error: {str(e)}",
            )

    def _get_ocsp_responder_url(self, cert: x509.Certificate) -> str | None:
        """
        Extract OCSP responder URL from certificate.

        Args:
            cert: Certificate to extract URL from

        Returns:
            OCSP responder URL or None if not found
        """
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            aia = aia_ext.value

            for access_description in aia:
                if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                    return access_description.access_location.value

        except x509.ExtensionNotFound:
            logger.debug("No Authority Information Access extension found")
        except Exception as e:
            logger.error(f"Error extracting OCSP URL: {e}")

        return None

    def _get_cache_key(self, cert: x509.Certificate) -> str:
        """
        Generate cache key for certificate.

        Args:
            cert: Certificate

        Returns:
            Cache key (hex digest of certificate serial number)
        """
        serial = str(cert.serial_number).encode()
        return hashlib.sha256(serial).hexdigest()

    def clear_cache(self) -> None:
        """Clear the OCSP response cache."""
        self._cache.clear()
        logger.debug("OCSP cache cleared")


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
        """
        Check certificate against a specific CRL.

        Args:
            cert: Certificate to check
            crl_url: CRL distribution point URL

        Returns:
            RevocationResult with status
        """
        # Check cache
        cached_crl = self._cache.get(crl_url)
        if cached_crl:
            if cached_crl.next_update and cached_crl.next_update > datetime.now(UTC):
                logger.debug(f"CRL cache hit for {crl_url}")
                return self._check_cert_in_crl(cert, cached_crl.crl, crl_url)

        # Download CRL
        logger.debug(f"Downloading CRL from {crl_url}")
        response = requests.get(crl_url, timeout=self.timeout)
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
        """
        Check if certificate is in the revoked list.

        Args:
            cert: Certificate to check
            crl: CRL to check against
            crl_url: CRL URL for reference

        Returns:
            RevocationResult
        """
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)

        if revoked_cert:
            revocation_time = revoked_cert.revocation_date_utc
            revocation_reason = None

            # Try to extract revocation reason
            try:
                reason_ext = revoked_cert.extensions.get_extension_for_oid(
                    CRLEntryExtensionOID.CRL_REASON
                )
                revocation_reason = str(reason_ext.value.reason.name)
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
        """
        Extract CRL distribution point URLs from certificate.

        Args:
            cert: Certificate

        Returns:
            List of CRL URLs
        """
        urls = []
        try:
            crl_dist_points_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            crl_dist_points = crl_dist_points_ext.value

            for dist_point in crl_dist_points:
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
            # Try OCSP first
            if issuer_cert:
                logger.debug("Attempting OCSP check")
                result = self.ocsp_checker.check(cert, issuer_cert)

                if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                    return result

                logger.debug(
                    f"OCSP check unsuccessful: {result.error_message}, falling back to CRL"
                )
            else:
                logger.debug("No issuer certificate provided, skipping OCSP")

            # Fallback to CRL
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
        else:
            # Try CRL first
            logger.debug("Attempting CRL check")
            result = self.crl_checker.check(cert)

            if result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                return result

            # Fallback to OCSP
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

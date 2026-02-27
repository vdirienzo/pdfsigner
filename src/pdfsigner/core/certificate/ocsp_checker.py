"""
ocsp_checker.py - OCSP certificate revocation checker

Author: Homero Thompson del Lago del Terror

Queries OCSP responders to verify certificate revocation status
with in-memory caching to reduce network requests.
"""

import hashlib
from datetime import UTC, datetime, timedelta

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from loguru import logger

from pdfsigner.core.certificate.revocation_types import (
    CachedOCSPResponse,
    RevocationResult,
    RevocationStatus,
)


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
        responder_url: str | None = None
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

            # SSRF protection: validate URL before making request
            from pdfsigner.core.security.url_validator import SSRFError, validate_ocsp_url

            try:
                validated_url = validate_ocsp_url(responder_url)
            except SSRFError as e:
                logger.warning(f"OCSP URL validation failed: {e}")
                return RevocationResult(
                    status=RevocationStatus.ERROR,
                    method="OCSP",
                    responder_url=responder_url,
                    error_message=f"SSRF protection: {e}",
                )

            logger.debug(f"Sending OCSP request to {validated_url}")
            response = requests.post(
                validated_url,
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
            result = self._parse_cert_status(ocsp_response, responder_url)

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
                responder_url=responder_url or "",
                error_message="OCSP request timeout",
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"OCSP request failed: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                responder_url=responder_url or "",
                error_message=f"OCSP request failed: {str(e)}",
            )
        except Exception as e:
            logger.error(f"OCSP check error: {e}")
            return RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message=f"OCSP check error: {str(e)}",
            )

    def _parse_cert_status(
        self, ocsp_response: ocsp.OCSPResponse, responder_url: str
    ) -> RevocationResult:
        """Parse OCSP response certificate status into a RevocationResult."""
        cert_status = ocsp_response.certificate_status

        if cert_status == ocsp.OCSPCertStatus.GOOD:
            return RevocationResult(
                status=RevocationStatus.GOOD,
                method="OCSP",
                responder_url=responder_url,
            )
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            revocation_time = getattr(ocsp_response, "revocation_time", None)
            revocation_reason = getattr(ocsp_response, "revocation_reason", None)
            return RevocationResult(
                status=RevocationStatus.REVOKED,
                method="OCSP",
                responder_url=responder_url,
                revocation_time=revocation_time,
                revocation_reason=str(revocation_reason) if revocation_reason else None,
            )
        else:
            return RevocationResult(
                status=RevocationStatus.UNKNOWN,
                method="OCSP",
                responder_url=responder_url,
            )

    def _get_ocsp_responder_url(self, cert: x509.Certificate) -> str | None:
        """Extract OCSP responder URL from certificate."""
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            aia = aia_ext.value

            # Iterate over access descriptions (duck typing for mock compatibility)
            for access_description in aia:  # type: ignore[attr-defined]
                if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                    return access_description.access_location.value

        except x509.ExtensionNotFound:
            logger.debug("No Authority Information Access extension found")
        except Exception as e:
            logger.error(f"Error extracting OCSP URL: {e}")

        return None

    def _get_cache_key(self, cert: x509.Certificate) -> str:
        """Generate cache key from certificate serial number."""
        serial = str(cert.serial_number).encode()
        return hashlib.sha256(serial).hexdigest()

    def clear_cache(self) -> None:
        """Clear the OCSP response cache."""
        self._cache.clear()
        logger.debug("OCSP cache cleared")

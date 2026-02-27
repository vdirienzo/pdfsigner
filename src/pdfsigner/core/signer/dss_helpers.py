"""
dss_helpers.py - Helper functions for DSS validation info collection

Extracted from dss_manager.py to keep modules under 400 lines.
Contains OCSP/CRL fetching, caching, and certificate URL extraction.
"""

import hashlib
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from loguru import logger


def ocsp_cache_key(cert: x509.Certificate, responder_url: str) -> str:
    """Generate a cache key for OCSP responses from cert serial + responder URL."""
    serial = str(cert.serial_number).encode()
    return hashlib.sha256(serial + responder_url.encode()).hexdigest()


def check_ocsp_cache(
    cache: dict[str, tuple[bytes, float]],
    cache_key: str,
    cache_ttl: float,
) -> bytes | None:
    """Check OCSP cache for a valid (non-expired) response.

    Args:
        cache: The OCSP response cache dict
        cache_key: Cache key for the certificate/responder pair
        cache_ttl: Cache time-to-live in seconds

    Returns:
        Cached OCSP response bytes or None if not found/expired
    """
    cached = cache.get(cache_key)
    if cached is not None:
        response_bytes, cached_at = cached
        if (time.monotonic() - cached_at) < cache_ttl:
            logger.debug(f"OCSP cache hit for {cache_key[:16]}...")
            return response_bytes
        del cache[cache_key]
    return None


def fetch_ocsp_response(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    responder_url: str,
    timeout: int,
    cache: dict[str, tuple[bytes, float]],
    cache_key: str,
) -> bytes | None:
    """Build, send, and validate an OCSP request. Cache on success.

    Args:
        cert: Certificate to check
        issuer_cert: Issuer certificate
        responder_url: OCSP responder URL
        timeout: HTTP request timeout in seconds
        cache: The OCSP response cache dict
        cache_key: Key for caching the response

    Returns:
        OCSP response bytes or None on failure
    """
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    ocsp_request = builder.build()

    ocsp_request_der = ocsp_request.public_bytes(Encoding.DER)
    headers = {"Content-Type": "application/ocsp-request"}

    response = requests.post(
        responder_url,
        data=ocsp_request_der,
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
        cache[cache_key] = (response.content, time.monotonic())
        return response.content

    logger.warning(f"Respuesta OCSP no exitosa: {ocsp_response.response_status.name}")
    return None


def get_ocsp_responder_url(cert: x509.Certificate) -> str | None:
    """
    Extract OCSP responder URL from certificate.

    Args:
        cert: Certificate

    Returns:
        OCSP responder URL or None
    """
    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia = aia_ext.value

        for access_description in aia:  # type: ignore[attr-defined]
            if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                return access_description.access_location.value

    except x509.ExtensionNotFound:
        logger.debug("No se encontro extension Authority Information Access")
    except Exception as e:
        cert_subject = getattr(cert, "subject", "unknown")
        logger.warning(
            f"Failed to extract OCSP URL from certificate (subject={cert_subject}): {e}. "
            "Will fall back to CRL for revocation check."
        )

    return None


def get_crl_urls(cert: x509.Certificate) -> list[str]:
    """
    Extract CRL distribution point URLs from certificate.

    Args:
        cert: Certificate

    Returns:
        List of CRL URLs
    """
    urls: list[str] = []
    try:
        crl_dist_points_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        crl_dist_points = crl_dist_points_ext.value

        for dist_point in crl_dist_points:  # type: ignore[attr-defined]
            if dist_point.full_name:
                for general_name in dist_point.full_name:
                    if isinstance(general_name, x509.UniformResourceIdentifier):
                        urls.append(general_name.value)

    except x509.ExtensionNotFound:
        logger.debug("No se encontro extension CRL Distribution Points")
    except Exception as e:
        cert_subject = getattr(cert, "subject", "unknown")
        logger.warning(
            f"Failed to extract CRL URLs from certificate (subject={cert_subject}): {e}. "
            "Revocation check may be incomplete for this certificate."
        )

    return urls


def get_crl_bytes(
    cert: x509.Certificate,
    crl_timeout: int,
    cache: dict[str, tuple[bytes, float]],
    cache_ttl: float,
) -> bytes | None:
    """
    Get CRL in DER format with in-memory caching.

    Uses a TTL cache keyed by CRL URL to avoid repeated downloads
    during batch signing operations.

    Args:
        cert: Certificate to get CRL for
        crl_timeout: HTTP timeout in seconds
        cache: The CRL cache dict
        cache_ttl: Cache time-to-live in seconds

    Returns:
        CRL bytes in DER format or None on failure
    """
    try:
        crl_url_list = get_crl_urls(cert)
        if not crl_url_list:
            logger.debug("No se encontraron puntos de distribucion de CRL")
            return None

        for crl_url in crl_url_list:
            try:
                # Check cache before downloading
                cached = cache.get(crl_url)
                if cached is not None:
                    crl_bytes, cached_at = cached
                    if (time.monotonic() - cached_at) < cache_ttl:
                        logger.debug(f"CRL cache hit for {crl_url}")
                        return crl_bytes
                    del cache[crl_url]

                logger.debug(f"Descargando CRL desde {crl_url}")
                response = requests.get(crl_url, timeout=crl_timeout)
                response.raise_for_status()

                # Validate CRL
                x509.load_der_x509_crl(response.content)
                cache[crl_url] = (response.content, time.monotonic())
                return response.content

            except Exception as e:
                logger.warning(f"Error descargando CRL desde {crl_url}: {e}")
                continue

        logger.warning("Todas las URLs de distribucion de CRL fallaron")
        return None

    except Exception as e:
        logger.warning(f"Error obteniendo CRL: {e}")
        return None

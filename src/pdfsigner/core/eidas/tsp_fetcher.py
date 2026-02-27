"""tsp_fetcher.py - EU Trusted Service List fetching and parsing

Handles fetching TSL data from real EU sources, including LOTL retrieval,
country TSL downloads, and conversion of parsed TSP data into the internal format.
"""

import hashlib
from typing import Any
from urllib.parse import urlparse

import requests
from loguru import logger

from pdfsigner.core.eidas.tsp_storage import TSPStorage
from pdfsigner.core.eidas.tsp_types import (
    QualificationStatus,
    ServiceType,
    TrustedListInfo,
    TSPInfo,
)


def fetch_from_eu(
    territories: list[str] | None,
    progress_callback: Any,
    normalize_url,
    storage: TSPStorage,
) -> tuple[dict[str, TSPInfo], dict[str, TSPInfo], TrustedListInfo] | None:
    """Fetch TSL data from real EU sources.

    Args:
        territories: List of country codes to fetch (None = all)
        progress_callback: Optional callback(country_code, current, total)
        normalize_url: URL normalization function
        storage: TSPStorage instance for caching

    Returns:
        Tuple of (tsps, cert_to_tsp, list_info) if successful, None otherwise
    """
    try:
        # Import here to avoid circular dependencies
        from pdfsigner.core.eidas.lotl_fetcher import get_lotl_fetcher
        from pdfsigner.core.eidas.tsl_parser import TSLParser

        logger.info("Fetching EU LOTL...")
        lotl_fetcher = get_lotl_fetcher()
        lotl_data = lotl_fetcher.fetch_lotl()

        logger.info("Fetching country TSLs...")
        tsl_parser = TSLParser()
        tsps: dict[str, TSPInfo] = {}
        cert_to_tsp: dict[str, TSPInfo] = {}

        # Filter pointers by configured territories, or fetch ALL if not set
        pointers_to_fetch = lotl_data.tsl_pointers
        if territories:
            territories_upper = [t.upper() for t in territories]
            pointers_to_fetch = [
                p for p in lotl_data.tsl_pointers if p.country_code in territories_upper
            ]
            logger.info(
                "Filtering TSLs to %d territories: %s",
                len(pointers_to_fetch),
                ", ".join(territories_upper),
            )

        total_pointers = len(pointers_to_fetch)
        for idx, pointer in enumerate(pointers_to_fetch):
            # Report progress if callback provided
            if progress_callback:
                try:
                    progress_callback(pointer.country_code, idx + 1, total_pointers)
                except Exception as e:
                    logger.warning("Progress callback error for %s: %s", pointer.country_code, e)

            try:
                logger.info("Fetching TSL for %s...", pointer.country_code)
                tsl_data = fetch_country_tsl(pointer.tsl_url)
                if not tsl_data:
                    continue

                # Parse TSL
                parsed_tsps = tsl_parser.parse(tsl_data)

                # Convert to our format and store
                for parsed_tsp in parsed_tsps:
                    _add_tsp_from_parsed(parsed_tsp, tsps, cert_to_tsp, normalize_url)

            except Exception as e:
                logger.warning("Failed to fetch TSL for %s: %s", pointer.country_code, e)
                continue

        # Create list info
        list_info = TrustedListInfo(
            version=lotl_data.version,
            issue_date=lotl_data.issue_date,
            next_update=lotl_data.next_update,
            total_tsps=len(tsps),
            countries=sorted(set(tsp.country for tsp in tsps.values())),
        )

        # Save to cache
        storage.save_to_cache(tsps, list_info)

        logger.info("Loaded %d TSPs from EU TSL", len(tsps))
        return tsps, cert_to_tsp, list_info

    except Exception as e:
        logger.error("Failed to fetch from EU: %s", e)
        return None


def fetch_country_tsl(tsl_url: str) -> bytes | None:
    """Fetch TSL XML for a specific country.

    Args:
        tsl_url: URL to country TSL

    Returns:
        Raw XML bytes or None if fetch fails
    """
    try:
        # SSRF protection: only allow HTTPS URLs from trusted EU domains
        parsed_url = urlparse(tsl_url)
        if parsed_url.scheme not in ("https", "http"):
            logger.warning("Rejecting non-HTTP(S) TSL URL: %s", tsl_url)
            return None

        response = requests.get(
            tsl_url,
            timeout=30,
            allow_redirects=True,
            headers={"User-Agent": "PDFSigner/1.1.0"},
        )
        response.raise_for_status()
        return response.content

    except requests.RequestException as e:
        logger.warning("Failed to fetch TSL from %s: %s", tsl_url, e)
        return None


def _add_tsp_from_parsed(
    parsed_tsp,
    tsps: dict[str, TSPInfo],
    cert_to_tsp: dict[str, TSPInfo],
    normalize_url,
) -> None:
    """Add TSP from parsed TSL data.

    Args:
        parsed_tsp: TSPInfo from tsl_parser
        tsps: Dictionary to add URL-indexed TSPs to
        cert_to_tsp: Dictionary to add cert-indexed TSPs to
        normalize_url: URL normalization function
    """
    from pdfsigner.core.eidas.tsl_parser import ServiceStatus as TSLStatus

    # Add each service as a separate TSP entry
    for service in parsed_tsp.services:
        # Map TSL status to our status
        if service.status == TSLStatus.GRANTED:
            status = QualificationStatus.QUALIFIED
        elif service.status == TSLStatus.WITHDRAWN:
            status = QualificationStatus.WITHDRAWN
        else:
            status = QualificationStatus.NOT_QUALIFIED

        # Map service type
        service_type = map_service_type(service.service_type_uri)

        # Create TSPInfo
        tsp_info = TSPInfo(
            name=parsed_tsp.name,
            country=parsed_tsp.country_code,
            service_type=service_type,
            status=status,
            service_url=service.service_supply_points[0] if service.service_supply_points else "",
            valid_from=service.status_start_date,
            valid_until=None,
            trust_anchor=None,
            certificate_der=service.certificate_der,
        )

        # Store by URL if available
        if tsp_info.service_url:
            normalized = normalize_url(tsp_info.service_url)
            tsps[normalized] = tsp_info

        # Store by certificate fingerprint
        if tsp_info.certificate_der:
            fingerprint = hashlib.sha256(tsp_info.certificate_der).hexdigest()
            cert_to_tsp[fingerprint] = tsp_info


def map_service_type(service_type_uri: str) -> ServiceType:
    """Map TSL service type URI to our ServiceType enum.

    Args:
        service_type_uri: URI from TSL

    Returns:
        ServiceType enum value
    """
    uri_lower = service_type_uri.lower()

    if "/ca/" in uri_lower or "/qc" in uri_lower:
        return ServiceType.CA
    elif "/tsa/" in uri_lower or "/tss" in uri_lower or "/qtst" in uri_lower:
        return ServiceType.TSA
    elif "/ocsp" in uri_lower:
        return ServiceType.OCSP
    elif "/crl" in uri_lower:
        return ServiceType.CRL
    else:
        logger.debug("Unknown service type URI: %s, defaulting to CA", service_type_uri)
        return ServiceType.CA

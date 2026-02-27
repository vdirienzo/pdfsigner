"""
qualified_tsa_selector.py - Intelligent TSA selection from EU Trusted Lists

Author: Homero Thompson del Lago del Terror

Extracts qualified Time Stamp Authorities from EUTL and provides
automatic TSA selection for eIDAS-compliant timestamping.

Standards:
- ETSI TS 119 612 (Trusted Lists - ServiceType TSA/QTST)
- CIR (EU) 2025/1929 (Qualified electronic time stamps)
- ETSI EN 319 421 (TSA requirements)
"""

from dataclasses import dataclass, field

from loguru import logger

# ETSI TS 119 612 Service Type URIs for TSAs
TSA_QTST_URI = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
TSA_TSS_QC_URI = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"
TSA_GENERIC_URI = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
STATUS_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

# Well-known qualified TSA URLs as ultimate fallback
# These are widely used TSAs with EU/international recognition
FALLBACK_QUALIFIED_TSAS: list[dict[str, str]] = [
    {
        "name": "DigiCert Timestamp Authority",
        "url": "http://timestamp.digicert.com",
        "country": "US",
    },
    {
        "name": "Sectigo Timestamp Authority",
        "url": "http://timestamp.sectigo.com",
        "country": "EU",
    },
]


@dataclass
class QualifiedTSA:
    """A qualified TSA from the EU Trusted List."""

    name: str
    country: str  # ISO 3166-1 alpha-2
    service_url: str
    qualified: bool = True
    service_type: str = ""  # URI of service type


@dataclass
class TSASelectionResult:
    """Result of TSA selection."""

    selected_url: str = ""
    selected_name: str = ""
    selected_country: str = ""
    is_qualified: bool = False
    fallback_urls: list[str] = field(default_factory=list)
    all_qualified_tsas: list[QualifiedTSA] = field(default_factory=list)
    selection_reason: str = ""


def get_qualified_tsas_from_registry() -> list[QualifiedTSA]:
    """Extract qualified TSA URLs from the loaded TSP registry.

    Queries the EUTSPRegistry for entries with ServiceType TSA
    and QualificationStatus QUALIFIED.

    Returns:
        List of QualifiedTSA entries with granted/qualified status
    """
    from pdfsigner.core.eidas.tsp_registry import (
        QualificationStatus,
        ServiceType,
        get_tsp_registry,
    )

    try:
        registry = get_tsp_registry()
        tsa_entries = registry.get_tsps_by_type(ServiceType.TSA)
    except Exception as e:
        logger.warning("Failed to query TSP registry for TSAs: %s", e)
        return []

    qualified_tsas: list[QualifiedTSA] = []

    for tsp in tsa_entries:
        if tsp.status != QualificationStatus.QUALIFIED:
            continue
        if not tsp.service_url:
            logger.debug("Skipping TSA '%s' with no service URL", tsp.name)
            continue

        qualified_tsas.append(
            QualifiedTSA(
                name=tsp.name,
                country=tsp.country,
                service_url=tsp.service_url,
                qualified=True,
                service_type=TSA_QTST_URI,
            )
        )

    logger.info(
        "Found %d qualified TSAs from EUTL registry",
        len(qualified_tsas),
    )
    return qualified_tsas


def select_best_tsa(
    preferred_country: str | None = None,
    exclude_urls: list[str] | None = None,
) -> TSASelectionResult:
    """Select the best qualified TSA from EUTL.

    Selection criteria (in priority order):
    1. Preferred country match (if specified)
    2. Qualified status (TSA/QTST + granted)
    3. Remaining qualified TSAs as fallbacks

    Args:
        preferred_country: ISO country code to prefer (e.g., "DE")
        exclude_urls: URLs to exclude (e.g., previously failed TSAs)

    Returns:
        TSASelectionResult with selected TSA and fallbacks
    """
    exclude_set = set(exclude_urls) if exclude_urls else set()
    result = TSASelectionResult()

    # Get qualified TSAs from registry
    all_qualified = get_qualified_tsas_from_registry()

    # Filter out excluded URLs
    available = [tsa for tsa in all_qualified if tsa.service_url not in exclude_set]
    result.all_qualified_tsas = all_qualified

    if not available:
        # No qualified TSAs available from registry, use fallbacks
        logger.warning("No qualified TSAs available from EUTL, using fallbacks")
        return _select_from_fallbacks(exclude_set, result)

    # Try preferred country first
    if preferred_country:
        country_upper = preferred_country.upper()
        country_matches = [tsa for tsa in available if tsa.country == country_upper]
        if country_matches:
            selected = country_matches[0]
            result.selected_url = selected.service_url
            result.selected_name = selected.name
            result.selected_country = selected.country
            result.is_qualified = True
            result.selection_reason = f"Qualified TSA from preferred country {country_upper}"
            # Remaining as fallbacks
            result.fallback_urls = [
                tsa.service_url for tsa in available if tsa.service_url != selected.service_url
            ]
            logger.info(
                "Selected TSA '%s' (%s) by country preference",
                selected.name,
                selected.country,
            )
            return result

        logger.info(
            "No qualified TSA found for country '%s', selecting from all",
            preferred_country,
        )

    # No country preference or no match: pick first available qualified
    selected = available[0]
    result.selected_url = selected.service_url
    result.selected_name = selected.name
    result.selected_country = selected.country
    result.is_qualified = True
    result.selection_reason = "Best available qualified TSA from EUTL"
    result.fallback_urls = [tsa.service_url for tsa in available[1:]]

    logger.info(
        "Selected TSA '%s' (%s) as best available",
        selected.name,
        selected.country,
    )
    return result


def _select_from_fallbacks(
    exclude_set: set[str],
    result: TSASelectionResult,
) -> TSASelectionResult:
    """Select from well-known fallback TSAs when registry is empty.

    Args:
        exclude_set: URLs to exclude
        result: TSASelectionResult to populate

    Returns:
        Updated TSASelectionResult with fallback selection
    """
    available_fallbacks = [fb for fb in FALLBACK_QUALIFIED_TSAS if fb["url"] not in exclude_set]

    if not available_fallbacks:
        result.selection_reason = "No TSAs available (all excluded)"
        logger.error("No TSA URLs available after exclusions")
        return result

    selected = available_fallbacks[0]
    result.selected_url = selected["url"]
    result.selected_name = selected["name"]
    result.selected_country = selected["country"]
    result.is_qualified = False  # Fallbacks are not verified from EUTL
    result.selection_reason = "Fallback well-known TSA (EUTL not loaded)"
    result.fallback_urls = [fb["url"] for fb in available_fallbacks[1:]]

    logger.info(
        "Selected fallback TSA '%s' (%s)",
        selected["name"],
        selected["url"],
    )
    return result


def get_qualified_tsa_urls() -> list[str]:
    """Simple helper: get list of qualified TSA URLs.

    Convenience function for integration with signing pipeline.
    Returns qualified TSA URLs from EUTL registry first, then
    falls back to well-known qualified TSAs if EUTL is not loaded.

    Returns:
        List of TSA URLs, qualified first
    """
    # Try registry first
    qualified = get_qualified_tsas_from_registry()
    urls = [tsa.service_url for tsa in qualified if tsa.service_url]

    if urls:
        logger.debug("Returning %d qualified TSA URLs from EUTL", len(urls))
        return urls

    # Fallback to well-known qualified TSAs
    fallback_urls = [fb["url"] for fb in FALLBACK_QUALIFIED_TSAS]
    logger.info(
        "EUTL not loaded, returning %d fallback TSA URLs",
        len(fallback_urls),
    )
    return fallback_urls

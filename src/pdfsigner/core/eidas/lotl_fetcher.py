from __future__ import annotations

"""
lotl_fetcher.py - EU List of Trusted Lists (LOTL) fetcher and parser

Author: Homero Thompson del Lago del Terror

Fetches and parses the official EU List of Trusted Lists (LOTL) from the
European Commission, providing pointers to member state Trusted Service Lists.

Based on ETSI TS 119 612 V2.2.1 specification for Trust Service Status Lists.

Official EU LOTL: https://ec.europa.eu/tools/lotl/eu-lotl.xml
"""

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

# Use defusedxml to prevent XXE attacks (CWE-611)
import defusedxml.ElementTree as ET
import requests

from pdfsigner.core.eidas.lotl_cache import (
    EU_LOTL_URL,
    NAMESPACES,
    LOTLCache,
    LOTLData,
    TSLPointer,
)

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

logger = logging.getLogger(__name__)


class LOTLFetcher:
    """Fetch and parse EU List of Trusted Lists.

    The LOTL provides pointers to each EU member state's Trusted Service List,
    enabling automated discovery and validation of qualified trust service providers
    across the European Union.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        cache_ttl_hours: int = 24,
        timeout: int = 30,
    ):
        """Initialize LOTL fetcher.

        Args:
            cache_dir: Directory for caching LOTL data
            cache_ttl_hours: Cache validity period in hours (default: 24)
            timeout: HTTP request timeout in seconds
        """
        cache_dir = cache_dir or Path.home() / ".config" / "pdfsigner" / "eidas_cache"
        self._cache = LOTLCache(cache_dir=cache_dir, cache_ttl=timedelta(hours=cache_ttl_hours))
        self.timeout = timeout

    # Expose cache_dir for backward compatibility
    @property
    def cache_dir(self) -> Path:
        """Cache directory path."""
        return self._cache.cache_dir

    @property
    def cache_ttl(self) -> timedelta:
        """Cache time-to-live."""
        return self._cache.cache_ttl

    def fetch_lotl(self, force_refresh: bool = False) -> LOTLData:
        """Fetch EU LOTL, using cache if valid.

        Args:
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            LOTLData containing parsed LOTL information

        Raises:
            requests.RequestException: If fetch fails and no cache available
            ValueError: If LOTL parsing fails
        """
        # Check cache first
        if not force_refresh and self._cache.is_valid():
            logger.info("Using cached EU LOTL")
            return self._parse_lotl_xml(self._cache.read())

        # Fetch fresh data
        logger.info("Fetching EU LOTL from %s", EU_LOTL_URL)
        try:
            response = requests.get(
                EU_LOTL_URL,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "PDFSigner/1.1.0"},
            )
            response.raise_for_status()

            # Save to cache
            self._cache.write(response.content)

            return self._parse_lotl_xml(response.content)

        except requests.RequestException as e:
            logger.warning("Failed to fetch LOTL: %s", e)
            # Try cache as fallback
            if self._cache.exists():
                logger.info("Using stale cache as fallback")
                return self._parse_lotl_xml(self._cache.read())
            raise

    def _parse_lotl_xml(self, xml_data: bytes) -> LOTLData:
        """Parse ETSI TS 119 612 XML format.

        Args:
            xml_data: Raw XML data from LOTL

        Returns:
            Parsed LOTLData

        Raises:
            ValueError: If XML parsing fails or required fields are missing
        """
        try:
            root = ET.fromstring(xml_data)

            # Extract scheme information
            scheme_info = root.find(".//tsl:SchemeInformation", NAMESPACES)
            if scheme_info is None:
                raise ValueError("SchemeInformation not found in LOTL XML")

            # Version and sequence number
            version_elem = scheme_info.find("tsl:TSLVersionIdentifier", NAMESPACES)
            version = version_elem.text or "0" if version_elem is not None else "0"

            sequence_elem = scheme_info.find("tsl:TSLSequenceNumber", NAMESPACES)
            sequence_number = (
                int(sequence_elem.text) if sequence_elem is not None and sequence_elem.text else 0
            )

            # Dates
            issue_date_elem = scheme_info.find("tsl:ListIssueDateTime", NAMESPACES)
            issue_date = (
                self._parse_datetime(issue_date_elem.text)
                if issue_date_elem is not None and issue_date_elem.text
                else datetime.now(UTC)
            )

            next_update_elem = scheme_info.find("tsl:NextUpdate/tsl:dateTime", NAMESPACES)
            next_update = (
                self._parse_datetime(next_update_elem.text)
                if next_update_elem is not None and next_update_elem.text
                else datetime.now(UTC) + timedelta(days=7)
            )

            # Operator name
            operator_elem = scheme_info.find(
                ".//tsl:SchemeOperatorName/tsl:Name[@xml:lang='en']", NAMESPACES
            )
            operator_name = (
                (operator_elem.text or "EU Commission")
                if operator_elem is not None
                else "EU Commission"
            )

            # Territory
            territory_elem = scheme_info.find("tsl:SchemeTerritory", NAMESPACES)
            territory = (territory_elem.text or "EU") if territory_elem is not None else "EU"

            # Extract TSL pointers
            pointers = self._extract_tsl_pointers(root)

            lotl_data = LOTLData(
                version=version,
                sequence_number=sequence_number,
                issue_date=issue_date,
                next_update=next_update,
                tsl_pointers=pointers,
                operator_name=operator_name,
                territory=territory,
                signature_valid=False,  # Signature validation requires xmlsec
            )

            logger.info(
                "Parsed LOTL v%s seq %d with %d TSL pointers",
                version,
                sequence_number,
                len(pointers),
            )

            return lotl_data

        except ET.ParseError as e:
            raise ValueError(f"Failed to parse LOTL XML: {e}") from e

    def _extract_tsl_pointers(self, root: Element) -> list[TSLPointer]:
        """Extract TSL pointers from LOTL XML.

        Args:
            root: Root XML element

        Returns:
            List of TSLPointer objects for each member state
        """
        pointers = []

        # Find all OtherTSLPointers
        pointer_elements = root.findall(".//tsl:OtherTSLPointer", NAMESPACES)

        for pointer_elem in pointer_elements:
            try:
                # Extract TSL location (URL)
                location_elem = pointer_elem.find("tsl:TSLLocation", NAMESPACES)
                if location_elem is None or not location_elem.text:
                    continue
                tsl_url = location_elem.text.strip()

                # Extract territory (country code)
                territory_elem = pointer_elem.find(".//tsl:SchemeTerritory", NAMESPACES)
                country_code = (
                    territory_elem.text.strip()
                    if territory_elem is not None and territory_elem.text
                    else "??"
                )

                # Extract scheme operator name (country name)
                name_elem = pointer_elem.find(
                    ".//tsl:SchemeOperatorName/tsl:Name[@xml:lang='en']", NAMESPACES
                )
                country_name = (
                    name_elem.text.strip()
                    if name_elem is not None and name_elem.text
                    else country_code
                )

                # Extract MIME type
                mime_elem = pointer_elem.find(".//tsl:MimeType", NAMESPACES)
                mime_type = (
                    mime_elem.text.strip()
                    if mime_elem is not None and mime_elem.text
                    else "application/vnd.etsi.tsl+xml"
                )

                # Create pointer
                pointer = TSLPointer(
                    country_code=country_code,
                    country_name=country_name,
                    tsl_url=tsl_url,
                    mime_type=mime_type,
                )

                pointers.append(pointer)
                logger.debug(
                    "Found TSL pointer for %s (%s): %s", country_name, country_code, tsl_url
                )

            except Exception as e:
                logger.warning("Failed to parse TSL pointer: %s", e)
                continue

        return pointers

    def _parse_datetime(self, dt_string: str) -> datetime:
        """Parse ISO 8601 datetime string.

        Args:
            dt_string: ISO 8601 datetime string

        Returns:
            Parsed datetime object
        """
        # Handle various ISO 8601 formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
        ]:
            try:
                return datetime.strptime(dt_string, fmt)
            except ValueError:
                continue

        # Fallback: try fromisoformat
        try:
            return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        except ValueError:
            logger.warning("Failed to parse datetime: %s, using current time", dt_string)
            return datetime.now(UTC)

    def get_country_tsl_url(self, country_code: str) -> str | None:
        """Get TSL URL for a specific country.

        Args:
            country_code: ISO 3166-1 alpha-2 country code (e.g., "DE", "FR")

        Returns:
            TSL URL if found, None otherwise
        """
        try:
            lotl = self.fetch_lotl()
            country_code_upper = country_code.upper()

            for pointer in lotl.tsl_pointers:
                if pointer.country_code == country_code_upper:
                    return pointer.tsl_url

            logger.warning("No TSL found for country: %s", country_code)
            return None

        except Exception as e:
            logger.error("Failed to get TSL URL for %s: %s", country_code, e)
            return None

    def get_all_tsl_urls(self) -> dict[str, str]:
        """Get all TSL URLs indexed by country code.

        Returns:
            Dictionary mapping country codes to TSL URLs
        """
        try:
            lotl = self.fetch_lotl()
            return {pointer.country_code: pointer.tsl_url for pointer in lotl.tsl_pointers}
        except Exception as e:
            logger.error("Failed to get TSL URLs: %s", e)
            return {}


# Singleton instance
_lotl_fetcher: LOTLFetcher | None = None


def get_lotl_fetcher() -> LOTLFetcher:
    """Get or create singleton LOTLFetcher instance.

    Returns:
        LOTLFetcher singleton
    """
    global _lotl_fetcher
    if _lotl_fetcher is None:
        _lotl_fetcher = LOTLFetcher()
    return _lotl_fetcher

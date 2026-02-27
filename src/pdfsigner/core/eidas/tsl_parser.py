from __future__ import annotations

"""
tsl_parser.py - ETSI TS 119 612 Trusted Service List parser

Author: Homero Thompson del Lago del Terror

Parses individual country Trusted Service Lists (TSL) to extract information
about qualified Trust Service Providers (TSPs) and their services.

Based on ETSI TS 119 612 V2.2.1 specification for Trust Service Status Lists.
"""

import base64
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

# Use defusedxml to prevent XXE attacks (CWE-611)
import defusedxml.ElementTree as ET
from loguru import logger

# Re-export types for backward compatibility
from pdfsigner.core.eidas.tsl_types import (
    ServiceInfo,
    ServiceStatus,
    ServiceType,
    TSPInfo,
)

# XML namespaces used in ETSI TS 119 612
NAMESPACES = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xml": "http://www.w3.org/XML/1998/namespace",
}


class TSLParser:
    """Parse country Trusted Service List XML per ETSI TS 119 612.

    Extracts Trust Service Provider information including:
    - Provider details (name, address, contact)
    - Service information (type, status, certificates)
    - Service supply points (OCSP URLs, CRL URLs, etc.)
    """

    def __init__(self):
        """Initialize TSL parser."""
        pass

    def parse(self, xml_data: bytes) -> list[TSPInfo]:
        """Parse TSL XML and extract TSP information.

        Args:
            xml_data: Raw XML data from country TSL

        Returns:
            List of TSPInfo objects

        Raises:
            ValueError: If XML parsing fails
        """
        try:
            root = ET.fromstring(xml_data)

            # Extract country code from scheme territory
            country_code = self._extract_country_code(root)

            # Find all Trust Service Providers
            tsp_elements = root.findall(
                ".//tsl:TrustServiceProvider",
                NAMESPACES,
            )

            tsps = []
            for tsp_elem in tsp_elements:
                try:
                    tsp = self._parse_tsp(tsp_elem, country_code)
                    if tsp:
                        tsps.append(tsp)
                except Exception as e:
                    logger.warning("Failed to parse TSP: %s", e)
                    continue

            logger.info("Parsed %d TSPs from country TSL (%s)", len(tsps), country_code)
            return tsps

        except ET.ParseError as e:
            raise ValueError(f"Failed to parse TSL XML: {e}") from e

    def _extract_country_code(self, root: Element) -> str:
        """Extract country code from TSL.

        Args:
            root: Root XML element

        Returns:
            ISO 3166-1 alpha-2 country code
        """
        territory_elem = root.find(
            ".//tsl:SchemeInformation/tsl:SchemeTerritory",
            NAMESPACES,
        )
        if territory_elem is not None and territory_elem.text:
            return territory_elem.text.strip()
        return "??"

    def _parse_tsp(self, tsp_elem: Element, country_code: str) -> TSPInfo | None:
        """Parse a single Trust Service Provider element.

        Args:
            tsp_elem: TSP XML element
            country_code: Country code for this TSP

        Returns:
            TSPInfo object or None if parsing fails
        """
        # Extract TSP information
        info_elem = tsp_elem.find("tsl:TSPInformation", NAMESPACES)
        if info_elem is None:
            return None

        # TSP name (prefer English, fallback to first available)
        name_elem = info_elem.find(
            ".//tsl:TSPName/tsl:Name[@xml:lang='en']",
            NAMESPACES,
        )
        if name_elem is None:
            name_elem = info_elem.find(".//tsl:TSPName/tsl:Name", NAMESPACES)

        if name_elem is None or not name_elem.text:
            logger.debug("TSP without name, skipping")
            return None

        name = name_elem.text.strip()

        # Trade name (optional)
        trade_name_elem = info_elem.find(
            ".//tsl:TSPTradeName/tsl:Name[@xml:lang='en']",
            NAMESPACES,
        )
        if trade_name_elem is None:
            trade_name_elem = info_elem.find(".//tsl:TSPTradeName/tsl:Name", NAMESPACES)
        trade_name = (
            trade_name_elem.text.strip()
            if trade_name_elem is not None and trade_name_elem.text
            else None
        )

        # Postal address (optional)
        postal_elem = info_elem.find(".//tsl:PostalAddress", NAMESPACES)
        postal_address = None
        if postal_elem is not None:
            address_parts = []
            for child in postal_elem:
                if child.text:
                    address_parts.append(child.text.strip())
            postal_address = ", ".join(address_parts) if address_parts else None

        # Electronic address (optional)
        email_elem = info_elem.find(".//tsl:ElectronicAddress/tsl:URI", NAMESPACES)
        electronic_address = (
            email_elem.text.strip() if email_elem is not None and email_elem.text else None
        )

        # Parse services
        services = self._parse_services(tsp_elem, name)

        return TSPInfo(
            name=name,
            trade_name=trade_name,
            country_code=country_code,
            postal_address=postal_address,
            electronic_address=electronic_address,
            services=services,
        )

    def _parse_services(self, tsp_elem: Element, tsp_name: str) -> list[ServiceInfo]:
        """Parse services for a TSP.

        Args:
            tsp_elem: TSP XML element
            tsp_name: Name of the TSP

        Returns:
            List of ServiceInfo objects
        """
        services = []

        service_elements = tsp_elem.findall(
            ".//tsl:TSPService",
            NAMESPACES,
        )

        for service_elem in service_elements:
            try:
                service = self._parse_service(service_elem, tsp_name)
                if service:
                    services.append(service)
            except Exception as e:
                logger.warning("Failed to parse service: %s", e)
                continue

        return services

    def _parse_service(self, service_elem: Element, tsp_name: str) -> ServiceInfo | None:
        """Parse a single service element.

        Args:
            service_elem: Service XML element
            tsp_name: Name of the parent TSP

        Returns:
            ServiceInfo object or None if parsing fails
        """
        info_elem = service_elem.find("tsl:ServiceInformation", NAMESPACES)
        if info_elem is None:
            return None

        # Service type
        type_elem = info_elem.find("tsl:ServiceTypeIdentifier", NAMESPACES)
        if type_elem is None or not type_elem.text:
            return None
        service_type_uri = type_elem.text.strip()
        service_type = ServiceType.from_uri(service_type_uri)

        # Service name
        name_elem = info_elem.find(
            ".//tsl:ServiceName/tsl:Name[@xml:lang='en']",
            NAMESPACES,
        )
        if name_elem is None:
            name_elem = info_elem.find(".//tsl:ServiceName/tsl:Name", NAMESPACES)

        name = (
            name_elem.text.strip()
            if name_elem is not None and name_elem.text
            else "Unnamed Service"
        )

        # Service status
        status_elem = info_elem.find(
            "tsl:ServiceStatus",
            NAMESPACES,
        )
        if status_elem is None or not status_elem.text:
            logger.debug("Service without status, skipping: %s", name)
            return None

        status = ServiceStatus.from_uri(status_elem.text.strip())

        # Status start date
        date_elem = info_elem.find(
            "tsl:StatusStartingTime",
            NAMESPACES,
        )
        status_start_date = (
            self._parse_datetime(date_elem.text)
            if date_elem is not None and date_elem.text
            else datetime.now(UTC)
        )

        # Service supply points (OCSP URLs, CRL URLs, etc.)
        supply_points = self._extract_service_supply_points(info_elem)

        # Digital identity (certificate)
        certificate_der = self._extract_certificate(info_elem)

        return ServiceInfo(
            name=name,
            service_type=service_type,
            service_type_uri=service_type_uri,
            status=status,
            status_start_date=status_start_date,
            certificate_der=certificate_der,
            service_supply_points=supply_points,
            tsp_name=tsp_name,
        )

    def _extract_service_supply_points(self, info_elem: Element) -> list[str]:
        """Extract service supply points (URLs).

        Args:
            info_elem: ServiceInformation XML element

        Returns:
            List of supply point URLs
        """
        supply_points = []

        supply_elem = info_elem.find(
            "tsl:ServiceSupplyPoints",
            NAMESPACES,
        )
        if supply_elem is not None:
            uri_elements = supply_elem.findall("tsl:ServiceSupplyPoint", NAMESPACES)
            for uri_elem in uri_elements:
                if uri_elem.text:
                    supply_points.append(uri_elem.text.strip())

        return supply_points

    def _extract_certificate(self, info_elem: Element) -> bytes | None:
        """Extract DER certificate from service digital identity.

        Args:
            info_elem: ServiceInformation XML element

        Returns:
            DER-encoded certificate bytes or None
        """
        try:
            # Find X509Certificate in ServiceDigitalIdentity
            cert_elem = info_elem.find(
                ".//tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate",
                NAMESPACES,
            )

            if cert_elem is not None and cert_elem.text:
                # Certificate is base64-encoded DER
                cert_b64 = cert_elem.text.strip().replace("\n", "").replace(" ", "")
                return base64.b64decode(cert_b64)

        except Exception as e:
            logger.debug("Failed to extract certificate: %s", e)

        return None

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

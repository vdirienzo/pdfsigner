"""
tsl_types.py - Type definitions for ETSI TS 119 612 Trusted Service Lists

Contains enums and dataclasses used by the TSL parser and other eIDAS modules.

Types:
- ServiceStatus: TSP service status values
- ServiceType: TSP service types
- ServiceInfo: Trust service information
- TSPInfo: Trust Service Provider information
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from loguru import logger


class ServiceStatus(str, Enum):
    """TSP service status values per ETSI TS 119 612."""

    GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
    DEPRECATED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"
    RECOGNIZED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
    REVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/revoked"
    SUSPENDED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/suspended"

    @classmethod
    def from_uri(cls, uri: str) -> ServiceStatus:
        """Parse service status from URI, defaulting to WITHDRAWN if unknown."""
        try:
            return cls(uri)
        except ValueError:
            logger.warning("Unknown service status URI: %s, defaulting to WITHDRAWN", uri)
            return cls.WITHDRAWN


class ServiceType(str, Enum):
    """TSP service types per ETSI TS 119 612."""

    # Qualified Certificate services
    CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"  # Qualified CA
    CA_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"  # Public Key Certificate CA

    # Timestamp services
    TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"  # Qualified TSA
    TSA_TSS_QC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"  # TSA with QC
    TSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA"  # Generic TSA

    # Certificate status services
    OCSP_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC"  # Qualified OCSP
    OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"  # Generic OCSP
    CRL_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC"  # Qualified CRL
    CRL = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL"  # Generic CRL

    # Electronic signature/seal validation
    VALIDATION_QC = "http://uri.etsi.org/TrstSvc/Svctype/AdesValidation/QC"  # Qualified validation

    @classmethod
    def from_uri(cls, uri: str) -> ServiceType | None:
        """Parse service type from URI, returning None if unknown."""
        try:
            return cls(uri)
        except ValueError:
            logger.debug("Unknown service type URI: %s", uri)
            return None


@dataclass
class ServiceInfo:
    """Information about a trust service."""

    name: str
    service_type: ServiceType | None
    service_type_uri: str
    status: ServiceStatus
    status_start_date: datetime
    certificate_der: bytes | None = None
    service_supply_points: list[str] = field(default_factory=list)
    tsp_name: str = ""
    extensions: dict[str, str] = field(default_factory=dict)

    def is_qualified(self) -> bool:
        """Check if service is qualified (has granted status)."""
        return self.status == ServiceStatus.GRANTED

    def is_ca(self) -> bool:
        """Check if service is a Certificate Authority."""
        if self.service_type is None:
            return False
        return self.service_type in (ServiceType.CA_QC, ServiceType.CA_PKC)

    def is_tsa(self) -> bool:
        """Check if service is a Timestamp Authority."""
        if self.service_type is None:
            return False
        return self.service_type in (ServiceType.TSA_QTST, ServiceType.TSA_TSS_QC, ServiceType.TSA)


@dataclass
class TSPInfo:
    """Information about a Trust Service Provider."""

    name: str
    trade_name: str | None
    country_code: str
    postal_address: str | None = None
    electronic_address: str | None = None
    services: list[ServiceInfo] = field(default_factory=list)

    def get_qualified_services(self) -> list[ServiceInfo]:
        """Get services with granted (qualified) status.

        Returns:
            List of qualified ServiceInfo objects
        """
        return [s for s in self.services if s.is_qualified()]

    def get_ca_services(self) -> list[ServiceInfo]:
        """Get Certificate Authority services.

        Returns:
            List of CA ServiceInfo objects
        """
        return [s for s in self.services if s.is_ca()]

    def get_tsa_services(self) -> list[ServiceInfo]:
        """Get Timestamp Authority services.

        Returns:
            List of TSA ServiceInfo objects
        """
        return [s for s in self.services if s.is_tsa()]


__all__ = [
    "ServiceInfo",
    "ServiceStatus",
    "ServiceType",
    "TSPInfo",
]

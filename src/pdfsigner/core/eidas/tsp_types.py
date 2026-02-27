"""tsp_types.py - Type definitions for EU Trust Service Providers

Type definitions for the EU Trusted List (TSL) of qualified Trust Service
Providers (TSPs) as mandated by eIDAS Regulation (EU) No 910/2014 Article 22.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class QualificationStatus(str, Enum):
    """Trust Service Provider qualification status per eIDAS."""

    QUALIFIED = "qualified"
    NOT_QUALIFIED = "not_qualified"
    UNKNOWN = "unknown"
    WITHDRAWN = "withdrawn"


class ServiceType(str, Enum):
    """Types of trust services per eIDAS."""

    CA = "ca"  # Certificate Authority
    TSA = "tsa"  # Time Stamp Authority
    OCSP = "ocsp"  # OCSP Responder
    CRL = "crl"  # CRL Issuer


@dataclass
class TSPInfo:
    """Trust Service Provider information from EU Trusted List."""

    name: str
    country: str  # ISO 3166-1 alpha-2
    service_type: ServiceType
    status: QualificationStatus
    service_url: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    trust_anchor: str | None = None  # Certificate fingerprint
    certificate_der: bytes | None = None  # DER-encoded certificate


@dataclass
class TrustedListInfo:
    """Metadata about the loaded EU Trusted List."""

    version: str
    issue_date: datetime
    next_update: datetime
    total_tsps: int
    countries: list[str] = field(default_factory=list)

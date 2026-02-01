"""
tsp_registry.py - EU Trusted List of Trust Service Providers

Author: Homero Thompson del Lago del Terror

Manages the EU Trusted List (TSL) of qualified Trust Service Providers (TSPs)
as mandated by eIDAS Regulation (EU) No 910/2014 Article 22.

Official EU Trust Service Status List: https://ec.europa.eu/tools/lotl/eu-lotl.xml

Key features:
- Load and parse EU Trusted List (TSL) in XML format
- Query TSPs by country, service type, or URL
- Cache TSL data to minimize HTTP requests
- Offline mode for air-gapped environments
- Qualification status checks for certificates
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


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


@dataclass
class TrustedListInfo:
    """Metadata about the loaded EU Trusted List."""

    version: str
    issue_date: datetime
    next_update: datetime
    total_tsps: int
    countries: list[str] = field(default_factory=list)


class EUTSPRegistry:
    """EU Trusted List of Trust Service Providers (TSPs).

    Based on eIDAS Regulation (EU) No 910/2014 Article 22.
    Uses EU Trust Service Status List (TSL) format.

    For MVP, uses mock data. Production implementation would parse
    the actual EU TSL XML from https://ec.europa.eu/tools/lotl/eu-lotl.xml
    """

    def __init__(self, cache_dir: Path | None = None):
        """Initialize TSP registry with optional cache directory."""
        self._cache_dir = cache_dir or Path.home() / ".pdfsigner" / "eidas_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        self._tsps: dict[str, TSPInfo] = {}
        self._list_info: TrustedListInfo | None = None

        # Cache settings
        self._cache_file = self._cache_dir / "tsl_cache.json"
        self._cache_max_age_days = 7  # eIDAS requires TSL updates weekly

    def load_trusted_list(self, offline: bool = False) -> bool:
        """Load EU Trusted List from cache or mock data.

        Args:
            offline: If True, only use cached data (no network requests)

        Returns:
            True if trusted list loaded successfully, False otherwise
        """
        # Try loading from cache first
        if self._load_from_cache():
            logger.info("Loaded EU Trusted List from cache")
            return True

        if offline:
            logger.warning("Offline mode: cannot fetch TSL, using mock data")
            return self._load_mock_data()

        # For MVP: use mock data instead of fetching from EU
        # Production would implement: return self._fetch_from_eu()
        logger.info("Loading mock EU Trusted List data (MVP mode)")
        return self._load_mock_data()

    def is_qualified_tsp(self, service_url: str) -> bool:
        """Check if a TSP is on the EU Trusted List with qualified status.

        Args:
            service_url: URL of the trust service

        Returns:
            True if TSP is qualified, False otherwise
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        normalized_url = self._normalize_url(service_url)
        tsp = self._tsps.get(normalized_url)

        if tsp is None:
            return False

        return tsp.status == QualificationStatus.QUALIFIED

    def get_tsp_info(self, service_url: str) -> TSPInfo | None:
        """Get detailed information about a TSP.

        Args:
            service_url: URL of the trust service

        Returns:
            TSPInfo if found, None otherwise
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        normalized_url = self._normalize_url(service_url)
        return self._tsps.get(normalized_url)

    def get_tsps_by_country(self, country_code: str) -> list[TSPInfo]:
        """Get all TSPs for a specific country.

        Args:
            country_code: ISO 3166-1 alpha-2 country code (e.g., "DE", "FR")

        Returns:
            List of TSPInfo for the specified country
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return [tsp for tsp in self._tsps.values() if tsp.country == country_code.upper()]

    def get_tsps_by_type(self, service_type: ServiceType) -> list[TSPInfo]:
        """Get all TSPs of a specific type (CA, TSA, etc.).

        Args:
            service_type: Type of trust service

        Returns:
            List of TSPInfo for the specified service type
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return [tsp for tsp in self._tsps.values() if tsp.service_type == service_type]

    def update_trusted_list(self) -> bool:
        """Force update of trusted list from EU source.

        Returns:
            True if update successful, False otherwise
        """
        # Clear cache
        if self._cache_file.exists():
            self._cache_file.unlink()

        # Reload (will fetch fresh data)
        return self.load_trusted_list(offline=False)

    def get_list_info(self) -> TrustedListInfo | None:
        """Get metadata about the loaded trusted list.

        Returns:
            TrustedListInfo if list is loaded, None otherwise
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return self._list_info

    def check_certificate_issuer(self, issuer_dn: str) -> QualificationStatus:
        """Check if certificate issuer is a qualified TSP.

        Args:
            issuer_dn: X.509 Distinguished Name of certificate issuer

        Returns:
            QualificationStatus of the issuer
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        # Common words to ignore in matching
        ignore_words = {"ca", "gmbh", "s.p.a.", "ltd", "inc", "llc", "ag", "sa", "qualified"}

        # Search for issuer in TSP names
        issuer_lower = issuer_dn.lower()
        for tsp in self._tsps.values():
            if tsp.service_type == ServiceType.CA:
                tsp_name_lower = tsp.name.lower()

                # Try exact match first
                if tsp_name_lower in issuer_lower:
                    return tsp.status

                # Try matching significant words
                tsp_words = [w for w in tsp_name_lower.split() if w not in ignore_words]

                # Require at least half of significant words to match (minimum 1)
                if len(tsp_words) > 0:
                    matches = sum(1 for word in tsp_words if word in issuer_lower)
                    required_matches = max(1, len(tsp_words) // 2)
                    if matches >= required_matches:
                        return tsp.status

        return QualificationStatus.UNKNOWN

    # --- Private methods ---

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent lookups.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL string
        """
        parsed = urlparse(url.lower())
        # Use domain + path for matching
        normalized = f"{parsed.netloc}{parsed.path}".rstrip("/")
        return normalized

    def _load_from_cache(self) -> bool:
        """Load TSL from cache file if not expired.

        Returns:
            True if loaded successfully, False otherwise
        """
        if not self._cache_file.exists():
            return False

        try:
            # Check cache age
            cache_age = datetime.now() - datetime.fromtimestamp(self._cache_file.stat().st_mtime)
            if cache_age > timedelta(days=self._cache_max_age_days):
                logger.info(f"TSL cache expired (age: {cache_age.days} days)")
                return False

            # Load cache
            with open(self._cache_file) as f:
                cache_data = json.load(f)

            # Restore TSPs
            self._tsps = {}
            for url, tsp_dict in cache_data.get("tsps", {}).items():
                # Convert string dates back to datetime
                if tsp_dict.get("valid_from"):
                    tsp_dict["valid_from"] = datetime.fromisoformat(tsp_dict["valid_from"])
                if tsp_dict.get("valid_until"):
                    tsp_dict["valid_until"] = datetime.fromisoformat(tsp_dict["valid_until"])

                # Convert enums
                tsp_dict["service_type"] = ServiceType(tsp_dict["service_type"])
                tsp_dict["status"] = QualificationStatus(tsp_dict["status"])

                self._tsps[url] = TSPInfo(**tsp_dict)

            # Restore list info
            list_info_dict = cache_data.get("list_info")
            if list_info_dict:
                list_info_dict["issue_date"] = datetime.fromisoformat(list_info_dict["issue_date"])
                list_info_dict["next_update"] = datetime.fromisoformat(
                    list_info_dict["next_update"]
                )
                self._list_info = TrustedListInfo(**list_info_dict)

            logger.info(f"Loaded {len(self._tsps)} TSPs from cache")
            return True

        except Exception as e:
            logger.warning(f"Failed to load TSL cache: {e}")
            return False

    def _save_to_cache(self) -> bool:
        """Save current TSL to cache file.

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            cache_data: dict[str, dict[str, dict[str, Any]] | dict[str, Any] | None] = {
                "tsps": {},
                "list_info": None,
            }

            # Serialize TSPs
            tsps_dict: dict[str, dict[str, Any]] = {}
            for url, tsp in self._tsps.items():
                tsp_dict = asdict(tsp)
                # Convert datetime to ISO format strings
                if tsp_dict.get("valid_from"):
                    tsp_dict["valid_from"] = tsp_dict["valid_from"].isoformat()
                if tsp_dict.get("valid_until"):
                    tsp_dict["valid_until"] = tsp_dict["valid_until"].isoformat()
                # Enums to strings
                tsp_dict["service_type"] = tsp_dict["service_type"].value
                tsp_dict["status"] = tsp_dict["status"].value

                tsps_dict[url] = tsp_dict

            cache_data["tsps"] = tsps_dict

            # Serialize list info
            if self._list_info:
                list_info_dict = asdict(self._list_info)
                list_info_dict["issue_date"] = list_info_dict["issue_date"].isoformat()
                list_info_dict["next_update"] = list_info_dict["next_update"].isoformat()
                cache_data["list_info"] = list_info_dict

            # Write to cache file
            with open(self._cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            logger.info(f"Saved {len(self._tsps)} TSPs to cache")
            return True

        except Exception as e:
            logger.error(f"Failed to save TSL cache: {e}")
            return False

    def _load_mock_data(self) -> bool:
        """Load mock TSP data for MVP/testing.

        Returns:
            True (always succeeds with mock data)
        """
        # Mock TSP data for common European providers
        mock_tsps = [
            # Qualified TSPs
            TSPInfo(
                name="DigiCert Qualified CA",
                country="US",
                service_type=ServiceType.CA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://www.digicert.com",
                valid_from=datetime(2020, 1, 1),
                valid_until=datetime(2030, 12, 31),
                trust_anchor="sha256:1234567890abcdef",
            ),
            TSPInfo(
                name="Bundesdruckerei GmbH",
                country="DE",
                service_type=ServiceType.CA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://www.bundesdruckerei.de",
                valid_from=datetime(2019, 6, 15),
                valid_until=datetime(2029, 6, 15),
                trust_anchor="sha256:abcdef1234567890",
            ),
            TSPInfo(
                name="Actalis S.p.A.",
                country="IT",
                service_type=ServiceType.CA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://www.actalis.it",
                valid_from=datetime(2018, 3, 1),
                valid_until=datetime(2028, 3, 1),
            ),
            TSPInfo(
                name="ACCV - Agencia de Tecnología y Certificación Electrónica",
                country="ES",
                service_type=ServiceType.CA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://www.accv.es",
                valid_from=datetime(2019, 1, 10),
                valid_until=datetime(2029, 1, 10),
            ),
            TSPInfo(
                name="ChamberSign France",
                country="FR",
                service_type=ServiceType.CA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://www.chambersign.fr",
                valid_from=datetime(2017, 9, 1),
                valid_until=datetime(2027, 9, 1),
            ),
            # Qualified TSA
            TSPInfo(
                name="Bundesdruckerei TSA",
                country="DE",
                service_type=ServiceType.TSA,
                status=QualificationStatus.QUALIFIED,
                service_url="https://tsp.bundesdruckerei.de/tsa",
                valid_from=datetime(2019, 6, 15),
                valid_until=datetime(2029, 6, 15),
            ),
            TSPInfo(
                name="DigiCert Timestamp Authority",
                country="US",
                service_type=ServiceType.TSA,
                status=QualificationStatus.QUALIFIED,
                service_url="http://timestamp.digicert.com",
                valid_from=datetime(2020, 1, 1),
                valid_until=datetime(2030, 12, 31),
            ),
            # Non-qualified TSPs
            TSPInfo(
                name="FreeTSA",
                country="EU",
                service_type=ServiceType.TSA,
                status=QualificationStatus.NOT_QUALIFIED,
                service_url="https://freetsa.org",
                valid_from=datetime(2015, 1, 1),
            ),
            TSPInfo(
                name="Let's Encrypt",
                country="US",
                service_type=ServiceType.CA,
                status=QualificationStatus.NOT_QUALIFIED,
                service_url="https://letsencrypt.org",
                valid_from=datetime(2016, 4, 12),
            ),
        ]

        # Store normalized
        self._tsps = {}
        for tsp in mock_tsps:
            normalized_url = self._normalize_url(tsp.service_url)
            self._tsps[normalized_url] = tsp

        # Create list info
        self._list_info = TrustedListInfo(
            version="5.5.1",
            issue_date=datetime.now(),
            next_update=datetime.now() + timedelta(days=7),
            total_tsps=len(mock_tsps),
            countries=sorted(set(tsp.country for tsp in mock_tsps)),
        )

        # Save to cache
        self._save_to_cache()

        logger.info(f"Loaded {len(self._tsps)} mock TSPs")
        return True


# --- Singleton access ---

_registry: EUTSPRegistry | None = None


def get_tsp_registry() -> EUTSPRegistry:
    """Get or create the singleton TSP registry instance.

    Returns:
        EUTSPRegistry singleton instance
    """
    global _registry
    if _registry is None:
        _registry = EUTSPRegistry()
        _registry.load_trusted_list(offline=True)
    return _registry

"""tsp_registry.py - EU Trusted List of Trust Service Providers (eIDAS Art. 22)

Manages the EU Trusted List (TSL) of qualified TSPs with cache, offline mode,
and certificate qualification checks.
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from pdfsigner.core.eidas.tsp_storage import TSPStorage
from pdfsigner.core.eidas.tsp_types import (
    QualificationStatus,
    ServiceType,
    TrustedListInfo,
    TSPInfo,
)

logger = logging.getLogger(__name__)


class EUTSPRegistry:
    """EU Trusted List of Trust Service Providers (TSPs).

    Based on eIDAS Regulation (EU) No 910/2014 Article 22.
    Production implementation that fetches and parses real EU TSL data.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        offline_mode: bool = False,
        use_mock_data: bool = False,
        territories: list[str] | None = None,
        progress_callback=None,
    ):
        self._cache_dir = cache_dir or Path.home() / ".pdfsigner" / "eidas_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        self._tsps: dict[str, TSPInfo] = {}  # URL -> TSPInfo
        self._cert_to_tsp: dict[str, TSPInfo] = {}  # cert fingerprint -> TSPInfo
        self._list_info: TrustedListInfo | None = None

        # Settings
        self._offline_mode = offline_mode
        self._use_mock_data = use_mock_data
        self._territories = territories
        self._progress_callback = progress_callback
        self._cache_file = self._cache_dir / "tsl_cache.json"
        self._storage = TSPStorage(self._cache_file)
        self._pyhanko_trust_manager = None  # Set by _try_pyhanko_eutl if available

    def _try_pyhanko_eutl(self) -> bool:
        """Try to load TSP data via pyHanko's EUTL (with XML signature validation).

        Falls back to custom parser if pyHanko EUTL is not available.

        Returns:
            True if loaded successfully
        """
        try:
            from pdfsigner.core.eidas.eutl_adapter import get_eutl_adapter

            adapter = get_eutl_adapter()
            if not adapter.is_available:
                logger.info("pyHanko EUTL not available, using custom parser")
                return False

            if not adapter.is_initialized:
                success = adapter.initialize_sync()
                if not success:
                    logger.warning("pyHanko EUTL initialization failed, using custom parser")
                    return False

            # pyHanko EUTL loaded with XML signature validation
            logger.info("Using pyHanko EUTL (with XML signature validation)")
            self._pyhanko_trust_manager = adapter.trust_manager
            return True

        except Exception as e:
            logger.debug("pyHanko EUTL not available: %s", e)
            return False

    def load_trusted_list(self, offline: bool = False) -> bool:
        """Load EU Trusted List from real EU data or cache.

        Args:
            offline: If True, only use cached data (no network requests)

        Returns:
            True if trusted list loaded successfully, False otherwise
        """
        # Try pyHanko EUTL first (with XML signature validation)
        if not self._use_mock_data and not offline and not self._offline_mode:
            if self._try_pyhanko_eutl():
                return True

        # Use mock data if requested (for testing)
        if self._use_mock_data:
            logger.info("Loading mock EU Trusted List data (testing mode)")
            return self._load_mock_data()

        # Try loading from cache first
        cache_result = self._storage.load_from_cache()
        if cache_result is not None:
            self._tsps, self._cert_to_tsp, self._list_info = cache_result
            logger.info("Loaded EU Trusted List from cache")
            return True

        # Check if offline mode
        if offline or self._offline_mode:
            logger.warning("Offline mode: using mock data as fallback")
            return self._load_mock_data()

        # Fetch from EU
        try:
            return self._fetch_from_eu()
        except Exception as e:
            logger.error("Failed to fetch EU TSL: %s", e)
            # Fallback to mock data
            logger.warning("Falling back to mock data")
            return self._load_mock_data()

    def _fetch_from_eu(self) -> bool:
        """Fetch TSL data from real EU sources.

        Returns:
            True if fetch successful
        """
        from pdfsigner.core.eidas.tsp_fetcher import fetch_from_eu

        result = fetch_from_eu(
            territories=self._territories,
            progress_callback=self._progress_callback,
            normalize_url=self._normalize_url,
            storage=self._storage,
        )
        if result is None:
            return False

        self._tsps, self._cert_to_tsp, self._list_info = result
        return True

    def find_tsp_by_certificate(self, cert_der: bytes) -> TSPInfo | None:
        """Find TSP that issued a certificate.

        Args:
            cert_der: DER-encoded certificate to search for

        Returns:
            TSPInfo if found, None otherwise
        """
        if not self._tsps:
            self.load_trusted_list(offline=True)

        # Try exact match first
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        if fingerprint in self._cert_to_tsp:
            return self._cert_to_tsp[fingerprint]

        # Try matching by issuer DN
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            issuer_dn = cert.issuer.rfc4514_string()
            status = self.check_certificate_issuer(issuer_dn)

            if status == QualificationStatus.QUALIFIED:
                # Find any qualified TSP matching the issuer
                for tsp in self._tsps.values():
                    if tsp.status == QualificationStatus.QUALIFIED:
                        if self._matches_issuer(tsp.name, issuer_dn):
                            return tsp

        except Exception as e:
            logger.debug("Failed to match certificate by issuer: %s", e)

        return None

    def _matches_issuer(self, tsp_name: str, issuer_dn: str) -> bool:
        """Check if TSP name matches issuer DN via substring match."""
        tsp_name_lower = tsp_name.lower()
        issuer_dn_lower = issuer_dn.lower()
        return tsp_name_lower in issuer_dn_lower or issuer_dn_lower in tsp_name_lower

    def is_qualified_tsp(self, service_url: str) -> bool:
        """Check if a TSP is on the EU Trusted List with qualified status."""
        if not self._tsps:
            self.load_trusted_list(offline=True)

        normalized_url = self._normalize_url(service_url)
        tsp = self._tsps.get(normalized_url)

        if tsp is None:
            return False

        return tsp.status == QualificationStatus.QUALIFIED

    def get_tsp_info(self, service_url: str) -> TSPInfo | None:
        """Get detailed information about a TSP by its service URL."""
        if not self._tsps:
            self.load_trusted_list(offline=True)

        normalized_url = self._normalize_url(service_url)
        return self._tsps.get(normalized_url)

    def get_tsps_by_country(self, country_code: str) -> list[TSPInfo]:
        """Get all TSPs for a specific country (ISO 3166-1 alpha-2)."""
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return [tsp for tsp in self._tsps.values() if tsp.country == country_code.upper()]

    def get_tsps_by_type(self, service_type: ServiceType) -> list[TSPInfo]:
        """Get all TSPs of a specific type (CA, TSA, OCSP, CRL)."""
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return [tsp for tsp in self._tsps.values() if tsp.service_type == service_type]

    def update_trusted_list(self) -> bool:
        """Force update of trusted list from EU source.

        Returns:
            True if update successful, False otherwise
        """
        # Clear cache
        self._storage.clear_cache()

        # Reload (will fetch fresh data)
        original_offline = self._offline_mode
        self._offline_mode = False
        try:
            result = self.load_trusted_list(offline=False)
            return result
        finally:
            self._offline_mode = original_offline

    def get_list_info(self) -> TrustedListInfo | None:
        """Get metadata about the loaded trusted list."""
        if not self._tsps:
            self.load_trusted_list(offline=True)

        return self._list_info

    def check_certificate_issuer(self, issuer_dn: str) -> QualificationStatus:
        """Check if certificate issuer is a qualified TSP by matching the issuer DN."""
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
                    required_matches = max(2, (len(tsp_words) * 2 + 2) // 3)
                    if matches >= required_matches:
                        return tsp.status

        return QualificationStatus.UNKNOWN

    # --- Private methods ---

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent lookups."""
        parsed = urlparse(url.lower())
        normalized = f"{parsed.netloc}{parsed.path}".rstrip("/")
        return normalized

    def _load_mock_data(self) -> bool:
        """Load mock TSP data for MVP/testing."""
        from pdfsigner.core.eidas.tsp_storage import get_mock_tsps

        mock_tsps = get_mock_tsps()

        # Store normalized
        self._tsps = {}
        for tsp in mock_tsps:
            normalized_url = self._normalize_url(tsp.service_url)
            self._tsps[normalized_url] = tsp

        # Create list info
        self._list_info = TrustedListInfo(
            version="5.5.1",
            issue_date=datetime.now(UTC),
            next_update=datetime.now(UTC) + timedelta(days=7),
            total_tsps=len(mock_tsps),
            countries=sorted(set(tsp.country for tsp in mock_tsps)),
        )

        # Save to cache
        self._storage.save_to_cache(self._tsps, self._list_info)

        logger.info(f"Loaded {len(self._tsps)} mock TSPs")
        return True


# --- Singleton access ---

_registry: EUTSPRegistry | None = None


def get_tsp_registry(
    use_mock_data: bool = False,
    territories: list[str] | None = None,
) -> EUTSPRegistry:
    """Get or create the singleton TSP registry instance.

    Args:
        use_mock_data: If True, use mock data instead of real TSLs
        territories: List of country codes to fetch (None = read from settings)

    Returns:
        EUTSPRegistry singleton instance
    """
    global _registry
    if _registry is None:
        # Try to read territories from settings if not provided
        if territories is None:
            try:
                from pdfsigner.config.settings import get_settings

                settings = get_settings()
                if settings.eidas_eutl_territories:
                    territories = settings.eidas_eutl_territories
            except Exception as e:
                logger.warning("Could not load eIDAS territory settings: %s", e)

        _registry = EUTSPRegistry(
            use_mock_data=use_mock_data,
            territories=territories,
        )
        _registry.load_trusted_list(offline=True)
    return _registry

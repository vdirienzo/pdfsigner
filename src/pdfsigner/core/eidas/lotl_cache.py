"""lotl_cache.py - Cache management for EU List of Trusted Lists (LOTL)

Handles caching of LOTL XML data to minimize HTTP requests and provide
offline fallback. Shared types (TSLPointer, LOTLData) are also defined here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

# Official EU LOTL URL
EU_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

# XML namespaces used in ETSI TS 119 612
NAMESPACES = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xades": "http://uri.etsi.org/01903/v1.3.2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xml": "http://www.w3.org/XML/1998/namespace",
}


@dataclass
class TSLPointer:
    """Pointer to a country's Trusted Service List."""

    country_code: str  # ISO 3166-1 alpha-2
    country_name: str
    tsl_url: str
    mime_type: str = "application/vnd.etsi.tsl+xml"
    certificate_hash: str | None = None
    last_update: datetime | None = None


@dataclass
class LOTLData:
    """Parsed EU List of Trusted Lists data."""

    version: str
    sequence_number: int
    issue_date: datetime
    next_update: datetime
    tsl_pointers: list[TSLPointer] = field(default_factory=list)
    operator_name: str = ""
    territory: str = "EU"
    signature_valid: bool = False


class LOTLCache:
    """Cache management for EU LOTL XML data.

    Handles cache validation, reading, and writing of raw LOTL XML files.
    """

    def __init__(self, cache_dir: Path, cache_ttl: timedelta):
        """Initialize LOTL cache.

        Args:
            cache_dir: Directory for storing cached LOTL data
            cache_ttl: Time-to-live for cached data
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def cache_file(self) -> Path:
        """Path to the LOTL cache file."""
        return self.cache_dir / "eu-lotl.xml"

    def is_valid(self) -> bool:
        """Check if cache file is still valid.

        Returns:
            True if cache exists and is not expired
        """
        if not self.cache_file.exists():
            return False

        mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime, tz=UTC)
        age = datetime.now(UTC) - mtime
        is_valid = age < self.cache_ttl

        if not is_valid:
            logger.debug("Cache expired (age: %s, ttl: %s)", age, self.cache_ttl)

        return is_valid

    def read(self) -> bytes:
        """Read cached LOTL XML data.

        Returns:
            Raw XML bytes from cache file

        Raises:
            FileNotFoundError: If cache file doesn't exist
        """
        return self.cache_file.read_bytes()

    def write(self, data: bytes) -> None:
        """Write LOTL XML data to cache.

        Args:
            data: Raw XML bytes to cache
        """
        self.cache_file.write_bytes(data)
        logger.info("Saved EU LOTL to cache (%d bytes)", len(data))

    def exists(self) -> bool:
        """Check if cache file exists (regardless of validity).

        Returns:
            True if cache file exists
        """
        return self.cache_file.exists()

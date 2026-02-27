"""tsp_storage.py - Cache storage for EU Trusted List data

Handles JSON serialization and deserialization of TSP data for the
local file cache used by EUTSPRegistry.
"""

import base64
import hashlib
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pdfsigner.core.eidas.tsp_types import (
    QualificationStatus,
    ServiceType,
    TrustedListInfo,
    TSPInfo,
)

logger = logging.getLogger(__name__)


class TSPStorage:
    """Cache storage for EU Trusted List data.

    Manages reading and writing TSP data to a local JSON cache file,
    with expiration based on eIDAS weekly update requirements.
    """

    def __init__(self, cache_file: Path, cache_max_age_days: int = 7):
        """Initialize TSP storage.

        Args:
            cache_file: Path to the JSON cache file
            cache_max_age_days: Maximum age of cache in days (eIDAS requires weekly)
        """
        self._cache_file = cache_file
        self._cache_max_age_days = cache_max_age_days

    @property
    def cache_file(self) -> Path:
        """Path to the cache file."""
        return self._cache_file

    def load_from_cache(
        self,
    ) -> tuple[dict[str, TSPInfo], dict[str, TSPInfo], TrustedListInfo | None] | None:
        """Load TSL from cache file if not expired.

        Returns:
            Tuple of (tsps_dict, cert_to_tsp_dict, list_info) if loaded,
            None if cache is missing or expired.
        """
        if not self._cache_file.exists():
            return None

        try:
            # Check cache age
            cache_age = datetime.now(UTC) - datetime.fromtimestamp(
                self._cache_file.stat().st_mtime, tz=UTC
            )
            if cache_age > timedelta(days=self._cache_max_age_days):
                logger.info(f"TSL cache expired (age: {cache_age.days} days)")
                return None

            # Load cache
            with open(self._cache_file) as f:
                cache_data = json.load(f)

            # Restore TSPs
            tsps: dict[str, TSPInfo] = {}
            cert_to_tsp: dict[str, TSPInfo] = {}
            for url, tsp_dict in cache_data.get("tsps", {}).items():
                # Convert string dates back to datetime
                if tsp_dict.get("valid_from"):
                    tsp_dict["valid_from"] = datetime.fromisoformat(tsp_dict["valid_from"])
                if tsp_dict.get("valid_until"):
                    tsp_dict["valid_until"] = datetime.fromisoformat(tsp_dict["valid_until"])

                # Convert enums
                tsp_dict["service_type"] = ServiceType(tsp_dict["service_type"])
                tsp_dict["status"] = QualificationStatus(tsp_dict["status"])

                # Convert certificate from base64
                if tsp_dict.get("certificate_der"):
                    tsp_dict["certificate_der"] = base64.b64decode(tsp_dict["certificate_der"])

                tsp_info = TSPInfo(**tsp_dict)
                tsps[url] = tsp_info

                # Index by certificate
                if tsp_info.certificate_der:
                    fingerprint = hashlib.sha256(tsp_info.certificate_der).hexdigest()
                    cert_to_tsp[fingerprint] = tsp_info

            # Restore list info
            list_info: TrustedListInfo | None = None
            list_info_dict = cache_data.get("list_info")
            if list_info_dict:
                list_info_dict["issue_date"] = datetime.fromisoformat(list_info_dict["issue_date"])
                list_info_dict["next_update"] = datetime.fromisoformat(
                    list_info_dict["next_update"]
                )
                list_info = TrustedListInfo(**list_info_dict)

            logger.info(f"Loaded {len(tsps)} TSPs from cache")
            return tsps, cert_to_tsp, list_info

        except Exception as e:
            logger.warning(f"Failed to load TSL cache: {e}")
            return None

    def save_to_cache(
        self,
        tsps: dict[str, TSPInfo],
        list_info: TrustedListInfo | None,
    ) -> bool:
        """Save current TSL to cache file.

        Args:
            tsps: Dictionary of URL -> TSPInfo
            list_info: Trusted list metadata

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
            for url, tsp in tsps.items():
                tsp_dict = asdict(tsp)
                # Convert datetime to ISO format strings
                if tsp_dict.get("valid_from"):
                    tsp_dict["valid_from"] = tsp_dict["valid_from"].isoformat()
                if tsp_dict.get("valid_until"):
                    tsp_dict["valid_until"] = tsp_dict["valid_until"].isoformat()
                # Enums to strings
                tsp_dict["service_type"] = tsp_dict["service_type"].value
                tsp_dict["status"] = tsp_dict["status"].value
                # Certificate to base64
                if tsp_dict.get("certificate_der"):
                    tsp_dict["certificate_der"] = base64.b64encode(
                        tsp_dict["certificate_der"]
                    ).decode("ascii")

                tsps_dict[url] = tsp_dict

            cache_data["tsps"] = tsps_dict

            # Serialize list info
            if list_info:
                list_info_dict = asdict(list_info)
                list_info_dict["issue_date"] = list_info_dict["issue_date"].isoformat()
                list_info_dict["next_update"] = list_info_dict["next_update"].isoformat()
                cache_data["list_info"] = list_info_dict

            # Write to cache file
            with open(self._cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            logger.info(f"Saved {len(tsps)} TSPs to cache")
            return True

        except Exception as e:
            logger.error(f"Failed to save TSL cache: {e}")
            return False

    def clear_cache(self) -> None:
        """Remove cache file if it exists."""
        if self._cache_file.exists():
            self._cache_file.unlink()


def get_mock_tsps() -> list[TSPInfo]:
    """Get mock TSP data for MVP/testing.

    Returns common European provider data for offline and test scenarios.

    Returns:
        List of TSPInfo objects
    """
    return [
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

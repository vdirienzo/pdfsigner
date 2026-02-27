"""
eutl_adapter.py - EU Trusted Lists adapter using pyHanko EUTL support

Bridges pyHanko's native EU Trusted List (EUTL) implementation with
PDFSigner's existing EUTSPRegistry interface. Provides TLv6 support
per ETSI TS 119 612 V2.3.1+ (mandatory from April 29, 2026).

Standards:
- ETSI TS 119 612 V2.3.1+ (Trusted Lists format, TLv6)
- ETSI TS 119 172-4 V1.1.1 (Validation policy using trusted lists)
- ETSI EN 319 102-1 V1.4.1 (AdES validation procedures)
"""

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import Any

from loguru import logger

# Try importing pyHanko EUTL modules (available with [etsi] extras)
_PYHANKO_EUTL_AVAILABLE = False
try:
    from pyhanko.sign.validation.qualified.eutl_fetch import (
        FileSystemTLCache,
        lotl_to_registry,
    )
    from pyhanko.sign.validation.qualified.tsp import TSPTrustManager

    _PYHANKO_EUTL_AVAILABLE = True
except ImportError:
    logger.info("pyHanko EUTL support not available (install pyhanko[etsi])")
    FileSystemTLCache = None
    lotl_to_registry = None
    TSPTrustManager = None


class EUTLAdapter:
    """Adapter for pyHanko's EU Trusted Lists functionality.

    Provides a higher-level interface for initializing and querying
    the EU LOTL/TSL system via pyHanko's built-in EUTL support.

    This replaces the custom LOTL/TSL parsing in lotl_fetcher.py
    and tsl_parser.py with pyHanko's validated implementation that
    includes XML signature verification of trust lists.
    """

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        cache_days: int = 7,
        territories: list[str] | None = None,
    ):
        self._cache_dir = (
            Path(cache_dir) if cache_dir else (Path.home() / ".config" / "pdfsigner" / "eutl_cache")
        )
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_days = cache_days
        self._territories = territories
        self._trust_manager: Any = None
        self._registry: Any = None
        self._initialized = False
        self._errors: list[str] = []

    @property
    def is_available(self) -> bool:
        """Check if pyHanko EUTL support is available."""
        return _PYHANKO_EUTL_AVAILABLE

    @property
    def is_initialized(self) -> bool:
        """Check if the EUTL adapter has been initialized."""
        return self._initialized

    @property
    def trust_manager(self) -> Any:
        """Get the pyHanko TSPTrustManager (None if not initialized)."""
        return self._trust_manager

    @property
    def errors(self) -> list[str]:
        """Get any errors from initialization."""
        return self._errors

    def initialize_sync(self) -> bool:
        """Initialize EUTL synchronously (wrapper around async init).

        Returns:
            True if initialization successful, False otherwise
        """
        if not _PYHANKO_EUTL_AVAILABLE:
            logger.warning("pyHanko EUTL not available, cannot initialize")
            return False

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self.initialize())
            loop.close()
            return result
        except Exception as e:
            logger.error("EUTL sync initialization failed: %s", e)
            self._errors.append(str(e))
            return False

    async def initialize(self) -> bool:
        """Initialize EUTL from EU LOTL asynchronously.

        Downloads and parses the EU LOTL and country TSLs, building
        a trust registry with XML signature validation.

        Returns:
            True if initialization successful, False otherwise
        """
        if not _PYHANKO_EUTL_AVAILABLE:
            logger.warning("pyHanko EUTL not available")
            return False

        try:
            import aiohttp

            tl_cache = FileSystemTLCache(
                str(self._cache_dir),
                expire_after=timedelta(days=self._cache_days),
            )

            territories_str = None
            if self._territories:
                territories_str = ",".join(t.lower() for t in self._territories)

            async with aiohttp.ClientSession() as client:
                self._registry, errors = await lotl_to_registry(
                    client,
                    tl_cache,
                    only_territories=territories_str,
                )

            if errors:
                for err in errors:
                    err_str = str(err)
                    logger.warning("EUTL loading error: %s", err_str)
                    self._errors.append(err_str)

            if self._registry:
                self._trust_manager = TSPTrustManager(tsp_registry=self._registry)
                self._initialized = True
                logger.info(
                    "EUTL initialized successfully (territories=%s, errors=%d)",
                    territories_str or "all",
                    len(errors) if errors else 0,
                )
                return True
            else:
                logger.error("EUTL initialization returned no registry")
                return False

        except ImportError as e:
            logger.error("Missing dependency for EUTL: %s", e)
            self._errors.append(f"Missing dependency: {e}")
            return False
        except Exception as e:
            logger.error("EUTL initialization failed: %s", e)
            self._errors.append(str(e))
            return False


# Singleton
_eutl_adapter: EUTLAdapter | None = None


def get_eutl_adapter() -> EUTLAdapter:
    """Get or create the singleton EUTL adapter.

    Returns:
        EUTLAdapter instance (may not be initialized yet)
    """
    global _eutl_adapter
    if _eutl_adapter is None:
        try:
            from pdfsigner.config.settings import get_settings

            settings = get_settings()
            cache_dir = settings.eidas_eutl_cache_dir or None
            cache_days = settings.eidas_cache_days
            territories = settings.eidas_eutl_territories or None
        except Exception:
            cache_dir = None
            cache_days = 7
            territories = None

        _eutl_adapter = EUTLAdapter(
            cache_dir=cache_dir,
            cache_days=cache_days,
            territories=territories,
        )
    return _eutl_adapter

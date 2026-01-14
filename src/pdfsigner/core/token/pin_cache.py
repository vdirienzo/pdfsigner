"""
pin_cache.py - Secure in-memory PIN cache

Author: Homero Thompson del Lago del Terror

Implements PIN cache for batch signing with:
- Storage only in memory (never on disk)
- Automatic expiration by time
- Secure memory cleanup
"""

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class CachedPin:
    """Cached PIN with expiration metadata."""

    pin: str
    created_at: float
    expires_at: float


class PinCache:
    """
    Secure in-memory PIN cache.

    PIN is stored temporarily to allow batch signing
    without asking for PIN multiple times.
    """

    def __init__(self, timeout_seconds: int = 300):
        """
        Initialize PIN cache.

        Args:
            timeout_seconds: Expiration timeout in seconds (default: 5 min)
        """
        self._timeout = timeout_seconds
        self._cache: CachedPin | None = None
        self._lock = threading.Lock()

    def store(self, pin: str) -> None:
        """
        Store PIN in cache.

        Args:
            pin: PIN to cache
        """
        with self._lock:
            now = time.time()
            self._cache = CachedPin(
                pin=pin,
                created_at=now,
                expires_at=now + self._timeout,
            )

    def get(self) -> str | None:
        """
        Get cached PIN if not expired.

        Returns:
            PIN if valid, None if expired or doesn't exist
        """
        with self._lock:
            if self._cache is None:
                return None

            if time.time() > self._cache.expires_at:
                self._clear_unsafe()
                return None

            return self._cache.pin

    def clear(self) -> None:
        """Clear cache securely."""
        with self._lock:
            self._clear_unsafe()

    def _clear_unsafe(self) -> None:
        """Clear cache (must be called with lock acquired)."""
        if self._cache is not None:
            # Overwrite PIN in memory before deleting
            if self._cache.pin:
                # Generate random data of same size
                dummy = secrets.token_hex(len(self._cache.pin))
                # Overwrite (best effort in Python)
                self._cache.pin = dummy
            self._cache = None

    def is_valid(self) -> bool:
        """Check if there's a valid PIN in cache."""
        return self.get() is not None

    def extend(self, additional_seconds: int | None = None) -> bool:
        """
        Extend cached PIN validity.

        Args:
            additional_seconds: Seconds to add (default: original timeout)

        Returns:
            True if extended, False if no valid PIN found
        """
        with self._lock:
            if self._cache is None or time.time() > self._cache.expires_at:
                return False

            extension = additional_seconds or self._timeout
            self._cache.expires_at = time.time() + extension
            return True

    @property
    def remaining_seconds(self) -> int:
        """Remaining seconds of PIN validity."""
        with self._lock:
            if self._cache is None:
                return 0
            remaining = self._cache.expires_at - time.time()
            return max(0, int(remaining))


# Global cache singleton
_pin_cache: PinCache | None = None


def get_pin_cache(timeout_seconds: int = 300) -> PinCache:
    """
    Get global PIN cache instance.

    Args:
        timeout_seconds: Initial timeout if creating new instance

    Returns:
        PinCache singleton instance
    """
    global _pin_cache
    if _pin_cache is None:
        _pin_cache = PinCache(timeout_seconds)
    return _pin_cache


def clear_global_cache() -> None:
    """Clear global PIN cache."""
    global _pin_cache
    if _pin_cache is not None:
        _pin_cache.clear()

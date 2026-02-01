"""
FIPS 140-2 compliant cryptography provider for PDFSigner.

This module provides a FIPS-validated cryptography provider that restricts
algorithm usage to FIPS-approved algorithms only. When FIPS mode is enabled,
any attempt to use non-FIPS algorithms will be rejected.

FIPS 140-2 is a U.S. government computer security standard used to approve
cryptographic modules. Compliance is required for federal agencies and
contractors handling sensitive information.

Author: Homero Thompson del Lago del Terror
"""

import hashlib
import logging
import warnings
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AlgorithmCategory(str, Enum):
    """Categories of cryptographic algorithms."""

    HASH = "hash"
    ENCRYPTION = "encryption"
    SIGNATURE = "signature"
    MAC = "mac"


class FIPSModeError(Exception):
    """Raised when a non-FIPS algorithm is used in strict FIPS mode."""

    pass


class FIPSCryptoProvider:
    """
    FIPS 140-2 compliant cryptography provider.

    Provides validation and access to FIPS-approved cryptographic algorithms.
    When FIPS mode is enabled, only algorithms from the allowed sets are permitted.

    FIPS-approved algorithms:
        - Hash: SHA-256, SHA-384, SHA-512
        - Encryption: AES-128, AES-256
        - Signature: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384
        - MAC: HMAC-SHA-256, HMAC-SHA-384

    Attributes:
        ALLOWED_HASH: Set of FIPS-approved hash algorithms
        ALLOWED_ENCRYPTION: Set of FIPS-approved encryption algorithms
        ALLOWED_SIGNATURE: Set of FIPS-approved signature algorithms
        ALLOWED_MAC: Set of FIPS-approved MAC algorithms
    """

    # FIPS 140-2 approved algorithms
    ALLOWED_HASH = {"SHA-256", "SHA-384", "SHA-512"}
    ALLOWED_ENCRYPTION = {"AES-128", "AES-256"}
    ALLOWED_SIGNATURE = {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}
    ALLOWED_MAC = {"HMAC-SHA-256", "HMAC-SHA-384"}

    def __init__(self, fips_mode: bool = False, strict_mode: bool = True) -> None:
        """
        Initialize FIPS crypto provider.

        Args:
            fips_mode: Enable FIPS mode (only allow FIPS-approved algorithms)
            strict_mode: In FIPS mode, raise exception vs warning for non-FIPS algorithms
        """
        self._fips_mode = fips_mode
        self._strict_mode = strict_mode
        self._fips_available = self._check_fips_availability()

        if fips_mode:
            logger.info(
                "FIPS 140-2 mode enabled (strict=%s, openssl_fips=%s)",
                strict_mode,
                self._fips_available,
            )

    def _check_fips_availability(self) -> bool:
        """
        Check if OpenSSL FIPS module is available.

        Returns:
            True if FIPS module is available, False otherwise
        """
        try:
            # Try to detect FIPS mode in OpenSSL
            # Note: This is a best-effort check, actual FIPS mode depends on OpenSSL config
            import ssl

            openssl_version = ssl.OPENSSL_VERSION
            logger.debug("OpenSSL version: %s", openssl_version)

            # Check if hashlib has FIPS indicators
            # In FIPS mode, some algorithms may not be available
            try:
                # MD5 is typically disabled in FIPS mode
                # Try to use MD5 with security flag (Python 3.9+)
                hashlib.md5(b"test", usedforsecurity=True)
                # If MD5 works, we're probably not in FIPS mode
                return False
            except ValueError:
                # MD5 disabled, possible FIPS mode
                return True
            except TypeError:
                # usedforsecurity not supported in older Python
                pass

            return False
        except Exception as e:
            logger.debug("Error checking FIPS availability: %s", e)
            return False

    @property
    def fips_mode(self) -> bool:
        """Check if FIPS mode is enabled."""
        return self._fips_mode

    @property
    def strict_mode(self) -> bool:
        """Check if strict mode is enabled."""
        return self._strict_mode

    def validate_algorithm(self, algorithm: str, category: AlgorithmCategory) -> bool:
        """
        Validate if an algorithm is allowed in current mode.

        Args:
            algorithm: Algorithm name (e.g., "SHA-256", "AES-256")
            category: Algorithm category (hash, encryption, signature, mac)

        Returns:
            True if algorithm is allowed, False otherwise

        Raises:
            FIPSModeError: If algorithm is not allowed in strict FIPS mode
        """
        # Normalize algorithm name
        algorithm_upper = algorithm.upper()

        # Get allowed algorithms for category
        allowed_algorithms = self._get_allowed_algorithms(category)

        # Check if algorithm is allowed
        is_allowed = algorithm_upper in allowed_algorithms

        if not self._fips_mode:
            # Not in FIPS mode, all algorithms allowed
            return True

        if not is_allowed:
            msg = f"Algorithm '{algorithm}' not allowed in FIPS mode (category: {category.value})"
            if self._strict_mode:
                logger.error(msg)
                raise FIPSModeError(msg)
            else:
                warnings.warn(msg, UserWarning, stacklevel=2)
                logger.warning(msg)
                return False

        return True

    def _get_allowed_algorithms(self, category: AlgorithmCategory) -> set[str]:
        """
        Get allowed algorithms for a category.

        Args:
            category: Algorithm category

        Returns:
            Set of allowed algorithm names
        """
        category_map = {
            AlgorithmCategory.HASH: self.ALLOWED_HASH,
            AlgorithmCategory.ENCRYPTION: self.ALLOWED_ENCRYPTION,
            AlgorithmCategory.SIGNATURE: self.ALLOWED_SIGNATURE,
            AlgorithmCategory.MAC: self.ALLOWED_MAC,
        }
        return category_map.get(category, set())

    def get_hash_algorithm(self, name: str) -> Any:
        """
        Get a hash algorithm instance.

        Args:
            name: Hash algorithm name (e.g., "SHA-256", "SHA-512")

        Returns:
            Hash algorithm instance from hashlib

        Raises:
            FIPSModeError: If algorithm not allowed in strict FIPS mode
            ValueError: If algorithm is unknown
        """
        # Validate algorithm
        self.validate_algorithm(name, AlgorithmCategory.HASH)

        # Normalize name for hashlib
        name_lower = name.lower().replace("-", "")

        # Get algorithm from hashlib
        try:
            return getattr(hashlib, name_lower)
        except AttributeError:
            raise ValueError(f"Unknown hash algorithm: {name}") from None

    def get_cipher(self, algorithm: str) -> str:
        """
        Get cipher identifier for encryption.

        Args:
            algorithm: Encryption algorithm name (e.g., "AES-256")

        Returns:
            Cipher identifier string

        Raises:
            FIPSModeError: If algorithm not allowed in strict FIPS mode
        """
        # Validate algorithm
        self.validate_algorithm(algorithm, AlgorithmCategory.ENCRYPTION)

        # Return normalized cipher identifier
        return algorithm.upper()

    def is_fips_available(self) -> bool:
        """
        Check if OpenSSL FIPS module is available.

        Returns:
            True if FIPS module is available, False otherwise
        """
        return self._fips_available

    def get_provider_info(self) -> dict[str, Any]:
        """
        Get information about the crypto provider.

        Returns:
            Dictionary with provider information including:
            - fips_mode: Whether FIPS mode is enabled
            - strict_mode: Whether strict mode is enabled
            - fips_available: Whether OpenSSL FIPS module is available
            - allowed_algorithms: Dictionary of allowed algorithms by category
        """
        return {
            "fips_mode": self._fips_mode,
            "strict_mode": self._strict_mode,
            "fips_available": self._fips_available,
            "allowed_algorithms": {
                "hash": sorted(self.ALLOWED_HASH),
                "encryption": sorted(self.ALLOWED_ENCRYPTION),
                "signature": sorted(self.ALLOWED_SIGNATURE),
                "mac": sorted(self.ALLOWED_MAC),
            },
        }

    def validate_signature_algorithm(self, algorithm: str, key_size: int | None = None) -> bool:
        """
        Validate a signature algorithm and optional key size.

        Args:
            algorithm: Base algorithm name (e.g., "RSA", "ECDSA")
            key_size: Optional key size in bits (e.g., 2048, 4096)

        Returns:
            True if algorithm/key size combination is allowed

        Raises:
            FIPSModeError: If combination not allowed in strict FIPS mode
        """
        # Build full algorithm identifier
        if key_size:
            if algorithm.upper() == "RSA":
                full_algo = f"RSA-{key_size}"
            elif algorithm.upper() == "ECDSA":
                # ECDSA uses curve name, not key size typically
                # Map common key sizes to curves
                curve_map = {256: "P256", 384: "P384"}
                curve = curve_map.get(key_size, f"P{key_size}")
                full_algo = f"ECDSA-{curve}"
            else:
                full_algo = algorithm.upper()
        else:
            full_algo = algorithm.upper()

        return self.validate_algorithm(full_algo, AlgorithmCategory.SIGNATURE)


# Singleton instance
_fips_provider: FIPSCryptoProvider | None = None


def get_fips_provider() -> FIPSCryptoProvider:
    """
    Get singleton FIPS provider instance.

    The provider is initialized based on settings from config.

    Returns:
        FIPSCryptoProvider instance
    """
    global _fips_provider

    if _fips_provider is None:
        # Import here to avoid circular dependency
        from pdfsigner.config.settings import get_settings

        settings = get_settings()
        _fips_provider = FIPSCryptoProvider(
            fips_mode=settings.fips_mode_enabled,
            strict_mode=settings.fips_strict_mode,
        )

    return _fips_provider


def reset_fips_provider() -> None:
    """
    Reset the singleton FIPS provider instance.

    Useful for testing or when settings change.
    """
    global _fips_provider
    _fips_provider = None

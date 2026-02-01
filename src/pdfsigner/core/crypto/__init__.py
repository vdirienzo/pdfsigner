"""
Cryptography module for PDFSigner.

Provides FIPS 140-2 compliant cryptography provider for enhanced security.
When FIPS mode is enabled, only FIPS-validated algorithms are allowed.

Usage:
    from pdfsigner.core.crypto import (
        FIPSCryptoProvider,
        get_fips_provider,
        AlgorithmCategory,
    )

    # Get FIPS provider
    provider = get_fips_provider()

    # Check if algorithm is allowed
    if provider.validate_algorithm("SHA-256", AlgorithmCategory.HASH):
        hash_algo = provider.get_hash_algorithm("SHA-256")

    # Check FIPS availability
    if provider.is_fips_available():
        print("OpenSSL FIPS module is available")
"""

from pdfsigner.core.crypto.fips_provider import (
    AlgorithmCategory,
    FIPSCryptoProvider,
    FIPSModeError,
    get_fips_provider,
    reset_fips_provider,
)

__all__ = [
    "FIPSCryptoProvider",
    "get_fips_provider",
    "reset_fips_provider",
    "AlgorithmCategory",
    "FIPSModeError",
]

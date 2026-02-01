"""
pkcs11_libs.py - PKCS#11 library paths configuration

Cross-platform support for Linux, macOS, and Windows.

Defines library paths for various PKCS#11 token vendors.
Paths are ordered by priority (first found is used).

Supported tokens:
- SafeNet/Thales eToken (5110, 5300, Luna HSM)
- YubiKey (PIV mode)
- Nitrokey Pro/HSM
- OpenSC (generic smart cards)
- Feitian ePass
- SoftHSM (testing)
- nCipher/Entrust HSM
- Generic NSS (fallback)

Usage:
    from pdfsigner.core.token.pkcs11_libs import (
        PKCS11_LIB_GROUPS,
        find_library,
    )

    # Find first available library
    lib_path = find_library()

    # Find specific vendor
    lib_path = find_library(vendor="yubikey")
"""

from pathlib import Path

from pdfsigner.core.platform import (
    find_pkcs11_library,
    get_pkcs11_lib_groups,
    get_pkcs11_paths_for_vendor,
    is_linux,
    is_macos,
    is_windows,
)

# ==========================================================================
# Cross-platform PKCS#11 library groups
# ==========================================================================

# Dynamic paths based on current platform
# Convert Path objects to strings for backward compatibility
_raw_groups = get_pkcs11_lib_groups()
PKCS11_LIB_GROUPS = [(name, [str(p) for p in paths]) for name, paths in _raw_groups]

# ==========================================================================
# Vendor-specific path lists (for backward compatibility)
# Convert Path objects to strings for legacy code
# ==========================================================================


def _paths_to_strings(paths: list[Path]) -> list[str]:
    """Convert Path objects to strings for legacy compatibility."""
    return [str(p) for p in paths]


SAFENET_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("safenet"))
YUBIKEY_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("yubikey"))
NITROKEY_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("nitrokey"))
OPENSC_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("opensc"))
FEITIAN_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("feitian"))
SOFTHSM_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("softhsm"))
NCIPHER_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("ncipher"))
NSS_LIB_PATHS = _paths_to_strings(get_pkcs11_paths_for_vendor("nss"))


# ==========================================================================
# Library discovery functions
# ==========================================================================


def find_library(vendor: str | None = None) -> str | None:
    """
    Find the first existing PKCS#11 library.

    Args:
        vendor: Optional vendor name (safenet, yubikey, nitrokey, opensc,
                feitian, softhsm, ncipher, nss). If None, searches all.

    Returns:
        Path string to the first found library, or None if not found.

    Example:
        >>> lib = find_library()  # Any available library
        >>> lib = find_library("yubikey")  # YubiKey specifically
    """
    result = find_pkcs11_library(vendor)
    return str(result) if result else None


def get_platform_info() -> dict[str, bool]:
    """
    Get current platform information.

    Returns:
        Dictionary with platform flags.

    Example:
        >>> info = get_platform_info()
        >>> if info["is_macos"]:
        ...     print("Running on macOS")
    """
    return {
        "is_linux": is_linux(),
        "is_macos": is_macos(),
        "is_windows": is_windows(),
    }

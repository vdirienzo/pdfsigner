"""
Platform detection and cross-platform path configuration.

This module provides OS detection and platform-specific paths for:
- PKCS#11 libraries (tokens, HSMs)
- Certificate trust stores
- NSS database locations
- Configuration directories

Supported platforms:
- Linux (primary)
- macOS (Darwin)
- Windows

Author: PDFSigner Team
"""

from pdfsigner.core.platform.detector import (
    Platform,
    get_platform,
    is_linux,
    is_macos,
    is_windows,
)
from pdfsigner.core.platform.paths import (
    get_config_dir,
    get_nss_db_path,
    get_pkcs11_extension,
    get_trust_store_paths,
)
from pdfsigner.core.platform.pkcs11_paths import (
    find_pkcs11_library,
    get_all_pkcs11_paths,
    get_pkcs11_lib_groups,
    get_pkcs11_paths_for_vendor,
)

__all__ = [
    # Platform detection
    "Platform",
    "get_platform",
    "is_linux",
    "is_macos",
    "is_windows",
    # Paths
    "get_config_dir",
    "get_nss_db_path",
    "get_pkcs11_extension",
    "get_trust_store_paths",
    # PKCS#11
    "find_pkcs11_library",
    "get_all_pkcs11_paths",
    "get_pkcs11_lib_groups",
    "get_pkcs11_paths_for_vendor",
]

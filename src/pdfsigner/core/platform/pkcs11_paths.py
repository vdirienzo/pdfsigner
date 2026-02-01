"""
PKCS#11 library paths for all supported platforms.

Defines library paths for various PKCS#11 token vendors across
Linux, macOS, and Windows. Paths are ordered by priority.

Supported tokens:
- SafeNet/Thales eToken (5110, 5300, Luna HSM)
- YubiKey (PIV mode)
- Nitrokey Pro/HSM
- OpenSC (generic smart cards)
- Feitian ePass
- SoftHSM (testing)
- nCipher/Entrust HSM
- Generic NSS (fallback)
"""

import os
from pathlib import Path

from pdfsigner.core.platform.detector import Platform, get_platform
from pdfsigner.core.platform.paths import (
    get_program_files_path,
    get_program_files_x86_path,
)

# =============================================================================
# Platform-specific path builders
# =============================================================================


def _get_windows_paths() -> dict[str, list[Path]]:
    """Get PKCS#11 library paths for Windows."""
    pf = get_program_files_path() or Path("C:/Program Files")
    pf86 = get_program_files_x86_path() or Path("C:/Program Files (x86)")
    sys32 = Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32"

    return {
        "safenet": [
            pf / "SafeNet" / "Authentication" / "SAC" / "x64" / "IDPrimePKCS11.dll",
            pf86 / "SafeNet" / "Authentication" / "SAC" / "x32" / "IDPrimePKCS11.dll",
            pf / "Gemalto" / "IDGo 800 PKCS#11" / "IDPrimePKCS11.dll",
            pf / "SafeNet" / "LunaClient" / "cryptoki.dll",
        ],
        "yubikey": [
            pf / "Yubico" / "Yubico PIV Tool" / "bin" / "libykcs11.dll",
            pf86 / "Yubico" / "Yubico PIV Tool" / "bin" / "libykcs11.dll",
            pf / "Yubico" / "YubiKey PIV Manager" / "libykcs11.dll",
        ],
        "nitrokey": [
            pf / "Nitrokey" / "bin" / "libnitrokey.dll",
            pf / "Nitrokey" / "NetHSM" / "libnethsm.dll",
        ],
        "opensc": [
            pf / "OpenSC Project" / "OpenSC" / "pkcs11" / "opensc-pkcs11.dll",
            pf86 / "OpenSC Project" / "OpenSC" / "pkcs11" / "opensc-pkcs11.dll",
            sys32 / "opensc-pkcs11.dll",
        ],
        "feitian": [
            pf / "Feitian" / "ePass" / "PKCS11" / "ePass.dll",
            pf86 / "Feitian" / "ePass" / "PKCS11" / "ePass.dll",
            pf / "Feitian" / "ePassNG" / "PKCS11" / "ftsafe-p11.dll",
        ],
        "softhsm": [
            pf / "SoftHSM2" / "lib" / "softhsm2.dll",
            pf / "SoftHSM" / "lib" / "softhsm2.dll",
            Path(os.environ.get("SOFTHSM2_LIB", ""))
            if os.environ.get("SOFTHSM2_LIB")
            else pf / "SoftHSM2" / "lib" / "softhsm2.dll",
        ],
        "ncipher": [
            pf / "nCipher" / "nfast" / "toolkits" / "pkcs11" / "cknfast.dll",
            Path("C:/") / "nfast" / "toolkits" / "pkcs11" / "cknfast.dll",
        ],
        "nss": [
            sys32 / "softokn3.dll",
            sys32 / "nssckbi.dll",
            pf / "Mozilla Firefox" / "softokn3.dll",
            pf / "Mozilla Thunderbird" / "softokn3.dll",
        ],
    }


def _get_macos_paths() -> dict[str, list[Path]]:
    """Get PKCS#11 library paths for macOS."""
    homebrew_intel = Path("/usr/local")
    homebrew_arm = Path("/opt/homebrew")
    library = Path("/Library")

    return {
        "safenet": [
            library
            / "Frameworks"
            / "eToken.framework"
            / "Versions"
            / "Current"
            / "libeToken.dylib",
            Path("/usr/local/lib/libeToken.dylib"),
            homebrew_intel / "lib" / "libeToken.dylib",
            homebrew_arm / "lib" / "libeToken.dylib",
            # Luna HSM
            Path("/usr/safenet/lunaclient/lib/libCryptoki2.dylib"),
            library / "SafeNet" / "LunaClient" / "lib" / "libCryptoki2.dylib",
        ],
        "yubikey": [
            homebrew_intel / "lib" / "libykcs11.dylib",
            homebrew_arm / "lib" / "libykcs11.dylib",
            Path("/usr/local/lib/libykcs11.dylib"),
            library / "Yubico" / "lib" / "libykcs11.dylib",
        ],
        "nitrokey": [
            homebrew_intel / "lib" / "libnitrokey.dylib",
            homebrew_arm / "lib" / "libnitrokey.dylib",
            homebrew_intel / "lib" / "libnethsm.dylib",
            homebrew_arm / "lib" / "libnethsm.dylib",
        ],
        "opensc": [
            library / "OpenSC" / "lib" / "opensc-pkcs11.dylib",
            homebrew_intel / "lib" / "opensc-pkcs11.dylib",
            homebrew_arm / "lib" / "opensc-pkcs11.dylib",
            Path("/usr/local/lib/opensc-pkcs11.dylib"),
            # MacPorts
            Path("/opt/local/lib/opensc-pkcs11.dylib"),
        ],
        "feitian": [
            library / "Feitian" / "libftsafe-p11.dylib",
            homebrew_intel / "lib" / "libftsafe-p11.dylib",
            homebrew_arm / "lib" / "libftsafe-p11.dylib",
        ],
        "softhsm": [
            homebrew_intel / "lib" / "softhsm" / "libsofthsm2.dylib",
            homebrew_arm / "lib" / "softhsm" / "libsofthsm2.dylib",
            Path("/usr/local/lib/softhsm/libsofthsm2.dylib"),
            # MacPorts
            Path("/opt/local/lib/softhsm/libsofthsm2.dylib"),
        ],
        "ncipher": [
            Path("/opt/nfast/toolkits/pkcs11/libcknfast.dylib"),
            library / "nCipher" / "toolkits" / "pkcs11" / "libcknfast.dylib",
        ],
        "nss": [
            # NSS from Firefox
            Path("/Applications/Firefox.app/Contents/MacOS/libsoftokn3.dylib"),
            homebrew_intel / "lib" / "libsoftokn3.dylib",
            homebrew_arm / "lib" / "libsoftokn3.dylib",
            # Homebrew NSS
            homebrew_intel / "opt" / "nss" / "lib" / "libsoftokn3.dylib",
            homebrew_arm / "opt" / "nss" / "lib" / "libsoftokn3.dylib",
        ],
    }


def _get_linux_paths() -> dict[str, list[Path]]:
    """Get PKCS#11 library paths for Linux."""
    return {
        "safenet": [
            Path("/usr/lib/libeToken.so"),
            Path("/usr/lib/x86_64-linux-gnu/libeToken.so"),
            Path("/usr/lib64/libeToken.so"),
            Path("/opt/safenet/lunaclient/lib/libCryptoki2_64.so"),
            Path("/usr/safenet/lunaclient/lib/libCryptoki2_64.so"),
        ],
        "yubikey": [
            Path("/usr/lib/x86_64-linux-gnu/libykcs11.so"),
            Path("/usr/lib/libykcs11.so"),
            Path("/usr/lib64/libykcs11.so"),
            Path("/usr/local/lib/libykcs11.so"),
        ],
        "nitrokey": [
            Path("/usr/lib/x86_64-linux-gnu/libnethsm.so"),
            Path("/usr/lib/libnethsm.so"),
            Path("/usr/lib/x86_64-linux-gnu/libnitrokey.so"),
            Path("/usr/lib/libnitrokey.so"),
        ],
        "opensc": [
            Path("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            Path("/usr/lib/opensc-pkcs11.so"),
            Path("/usr/lib64/opensc-pkcs11.so"),
            Path("/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"),
        ],
        "feitian": [
            Path("/usr/lib/libcastle.so"),
            Path("/usr/lib/x86_64-linux-gnu/libcastle.so"),
            Path("/usr/lib/libftsafe-p11.so"),
        ],
        "softhsm": [
            Path("/usr/lib/softhsm/libsofthsm2.so"),
            Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
            Path("/usr/local/lib/softhsm/libsofthsm2.so"),
            Path("/usr/lib64/softhsm/libsofthsm2.so"),
        ],
        "ncipher": [
            Path("/opt/nfast/toolkits/pkcs11/libcknfast.so"),
            Path("/usr/lib/libcknfast.so"),
        ],
        "nss": [
            Path("/usr/lib/x86_64-linux-gnu/libnssckbi.so"),
            Path("/usr/lib/x86_64-linux-gnu/libsoftokn3.so"),
            Path("/usr/lib/libnssckbi.so"),
            Path("/usr/lib/libsoftokn3.so"),
            Path("/usr/lib64/libnssckbi.so"),
            Path("/usr/lib64/libsoftokn3.so"),
        ],
    }


# =============================================================================
# Public API
# =============================================================================


def get_pkcs11_paths_for_vendor(vendor: str) -> list[Path]:
    """
    Get PKCS#11 library paths for a specific vendor on the current platform.

    Args:
        vendor: Token vendor name (safenet, yubikey, nitrokey, opensc,
                feitian, softhsm, ncipher, nss).

    Returns:
        List of possible library paths for the vendor.
    """
    platform = get_platform()

    path_getters = {
        Platform.LINUX: _get_linux_paths,
        Platform.MACOS: _get_macos_paths,
        Platform.WINDOWS: _get_windows_paths,
    }

    getter = path_getters.get(platform, _get_linux_paths)
    paths = getter()

    return paths.get(vendor.lower(), [])


def get_all_pkcs11_paths() -> dict[str, list[Path]]:
    """
    Get all PKCS#11 library paths for the current platform.

    Returns:
        Dictionary mapping vendor names to their library paths.
    """
    platform = get_platform()

    path_getters = {
        Platform.LINUX: _get_linux_paths,
        Platform.MACOS: _get_macos_paths,
        Platform.WINDOWS: _get_windows_paths,
    }

    getter = path_getters.get(platform, _get_linux_paths)
    return getter()


def find_pkcs11_library(vendor: str | None = None) -> Path | None:
    """
    Find the first existing PKCS#11 library.

    Args:
        vendor: Optional vendor name to search. If None, searches all vendors.

    Returns:
        Path to the first found library, or None if not found.
    """
    if vendor:
        paths = get_pkcs11_paths_for_vendor(vendor)
        for path in paths:
            if path.exists():
                return path
        return None

    # Search all vendors in priority order
    all_paths = get_all_pkcs11_paths()
    priority_order = [
        "safenet",
        "yubikey",
        "nitrokey",
        "opensc",
        "feitian",
        "softhsm",
        "ncipher",
        "nss",
    ]

    for vendor_name in priority_order:
        paths = all_paths.get(vendor_name, [])
        for path in paths:
            if path.exists():
                return path

    return None


def get_pkcs11_lib_groups() -> list[tuple[str, list[Path]]]:
    """
    Get PKCS#11 library groups in search order (priority).

    Returns:
        List of tuples (vendor_display_name, paths) for library discovery.
        Compatible with the legacy PKCS11_LIB_GROUPS format.
    """
    all_paths = get_all_pkcs11_paths()

    display_names = {
        "safenet": "SafeNet/Thales",
        "yubikey": "YubiKey",
        "nitrokey": "Nitrokey",
        "opensc": "OpenSC",
        "feitian": "Feitian",
        "softhsm": "SoftHSM",
        "ncipher": "nCipher",
        "nss": "NSS",
    }

    return [(display_names[key], all_paths[key]) for key in display_names if key in all_paths]

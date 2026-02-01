"""
Platform-specific path configurations.

Provides paths for certificates, PKCS#11 libraries, and configuration
directories across Linux, macOS, and Windows.
"""

import os
from pathlib import Path

from pdfsigner.core.platform.detector import Platform, get_platform


def get_pkcs11_extension() -> str:
    """
    Get the shared library extension for the current platform.

    Returns:
        ".so" for Linux, ".dylib" for macOS, ".dll" for Windows.
    """
    extensions = {
        Platform.LINUX: ".so",
        Platform.MACOS: ".dylib",
        Platform.WINDOWS: ".dll",
    }
    return extensions.get(get_platform(), ".so")


def get_config_dir() -> Path:
    """
    Get the user configuration directory for PDFSigner.

    Returns:
        Platform-appropriate config directory path.
    """
    platform = get_platform()

    if platform == Platform.WINDOWS:
        # %APPDATA%/pdfsigner or fallback
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "pdfsigner"
        return Path.home() / "AppData" / "Roaming" / "pdfsigner"

    elif platform == Platform.MACOS:
        # ~/Library/Application Support/pdfsigner
        return Path.home() / "Library" / "Application Support" / "pdfsigner"

    else:
        # Linux: ~/.config/pdfsigner (XDG standard)
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config) / "pdfsigner"
        return Path.home() / ".config" / "pdfsigner"


def get_nss_db_path() -> Path:
    """
    Get the default NSS database path for the current platform.

    Returns:
        Platform-appropriate NSS database directory.
    """
    platform = get_platform()

    if platform == Platform.WINDOWS:
        # Windows: use config dir
        return get_config_dir() / "nssdb"

    elif platform == Platform.MACOS:
        # macOS: ~/.nss (same as Linux for consistency)
        return Path.home() / ".nss"

    else:
        # Linux: ~/.nss
        return Path.home() / ".nss"


def get_trust_store_paths() -> list[Path]:
    """
    Get system CA certificate trust store paths.

    Returns:
        List of paths to check for CA certificates, in priority order.
    """
    platform = get_platform()

    if platform == Platform.WINDOWS:
        # Windows uses the certificate store, but OpenSSL might need these
        return [
            Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
            / "ssl"
            / "certs"
            / "ca-bundle.crt",
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
            / "Git"
            / "mingw64"
            / "ssl"
            / "certs"
            / "ca-bundle.crt",
            Path(os.environ.get("LOCALAPPDATA", "")) / "mkcert" / "rootCA.pem",
        ]

    elif platform == Platform.MACOS:
        return [
            # Homebrew OpenSSL
            Path("/usr/local/etc/openssl@3/cert.pem"),
            Path("/usr/local/etc/openssl/cert.pem"),
            Path("/opt/homebrew/etc/openssl@3/cert.pem"),
            Path("/opt/homebrew/etc/openssl/cert.pem"),
            # System (extracted from Keychain)
            Path("/etc/ssl/cert.pem"),
            # MacPorts
            Path("/opt/local/etc/openssl/cert.pem"),
        ]

    else:
        # Linux distributions
        return [
            Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian/Ubuntu
            Path("/etc/pki/tls/certs/ca-bundle.crt"),  # RedHat/Fedora
            Path("/etc/ssl/ca-bundle.pem"),  # OpenSUSE
            Path("/etc/ssl/cert.pem"),  # Alpine/OpenBSD
            Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),  # CentOS
        ]


def get_program_files_path() -> Path | None:
    """
    Get the Program Files directory on Windows.

    Returns:
        Path to Program Files, or None if not on Windows.
    """
    if get_platform() != Platform.WINDOWS:
        return None

    return Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))


def get_program_files_x86_path() -> Path | None:
    """
    Get the Program Files (x86) directory on Windows.

    Returns:
        Path to Program Files (x86), or None if not on Windows.
    """
    if get_platform() != Platform.WINDOWS:
        return None

    return Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)"))

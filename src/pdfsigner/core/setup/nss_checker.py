"""
nss_checker.py - NSS database configuration checker

Author: Homero Thompson del Lago del Terror

Checks if NSS database is properly configured and ready
for PKCS#11 token communication.
"""

import shutil
from pathlib import Path

from loguru import logger


class NSSChecker:
    """
    Checks NSS database configuration status.

    Verifies that the NSS database exists and contains
    the required files for PKCS#11 token operations.
    """

    # Required NSS database files (SQLite format)
    REQUIRED_FILES = ["cert9.db", "key4.db"]

    # Legacy BerkeleyDB format files (older systems)
    LEGACY_FILES = ["cert8.db", "key3.db", "secmod.db"]

    def __init__(self, nss_path: Path | None = None):
        """
        Initialize NSS checker.

        Args:
            nss_path: Path to NSS database (default: ~/.nss)
        """
        self.nss_path = nss_path or Path.home() / ".nss"

    def is_configured(self) -> bool:
        """
        Check if NSS database exists and is initialized.

        Returns:
            True if NSS is properly configured
        """
        configured, _ = self.get_status()
        return configured

    def get_status(self) -> tuple[bool, str]:
        """
        Get detailed configuration status.

        Returns:
            Tuple of (is_configured, reason_if_not)
        """
        # Check directory exists
        if not self.nss_path.exists():
            logger.debug(f"NSS directory does not exist: {self.nss_path}")
            return False, "NSS database directory does not exist"

        if not self.nss_path.is_dir():
            logger.warning(f"NSS path is not a directory: {self.nss_path}")
            return False, "NSS path exists but is not a directory"

        # Check for SQLite format (modern)
        has_modern = all((self.nss_path / f).exists() for f in self.REQUIRED_FILES)
        if has_modern:
            logger.debug("NSS database configured (SQLite format)")
            return True, ""

        # Check for legacy format
        has_legacy = all((self.nss_path / f).exists() for f in self.LEGACY_FILES)
        if has_legacy:
            logger.debug("NSS database configured (legacy BerkeleyDB format)")
            return True, ""

        # Directory exists but missing required files
        existing = [f for f in self.REQUIRED_FILES if (self.nss_path / f).exists()]
        if existing:
            missing = [f for f in self.REQUIRED_FILES if f not in existing]
            logger.warning(f"NSS database incomplete, missing: {missing}")
            return False, f"Missing NSS database files: {', '.join(missing)}"

        logger.debug("NSS directory exists but is empty or uninitialized")
        return False, "NSS database not initialized"

    def is_certutil_available(self) -> bool:
        """
        Check if certutil command is available in PATH.

        Returns:
            True if certutil is available
        """
        available = shutil.which("certutil") is not None
        if not available:
            logger.debug("certutil not found in PATH")
        return available

    def get_install_instructions(self) -> str:
        """
        Get distro-specific instructions for installing NSS tools.

        Returns:
            Multi-line string with installation commands
        """
        return (
            "Ubuntu/Debian:  sudo apt install libnss3-tools\n"
            "Fedora/RHEL:    sudo dnf install nss-tools\n"
            "Arch Linux:     sudo pacman -S nss\n"
            "openSUSE:       sudo zypper install mozilla-nss-tools"
        )

    def get_nss_path(self) -> Path:
        """Get the NSS database path."""
        return self.nss_path

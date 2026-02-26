"""
nss_setup.py - NSS database setup and initialization

Author: Homero Thompson del Lago del Terror

Creates and initializes NSS database for PKCS#11 token
communication using certutil.
"""

import shutil
import subprocess  # nosec B404 - subprocess used safely with fixed certutil command
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from .nss_checker import NSSChecker


@dataclass
class SetupResult:
    """Result of NSS setup operation."""

    success: bool
    message: str
    error_type: str | None = None  # "not_found", "permission", "timeout", "unknown"


class NSSSetup:
    """
    Creates and initializes NSS database.

    Uses certutil to create an empty NSS database with no password,
    suitable for PKCS#11 token operations.
    """

    # Timeout for certutil command (seconds)
    TIMEOUT_SECONDS = 30

    def __init__(self, nss_path: Path | None = None):
        """
        Initialize NSS setup.

        Args:
            nss_path: Path to NSS database (default: ~/.nss)
        """
        self.nss_path = nss_path or Path.home() / ".nss"
        self.checker = NSSChecker(self.nss_path)

    def create_database(self) -> SetupResult:
        """
        Create NSS database using certutil.

        Executes: certutil -N --empty-password -d sql:~/.nss

        Returns:
            SetupResult with success status and message
        """
        # Check if certutil is available
        if not self.checker.is_certutil_available():
            logger.error("certutil not found in PATH")
            return SetupResult(
                success=False,
                message=(
                    "certutil not found. Please install NSS tools:\n\n"
                    f"{self.checker.get_install_instructions()}"
                ),
                error_type="not_found",
            )

        # Create directory if it doesn't exist
        try:
            self.nss_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"NSS directory ensured: {self.nss_path}")
        except PermissionError as e:
            logger.error(f"Permission denied creating directory: {e}")
            return SetupResult(
                success=False,
                message=f"Permission denied creating directory: {self.nss_path}",
                error_type="permission",
            )
        except OSError as e:
            logger.error(f"Error creating directory: {e}")
            return SetupResult(
                success=False,
                message=f"Error creating directory: {e}",
                error_type="unknown",
            )

        # Run certutil to create database
        try:
            result = self._run_certutil()
        except subprocess.TimeoutExpired:
            logger.error("certutil command timed out")
            return SetupResult(
                success=False,
                message="Setup timed out. Please try again.",
                error_type="timeout",
            )

        # Check result
        if result.returncode == 0:
            logger.info("NSS database created successfully")
            return SetupResult(
                success=True,
                message="Security database created successfully!",
            )

        # Handle specific errors
        stderr = result.stderr.lower() if result.stderr else ""

        if "already exists" in stderr or "database already exists" in stderr:
            # Database already exists - treat as success
            logger.info("NSS database already exists")
            return SetupResult(
                success=True,
                message="Security database already configured.",
            )

        if "permission" in stderr or "access denied" in stderr:
            logger.error(f"Permission error: {result.stderr}")
            return SetupResult(
                success=False,
                message=f"Permission denied: {result.stderr}",
                error_type="permission",
            )

        # Unknown error
        logger.error(f"certutil failed: {result.stderr}")
        return SetupResult(
            success=False,
            message=f"Setup failed: {result.stderr or 'Unknown error'}",
            error_type="unknown",
        )

    def _run_certutil(self) -> subprocess.CompletedProcess:
        """
        Run certutil command to create NSS database.

        Returns:
            CompletedProcess with result
        """
        certutil_path = shutil.which("certutil")
        if certutil_path is None:
            raise FileNotFoundError("certutil not found in PATH")

        cmd = [
            certutil_path,
            "-N",
            "--empty-password",
            "-d",
            f"sql:{self.nss_path}",
        ]

        logger.info(f"Executing: {' '.join(cmd)}")

        return subprocess.run(  # nosec B603 - cmd is hardcoded, no user input
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT_SECONDS,
        )

    def verify_setup(self) -> bool:
        """
        Verify that NSS database was created successfully.

        Returns:
            True if database is properly configured
        """
        return self.checker.is_configured()

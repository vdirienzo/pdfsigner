"""
totp_provider.py - TOTP (Time-based One-Time Password) provider

Implements RFC 6238 TOTP for MFA using pyotp library.
Compatible with Google Authenticator and other TOTP apps.
"""

import io
from dataclasses import dataclass
from typing import Any

import pyotp
import qrcode
from loguru import logger


@dataclass
class TOTPConfig:
    """Configuration for TOTP generation."""

    digits: int = 6
    interval: int = 30  # seconds
    algorithm: str = "SHA1"  # For Google Authenticator compatibility
    issuer: str = "PDFSigner"

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.digits not in (6, 7, 8):
            raise ValueError("TOTP digits must be 6, 7, or 8")
        if self.interval not in (30, 60):
            raise ValueError("TOTP interval must be 30 or 60 seconds")
        if self.algorithm not in ("SHA1", "SHA256", "SHA512"):
            raise ValueError("Algorithm must be SHA1, SHA256, or SHA512")


class TOTPProvider:
    """
    TOTP provider for multi-factor authentication.

    Uses pyotp library to generate and verify TOTP codes.
    Compatible with Google Authenticator, Authy, and other TOTP apps.
    """

    def __init__(self, config: TOTPConfig | None = None) -> None:
        """
        Initialize TOTP provider.

        Args:
            config: TOTP configuration (default: 6 digits, 30s, SHA1)
        """
        self.config = config or TOTPConfig()

    def generate_secret(self) -> str:
        """
        Generate a random Base32-encoded secret key.

        Returns:
            Base32-encoded secret (e.g., "JBSWY3DPEHPK3PXP")
        """
        return pyotp.random_base32()

    def generate_totp(self, secret: str, timestamp: int | None = None) -> str:
        """
        Generate TOTP code for given secret.

        Args:
            secret: Base32-encoded secret key
            timestamp: Unix timestamp (default: current time)

        Returns:
            TOTP code (e.g., "123456")

        Raises:
            ValueError: If secret is invalid
        """
        try:
            totp = pyotp.TOTP(
                secret,
                digits=self.config.digits,
                interval=self.config.interval,
                digest=self._get_digest(),
            )
            if timestamp is not None:
                return totp.at(timestamp)
            return totp.now()
        except Exception as e:
            logger.error(f"Failed to generate TOTP: {e}")
            raise ValueError(f"Invalid TOTP secret: {e}") from e

    def verify_totp(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verify TOTP code against secret.

        Args:
            secret: Base32-encoded secret key
            code: TOTP code to verify (e.g., "123456")
            window: Number of intervals to check (±window * interval seconds)
                   Default: 1 (checks current, previous, and next interval)

        Returns:
            True if code is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(
                secret,
                digits=self.config.digits,
                interval=self.config.interval,
                digest=self._get_digest(),
            )
            # pyotp.verify() returns True or False
            return totp.verify(code, valid_window=window)
        except Exception as e:
            logger.warning(f"TOTP verification failed: {e}")
            return False

    def get_provisioning_uri(self, secret: str, account_name: str) -> str:
        """
        Generate provisioning URI for QR code.

        Args:
            secret: Base32-encoded secret key
            account_name: User account name (e.g., "user@example.com")

        Returns:
            otpauth:// URI for QR code generation

        Example:
            otpauth://totp/PDFSigner:user@example.com?secret=JBSWY3DP...&issuer=PDFSigner
        """
        totp = pyotp.TOTP(
            secret,
            digits=self.config.digits,
            interval=self.config.interval,
            digest=self._get_digest(),
        )
        return totp.provisioning_uri(name=account_name, issuer_name=self.config.issuer)

    def generate_qr_code(self, secret: str, account_name: str) -> bytes:
        """
        Generate QR code image for TOTP setup.

        Args:
            secret: Base32-encoded secret key
            account_name: User account name

        Returns:
            PNG image bytes

        Raises:
            ValueError: If QR code generation fails
        """
        try:
            uri = self.get_provisioning_uri(secret, account_name)

            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(uri)
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to PNG bytes
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")  # type: ignore[call-arg]
            return buffer.getvalue()

        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            raise ValueError(f"QR code generation failed: {e}") from e

    def _get_digest(self) -> Any:
        """
        Get hashlib digest for pyotp.

        Returns:
            Digest function (hashlib.sha1, sha256, or sha512)
        """
        import hashlib

        if self.config.algorithm == "SHA1":
            return hashlib.sha1
        elif self.config.algorithm == "SHA256":
            return hashlib.sha256
        elif self.config.algorithm == "SHA512":
            return hashlib.sha512
        else:
            # Default to SHA1 for compatibility
            return hashlib.sha1


# Public exports
__all__ = ["TOTPProvider", "TOTPConfig"]

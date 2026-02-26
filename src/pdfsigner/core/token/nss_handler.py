"""
nss_handler.py - NSS/PKCS#11 connection handler

Author: Homero Thompson del Lago del Terror

Manages communication with USB cryptographic tokens
through the NSS database using python-pkcs11.
"""

from dataclasses import dataclass
from pathlib import Path

import pkcs11
import pkcs11.exceptions
from cryptography import x509
from loguru import logger
from pkcs11 import ObjectClass, lib

from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit import log_token_event
from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    NSSConfigError,
    TokenAuthenticationError,
    TokenNotFoundError,
)


@dataclass
class CertificateInfo:
    """Information about a certificate in the token."""

    label: str
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    can_sign: bool
    pkcs11_id: bytes


class NSSHandler:
    """
    NSS/PKCS#11 connection handler.

    Manages communication with USB cryptographic tokens through NSS.
    Compatible with any PKCS#11 compliant token.
    """

    def __init__(self, nss_db_path: Path | None = None):
        """
        Initialize NSS handler.

        Args:
            nss_db_path: Path to NSS database (default: from settings)
        """
        settings = get_settings()
        self.nss_db_path = nss_db_path or settings.nss_db_path
        self._lib: pkcs11.lib | None = None
        self._token: pkcs11.Token | None = None
        self._session: pkcs11.Session | None = None

    def get_session(self) -> "pkcs11.Session":
        """
        Get the authenticated PKCS#11 session.

        Returns:
            Active PKCS#11 session

        Raises:
            RuntimeError: If no session is active (not logged in)
        """
        if self._session is None:
            raise RuntimeError("No active PKCS#11 session. Call login() first.")
        return self._session

    def _find_pkcs11_lib(self) -> str:
        """
        Find available PKCS#11 library.

        Searches for libraries in priority order defined in pkcs11_libs.py.

        Returns:
            Path to found library

        Raises:
            TokenNotFoundError: If no library found
        """
        from pdfsigner.core.token.pkcs11_libs import PKCS11_LIB_GROUPS

        for token_name, paths in PKCS11_LIB_GROUPS:
            for path in paths:
                if Path(path).exists():
                    logger.info(f"Found {token_name} PKCS#11 library: {path}")
                    return path

        raise TokenNotFoundError(
            "No PKCS#11 library found. Supported tokens: SafeNet, YubiKey, "
            "Nitrokey, OpenSC, Feitian, SoftHSM, nCipher. "
            "Verify that your token driver is installed."
        )

    def initialize(self) -> None:
        """
        Initialize PKCS#11 connection.

        Raises:
            NSSConfigError: If NSS configuration is invalid
            TokenNotFoundError: If token not detected
        """
        if not self.nss_db_path.exists():
            raise NSSConfigError(str(self.nss_db_path))

        lib_path = self._find_pkcs11_lib()

        try:
            self._lib = lib(lib_path)
            logger.info(f"PKCS#11 library loaded: {lib_path}")
        except pkcs11.exceptions.PKCS11Error as e:
            raise TokenNotFoundError(f"PKCS#11 library error: {e}") from e
        except OSError as e:
            raise TokenNotFoundError(f"Cannot load PKCS#11 library '{lib_path}': {e}") from e

    def get_available_tokens(self) -> list[str]:
        """
        List available tokens.

        Returns:
            List of token names
        """
        if self._lib is None:
            self.initialize()

        if self._lib is None:
            raise RuntimeError("NSSHandler not initialized. Call initialize() first.")
        tokens = []
        for slot in self._lib.get_slots(token_present=True):
            token = slot.get_token()
            tokens.append(token.label.strip())
            logger.debug(f"Token found: {token.label}")

        return tokens

    def connect_token(self, token_label: str | None = None) -> None:
        """
        Connect to a specific token.

        Args:
            token_label: Token label (None = first available token)

        Raises:
            TokenNotFoundError: If token not found
        """
        if self._lib is None:
            self.initialize()

        if self._lib is None:
            raise RuntimeError("NSSHandler not initialized. Call initialize() first.")
        for slot in self._lib.get_slots(token_present=True):
            token = slot.get_token()
            if token_label is None or token.label.strip() == token_label:
                self._token = token
                logger.info(f"Connected to token: {token.label.strip()}")
                return

        raise TokenNotFoundError(
            f"Token '{token_label}' not found" if token_label else "No tokens available"
        )

    def authenticate(self, pin: str) -> None:
        """
        Authenticate with token using PIN.

        Args:
            pin: Token PIN

        Raises:
            TokenAuthenticationError: If PIN is incorrect
        """
        if self._token is None:
            raise TokenNotFoundError("You must connect a token first")

        token_label = self._token.label.strip()

        try:
            self._session = self._token.open(user_pin=pin)
            logger.info("Successful authentication with token")

            # Log successful authentication
            log_token_event(
                event_type=AuditEventType.TOKEN_LOGIN,
                success=True,
                details={"token_label": token_label},
            )
        except pkcs11.exceptions.PinIncorrect:
            log_token_event(
                event_type=AuditEventType.TOKEN_LOGIN,
                success=False,
                error="Incorrect PIN",
                details={"token_label": token_label},
            )
            raise TokenAuthenticationError("Incorrect PIN")
        except pkcs11.exceptions.PinLocked:
            log_token_event(
                event_type=AuditEventType.TOKEN_LOGIN,
                success=False,
                error="Token locked due to too many attempts",
                details={"token_label": token_label},
            )
            raise TokenAuthenticationError("Token locked due to too many attempts")
        except pkcs11.exceptions.PKCS11Error as e:
            log_token_event(
                event_type=AuditEventType.TOKEN_LOGIN,
                success=False,
                error=f"PKCS#11 authentication error: {e}",
                details={"token_label": token_label},
            )
            raise TokenAuthenticationError(f"PKCS#11 authentication error: {e}") from e

    def list_certificates(self) -> list[CertificateInfo]:
        """
        List available certificates in the token.

        Returns:
            List of certificate information
        """
        if self._session is None:
            raise TokenAuthenticationError("You must authenticate first")

        certs = []
        for obj in self._session.get_objects({pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE}):
            try:
                cert_der = obj[pkcs11.Attribute.VALUE]
                cert = x509.load_der_x509_certificate(cert_der)

                # Check if it has key usage for signing
                can_sign = False
                try:
                    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    # content_commitment is the RFC 5280 name for non_repudiation
                    can_sign = (
                        key_usage.value.digital_signature or key_usage.value.content_commitment
                    )
                except x509.ExtensionNotFound:
                    can_sign = True  # If no extension, assume it can sign

                cert_info = CertificateInfo(
                    label=obj[pkcs11.Attribute.LABEL],
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    serial_number=format(cert.serial_number, "x"),
                    not_before=cert.not_valid_before_utc.isoformat(),
                    not_after=cert.not_valid_after_utc.isoformat(),
                    can_sign=can_sign,
                    pkcs11_id=obj[pkcs11.Attribute.ID],
                )
                certs.append(cert_info)
                logger.debug(f"Certificate found: {cert_info.label}")

            except pkcs11.exceptions.PKCS11Error as e:
                logger.warning(f"PKCS#11 error reading certificate: {e}")
                continue
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing certificate data: {e}")
                continue

        return certs

    def get_signing_key_and_cert(
        self, cert_id: bytes | None = None
    ) -> tuple[pkcs11.PrivateKey, bytes]:
        """
        Get private key and certificate for signing.

        Args:
            cert_id: Certificate ID (None = first signing certificate)

        Returns:
            Tuple (private_key, certificate_der)

        Raises:
            CertificateNotFoundError: If signing certificate not found
        """
        if self._session is None:
            raise TokenAuthenticationError("You must authenticate first")

        # Search for certificates that can sign
        certs = [c for c in self.list_certificates() if c.can_sign]
        if not certs:
            raise CertificateNotFoundError()

        # Select certificate
        selected = None
        if cert_id:
            selected = next((c for c in certs if c.pkcs11_id == cert_id), None)
        if selected is None:
            selected = certs[0]

        # Get associated private key
        try:
            priv_key = self._session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                id=selected.pkcs11_id,
            )
        except pkcs11.exceptions.NoSuchKey:
            raise CertificateNotFoundError(
                f"Private key not found for certificate '{selected.label}'"
            )
        except pkcs11.exceptions.PKCS11Error as e:
            raise CertificateNotFoundError(f"PKCS#11 error accessing private key: {e}") from e

        # Get DER certificate
        cert_obj = list(
            self._session.get_objects(
                {
                    pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE,
                    pkcs11.Attribute.ID: selected.pkcs11_id,
                }
            )
        )[0]
        cert_der = cert_obj[pkcs11.Attribute.VALUE]

        return priv_key, cert_der

    def close(self) -> None:
        """Close token session."""
        if self._session is not None:
            # Get token label before closing
            token_label = self._token.label.strip() if self._token else "Unknown"

            try:
                self._session.close()

                # Log successful logout
                log_token_event(
                    event_type=AuditEventType.TOKEN_LOGOUT,
                    success=True,
                    details={"token_label": token_label},
                )
            except pkcs11.exceptions.PKCS11Error as e:
                logger.debug(f"Error closing PKCS#11 session (non-fatal): {e}")
            self._session = None
        self._token = None
        logger.debug("Token session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

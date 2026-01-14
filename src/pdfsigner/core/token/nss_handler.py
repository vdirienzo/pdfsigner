"""
nss_handler.py - NSS/PKCS#11 connection handler

Author: Homero Thompson del Lago del Terror

Manages communication with USB cryptographic tokens
through the NSS database using python-pkcs11.

Supported tokens:
- SafeNet/Thales eToken 5110, 5300
- Gemalto tokens
- YubiKey (PIV mode)
- Nitrokey Pro/HSM
- OpenSC compatible tokens
- Feitian ePass
- Luna HSM
- SoftHSM (for testing)
- Any PKCS#11 compatible token
"""

from dataclasses import dataclass
from pathlib import Path

import pkcs11
from cryptography import x509
from loguru import logger
from pkcs11 import ObjectClass, lib

from pdfsigner.config.settings import get_settings
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

    # ==========================================================================
    # PKCS#11 Library Paths - Ordered by priority (first found is used)
    # ==========================================================================

    # SafeNet/Thales eToken (5110, 5300, etc.)
    SAFENET_LIB_PATHS = [
        "/usr/lib/libeToken.so",
        "/usr/lib/x86_64-linux-gnu/libeToken.so",
        "/usr/lib64/libeToken.so",
        "/opt/safenet/lunaclient/lib/libCryptoki2_64.so",  # Luna HSM
        "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
    ]

    # YubiKey (PIV mode)
    YUBIKEY_LIB_PATHS = [
        "/usr/lib/x86_64-linux-gnu/libykcs11.so",
        "/usr/lib/libykcs11.so",
        "/usr/lib64/libykcs11.so",
        "/usr/local/lib/libykcs11.so",
    ]

    # Nitrokey Pro/HSM
    NITROKEY_LIB_PATHS = [
        "/usr/lib/x86_64-linux-gnu/libnethsm.so",
        "/usr/lib/libnethsm.so",
        "/usr/lib/x86_64-linux-gnu/libnitrokey.so",
        "/usr/lib/libnitrokey.so",
    ]

    # OpenSC (generic smart cards)
    OPENSC_LIB_PATHS = [
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    ]

    # Feitian ePass
    FEITIAN_LIB_PATHS = [
        "/usr/lib/libcastle.so",
        "/usr/lib/x86_64-linux-gnu/libcastle.so",
        "/usr/lib/libftsafe-p11.so",
    ]

    # SoftHSM (software HSM for testing)
    SOFTHSM_LIB_PATHS = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
    ]

    # nCipher/Entrust HSM
    NCIPHER_LIB_PATHS = [
        "/opt/nfast/toolkits/pkcs11/libcknfast.so",
        "/usr/lib/libcknfast.so",
    ]

    # Generic NSS libraries (fallback)
    NSS_LIB_PATHS = [
        "/usr/lib/x86_64-linux-gnu/libnssckbi.so",
        "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
        "/usr/lib/libnssckbi.so",
        "/usr/lib/libsoftokn3.so",
        "/usr/lib64/libnssckbi.so",
        "/usr/lib64/libsoftokn3.so",
    ]

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

    def _find_pkcs11_lib(self) -> str:
        """
        Find available PKCS#11 library.

        Searches for libraries in priority order:
        1. SafeNet/Thales (eToken, Luna)
        2. YubiKey
        3. Nitrokey
        4. OpenSC (generic smart cards)
        5. Feitian
        6. SoftHSM (testing)
        7. nCipher
        8. Generic NSS (fallback)

        Returns:
            Path to found library

        Raises:
            TokenNotFoundError: If no library found
        """
        # Define search order with descriptive names
        lib_groups = [
            ("SafeNet/Thales", self.SAFENET_LIB_PATHS),
            ("YubiKey", self.YUBIKEY_LIB_PATHS),
            ("Nitrokey", self.NITROKEY_LIB_PATHS),
            ("OpenSC", self.OPENSC_LIB_PATHS),
            ("Feitian", self.FEITIAN_LIB_PATHS),
            ("SoftHSM", self.SOFTHSM_LIB_PATHS),
            ("nCipher", self.NCIPHER_LIB_PATHS),
            ("NSS", self.NSS_LIB_PATHS),
        ]

        for token_name, paths in lib_groups:
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
        except Exception as e:
            raise TokenNotFoundError(f"Error loading PKCS#11 library: {e}")

    def get_available_tokens(self) -> list[str]:
        """
        List available tokens.

        Returns:
            List of token names
        """
        if self._lib is None:
            self.initialize()

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

        try:
            self._session = self._token.open(user_pin=pin)
            logger.info("Successful authentication with token")
        except pkcs11.exceptions.PinIncorrect:
            raise TokenAuthenticationError("Incorrect PIN")
        except pkcs11.exceptions.PinLocked:
            raise TokenAuthenticationError("Token locked due to too many attempts")
        except Exception as e:
            raise TokenAuthenticationError(f"Authentication error: {e}")

    def list_certificates(self) -> list[CertificateInfo]:
        """
        List available certificates in the token.

        Returns:
            List of certificate information
        """
        if self._session is None:
            raise TokenAuthenticationError("You must authenticate first")

        certs = []
        for obj in self._session.get_objects({ObjectClass.CERTIFICATE}):
            try:
                cert_der = obj[pkcs11.Attribute.VALUE]
                cert = x509.load_der_x509_certificate(cert_der)

                # Check if it has key usage for signing
                can_sign = False
                try:
                    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    can_sign = key_usage.value.digital_signature or key_usage.value.non_repudiation
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

            except Exception as e:
                logger.warning(f"Error reading certificate: {e}")
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
        except Exception as e:
            raise CertificateNotFoundError(f"Private key not found: {e}")

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
            try:
                self._session.close()
            except Exception:
                pass
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

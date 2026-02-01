"""
Certificate service for API.

Provides high-level certificate operations wrapping the core NSSHandler,
converting between core and API data models.
"""

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from loguru import logger

from pdfsigner.api.schemas.certificates import CertificateChain, CertificateInfo
from pdfsigner.config.settings import get_settings
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    NSSConfigError,
    TokenNotFoundError,
)


class CertificateService:
    """
    Certificate management service for API.

    Wraps NSSHandler to provide certificate listing, inspection,
    and chain validation functionality for API endpoints.
    """

    def __init__(self, nss_db_path: Path | None = None):
        """
        Initialize certificate service.

        Args:
            nss_db_path: Path to NSS database (default: from settings)
        """
        settings = get_settings()
        self.nss_db_path = nss_db_path or settings.nss_db_path
        self._handler: NSSHandler | None = None

    def _get_handler(self) -> NSSHandler:
        """
        Get or create NSSHandler instance.

        Returns:
            Initialized NSSHandler

        Raises:
            NSSConfigError: If NSS database not configured or invalid
            TokenNotFoundError: If no PKCS#11 library found
        """
        if self._handler is None:
            if not self.nss_db_path.exists():
                raise NSSConfigError(
                    f"NSS database not found at {self.nss_db_path}. "
                    "Please configure NSS database path in settings."
                )

            self._handler = NSSHandler(nss_db_path=self.nss_db_path)
            self._handler.initialize()

        return self._handler

    def _convert_cert_to_api_schema(self, cert_der: bytes, cert_label: str = "") -> CertificateInfo:
        """
        Convert X.509 certificate (DER) to API schema.

        Args:
            cert_der: Certificate in DER format
            cert_label: Optional label/nickname for the certificate

        Returns:
            CertificateInfo schema for API response
        """
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Calculate expiry information
        now = datetime.now(UTC)
        not_after = cert.not_valid_after_utc
        days_until_expiry = (not_after - now).days
        is_expired = now > not_after

        # Extract key usage
        key_usage_list: list[str] = []
        try:
            key_usage_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
            ku = key_usage_ext.value

            if ku.digital_signature:
                key_usage_list.append("digitalSignature")
            if ku.content_commitment:
                key_usage_list.append("contentCommitment")
            if ku.key_encipherment:
                key_usage_list.append("keyEncipherment")
            if ku.data_encipherment:
                key_usage_list.append("dataEncipherment")
            if ku.key_agreement:
                key_usage_list.append("keyAgreement")
            if ku.key_cert_sign:
                key_usage_list.append("keyCertSign")
            if ku.crl_sign:
                key_usage_list.append("crlSign")

        except x509.ExtensionNotFound:
            logger.debug(f"Certificate '{cert_label}' has no key usage extension")

        # Determine if CA certificate
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            # No basic constraints = not a CA
            pass

        # Generate certificate ID (SHA-256 fingerprint)
        from cryptography.hazmat.primitives import hashes

        cert_id = cert.fingerprint(hashes.SHA256()).hex()

        return CertificateInfo(
            id=cert_id,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            key_usage=key_usage_list,
            is_ca=is_ca,
        )

    def list_certificates(
        self, token_label: str | None = None, pin: str | None = None
    ) -> list[CertificateInfo]:
        """
        List all available certificates in NSS database or token.

        Args:
            token_label: Optional token label to connect to
            pin: Optional PIN for token authentication

        Returns:
            List of CertificateInfo objects

        Raises:
            NSSConfigError: If NSS database not configured
            TokenNotFoundError: If specified token not found
            TokenAuthenticationError: If PIN provided but incorrect
        """
        handler = self._get_handler()

        try:
            # If token_label provided, connect to specific token
            if token_label:
                handler.connect_token(token_label)

                # If PIN provided, authenticate
                if pin:
                    handler.authenticate(pin)
                else:
                    # Try to list without authentication (may fail for some tokens)
                    logger.debug("No PIN provided, attempting to list without authentication")
            else:
                # Try to connect to first available token
                try:
                    handler.connect_token(None)
                except TokenNotFoundError:
                    logger.info("No token connected, returning empty certificate list")
                    return []

            # List certificates from token (requires authentication for most tokens)
            if pin:
                cert_infos = handler.list_certificates()
            else:
                # Without PIN, we can't list from token
                logger.info("PIN required to list certificates from token")
                return []

            # Convert to API schema
            api_certs = []
            for cert_info in cert_infos:
                # Get the actual certificate DER data
                try:
                    _, cert_der = handler.get_signing_key_and_cert(cert_info.pkcs11_id)
                    api_cert = self._convert_cert_to_api_schema(cert_der, cert_info.label)
                    api_certs.append(api_cert)
                except CertificateNotFoundError:
                    logger.warning(f"Could not retrieve certificate '{cert_info.label}'")
                    continue

            return api_certs

        finally:
            handler.close()

    def get_certificate(
        self, cert_id: str, token_label: str | None = None, pin: str | None = None
    ) -> CertificateInfo:
        """
        Get specific certificate by ID.

        Args:
            cert_id: Certificate ID (SHA-256 fingerprint hex)
            token_label: Optional token label
            pin: Optional PIN for authentication

        Returns:
            CertificateInfo object

        Raises:
            CertificateNotFoundError: If certificate not found
            TokenAuthenticationError: If authentication fails
        """
        # List all certificates and find matching one
        certs = self.list_certificates(token_label=token_label, pin=pin)

        for cert in certs:
            if cert.id == cert_id:
                return cert

        raise CertificateNotFoundError(f"Certificate with ID '{cert_id}' not found")

    def get_certificate_chain(
        self, cert_id: str, token_label: str | None = None, pin: str | None = None
    ) -> CertificateChain:
        """
        Get certificate chain for a specific certificate.

        Args:
            cert_id: Certificate ID (SHA-256 fingerprint hex)
            token_label: Optional token label
            pin: Optional PIN for authentication

        Returns:
            CertificateChain with certificates from leaf to root

        Raises:
            CertificateNotFoundError: If certificate not found
        """
        # Get the target certificate
        cert = self.get_certificate(cert_id, token_label=token_label, pin=pin)

        # Get all available certificates to build chain
        all_certs = self.list_certificates(token_label=token_label, pin=pin)

        # Build chain from leaf to root
        chain: list[CertificateInfo] = [cert]
        validation_errors: list[str] = []
        current_cert = cert

        # Try to build chain by matching issuer to subject
        max_depth = 10  # Prevent infinite loops
        for _ in range(max_depth):
            # Check if current cert is self-signed (root CA)
            if current_cert.subject == current_cert.issuer:
                break

            # Find issuer certificate
            issuer_found = False
            for candidate in all_certs:
                if candidate.subject == current_cert.issuer:
                    chain.append(candidate)
                    current_cert = candidate
                    issuer_found = True
                    break

            if not issuer_found:
                validation_errors.append(
                    f"Issuer certificate not found for: {current_cert.subject}"
                )
                break

        # Check if chain is complete (reaches self-signed root)
        is_complete = len(chain) > 0 and chain[-1].subject == chain[-1].issuer

        if not is_complete and not validation_errors:
            validation_errors.append("Certificate chain does not reach a trusted root CA")

        # Check for expired certificates in chain
        for cert_in_chain in chain:
            if cert_in_chain.is_expired:
                validation_errors.append(
                    f"Certificate expired: {cert_in_chain.subject} "
                    f"(expired {abs(cert_in_chain.days_until_expiry)} days ago)"
                )

        return CertificateChain(
            certificates=chain,
            is_complete=is_complete,
            validation_errors=validation_errors,
        )

    def get_available_tokens(self) -> list[str]:
        """
        Get list of available PKCS#11 tokens.

        Returns:
            List of token labels

        Raises:
            TokenNotFoundError: If no PKCS#11 library found
        """
        handler = self._get_handler()

        try:
            return handler.get_available_tokens()
        finally:
            handler.close()

    def close(self) -> None:
        """Close any open handler sessions."""
        if self._handler is not None:
            self._handler.close()
            self._handler = None


# --- Public Exports ---

__all__ = ["CertificateService"]

"""
trust_store.py - Certificate trust store management

Author: Homero Thompson del Lago del Terror

Manages trusted Root CA certificates from system store and
custom CA additions for certificate chain validation.

Cross-platform support: Linux, macOS, Windows.
"""

from pathlib import Path

from cryptography import x509
from loguru import logger

from pdfsigner.core.platform import get_trust_store_paths


class TrustStore:
    """
    Manages trusted Root CA certificates.

    Loads system Root CAs and allows adding custom CAs for
    certificate chain validation.

    Cross-platform: Automatically detects CA paths for Linux, macOS, Windows.
    """

    def __init__(self):
        """Initialize trust store."""
        self._trusted_certs: dict[bytes, x509.Certificate] = {}
        self._custom_certs: list[x509.Certificate] = []
        # Get platform-specific CA paths
        self._system_ca_paths = get_trust_store_paths()

    @property
    def SYSTEM_CA_PATHS(self) -> list[str]:
        """Get system CA paths (for backward compatibility)."""
        return [str(p) for p in self._system_ca_paths]

    def load_system_cas(self) -> list[x509.Certificate]:
        """
        Load Root CA certificates from system trust store.

        Returns:
            List of loaded certificates

        Raises:
            FileNotFoundError: If no system CA bundle found
        """
        for ca_path in self._system_ca_paths:
            if ca_path.exists():
                logger.info(f"Loading system CAs from {ca_path}")
                certs = self._load_pem_bundle(str(ca_path))
                logger.info(f"Loaded {len(certs)} system Root CAs")
                return certs

        paths_str = ", ".join(str(p) for p in self._system_ca_paths)
        raise FileNotFoundError(f"System CA bundle not found in: {paths_str}")

    def _load_pem_bundle(self, path: str) -> list[x509.Certificate]:
        """
        Load PEM certificate bundle from file.

        Args:
            path: Path to PEM bundle file

        Returns:
            List of parsed certificates
        """
        certs = []
        try:
            with open(path, "rb") as f:
                pem_data = f.read()

            # Split PEM bundle into individual certificates
            pem_blocks = pem_data.split(b"-----BEGIN CERTIFICATE-----")

            for block in pem_blocks[1:]:  # Skip first empty split
                if b"-----END CERTIFICATE-----" not in block:
                    continue

                pem_cert = (
                    b"-----BEGIN CERTIFICATE-----"
                    + block.split(b"-----END CERTIFICATE-----")[0]
                    + b"-----END CERTIFICATE-----"
                )

                try:
                    cert = x509.load_pem_x509_certificate(pem_cert)
                    # Index by subject for fast lookup
                    subject_der = cert.subject.public_bytes()
                    self._trusted_certs[subject_der] = cert
                    certs.append(cert)
                except Exception as e:
                    logger.debug(f"Failed to parse certificate in bundle: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to load CA bundle from {path}: {e}")
            raise

        return certs

    def add_custom_ca(self, cert_path: str) -> None:
        """
        Add custom Root CA certificate to trust store.

        Args:
            cert_path: Path to PEM certificate file

        Raises:
            FileNotFoundError: If certificate file not found
            ValueError: If certificate cannot be parsed
        """
        path = Path(cert_path)
        if not path.exists():
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")

        try:
            with open(cert_path, "rb") as f:
                pem_data = f.read()

            cert = x509.load_pem_x509_certificate(pem_data)

            # Add to trusted certs
            subject_der = cert.subject.public_bytes()
            self._trusted_certs[subject_der] = cert
            self._custom_certs.append(cert)

            logger.info(f"Added custom CA: {cert.subject.rfc4514_string()}")

        except Exception as e:
            raise ValueError(f"Failed to load certificate from {cert_path}: {e}") from e

    def is_trusted(self, cert: x509.Certificate) -> bool:
        """
        Check if certificate is in trust store.

        Args:
            cert: Certificate to check

        Returns:
            True if certificate is trusted
        """
        subject_der = cert.subject.public_bytes()
        return subject_der in self._trusted_certs

    def get_issuer(self, cert: x509.Certificate) -> x509.Certificate | None:
        """
        Find issuer certificate in trust store.

        Args:
            cert: Certificate whose issuer to find

        Returns:
            Issuer certificate if found, None otherwise
        """
        # Look up issuer by name
        issuer_der = cert.issuer.public_bytes()

        if issuer_der in self._trusted_certs:
            return self._trusted_certs[issuer_der]

        return None

    def get_certificate_by_subject(self, subject_der: bytes) -> x509.Certificate | None:
        """
        Get certificate by DER-encoded subject.

        Args:
            subject_der: DER-encoded subject name

        Returns:
            Certificate if found, None otherwise
        """
        return self._trusted_certs.get(subject_der)

    @property
    def trusted_count(self) -> int:
        """Get count of trusted certificates."""
        return len(self._trusted_certs)

    @property
    def custom_count(self) -> int:
        """Get count of custom CA certificates."""
        return len(self._custom_certs)

    def clear_custom_cas(self) -> None:
        """Remove all custom CA certificates from trust store."""
        for cert in self._custom_certs:
            subject_der = cert.subject.public_bytes()
            self._trusted_certs.pop(subject_der, None)

        self._custom_certs.clear()
        logger.info("Cleared all custom CA certificates")

"""
test_certificates.py - Shared test certificate fixtures

Provides session-scoped P12 certificate for CLI and integration tests.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def create_test_certificate():
    """Create a self-signed test certificate for signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "New York"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PDFSigner Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Signing Certificate"),
        ]
    )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    certificate = cert_builder.sign(private_key, hashes.SHA256())
    return private_key, certificate


@pytest.fixture(scope="session")
def test_cert_p12(tmp_path_factory) -> tuple[Path, str]:
    """
    Session-scoped fixture providing a P12 certificate file.

    Returns:
        Tuple of (p12_path, password)
    """
    cert_dir = tmp_path_factory.mktemp("certs")
    p12_path = cert_dir / "test_signer.p12"
    password = "test123"

    private_key, certificate = create_test_certificate()

    # Create P12/PKCS12 bundle
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"Test Signer",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    p12_path.write_bytes(p12_data)

    return p12_path, password


@pytest.fixture(scope="session")
def test_cert_pem(tmp_path_factory) -> tuple[Path, Path]:
    """
    Session-scoped fixture providing PEM certificate and key files.

    Returns:
        Tuple of (cert_path, key_path)
    """
    cert_dir = tmp_path_factory.mktemp("certs_pem")
    cert_path = cert_dir / "test_cert.pem"
    key_path = cert_dir / "test_key.pem"

    private_key, certificate = create_test_certificate()

    # Write certificate
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    # Write private key (unencrypted for testing)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return cert_path, key_path

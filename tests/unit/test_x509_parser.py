"""
test_x509_parser.py - Tests for X.509 certificate parser

Author: Homero Thompson del Lago del Terror

Tests certificate parsing functionality including all fields,
extensions, and edge cases.
"""

from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from pdfsigner.core.certificate import X509Details, X509Parser


@pytest.fixture
def sample_rsa_key():
    """Generate a sample RSA private key for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def basic_certificate(sample_rsa_key):
    """Create a basic self-signed certificate for testing."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sample_rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2025, 1, 1, tzinfo=UTC))
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
        .sign(sample_rsa_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def certificate_with_extensions(sample_rsa_key):
    """Create a certificate with multiple extensions."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
        ]
    )

    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Example CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sample_rsa_key.public_key())
        .serial_number(12345678901234567890)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2026, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                    x509.DNSName("www.example.com"),
                    x509.RFC822Name("admin@example.com"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(sample_rsa_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_basic_certificate(basic_certificate):
    """Test parsing a basic certificate with minimal fields."""
    details = X509Parser.parse(basic_certificate)

    assert isinstance(details, X509Details)
    assert details.subject_dn["CN"] == "Test User"
    assert details.subject_dn["O"] == "Test Corp"
    assert details.subject_dn["OU"] == "IT Department"
    assert details.subject_dn["C"] == "US"
    assert details.subject_dn["ST"] == "California"
    assert details.subject_dn["L"] == "San Francisco"


def test_parse_extracts_issuer(basic_certificate):
    """Test that issuer DN is correctly extracted."""
    details = X509Parser.parse(basic_certificate)

    assert details.issuer_dn["CN"] == "Test User"
    assert details.issuer_dn["O"] == "Test Corp"


def test_parse_extracts_serial_number(certificate_with_extensions):
    """Test that serial number is extracted in both hex and decimal."""
    details = X509Parser.parse(certificate_with_extensions)

    assert details.serial_number_decimal == "12345678901234567890"
    assert details.serial_number == format(12345678901234567890, "x").upper()


def test_parse_extracts_validity_dates(basic_certificate):
    """Test that validity dates are correctly extracted."""
    details = X509Parser.parse(basic_certificate)

    assert details.not_before == datetime(2024, 1, 1, tzinfo=UTC)
    assert details.not_after == datetime(2025, 1, 1, tzinfo=UTC)


def test_parse_extracts_key_usage(basic_certificate):
    """Test that key usage extension is parsed correctly."""
    details = X509Parser.parse(basic_certificate)

    assert "Digital Signature" in details.key_usage
    assert "Non-Repudiation" in details.key_usage
    assert len(details.key_usage) == 2


def test_parse_extracts_extended_key_usage(certificate_with_extensions):
    """Test that extended key usage is parsed correctly."""
    details = X509Parser.parse(certificate_with_extensions)

    assert "TLS Web Server Authentication" in details.extended_key_usage
    assert "TLS Web Client Authentication" in details.extended_key_usage


def test_parse_extracts_subject_alt_names(certificate_with_extensions):
    """Test that Subject Alternative Names are extracted."""
    details = X509Parser.parse(certificate_with_extensions)

    assert "DNS: example.com" in details.subject_alt_names
    assert "DNS: www.example.com" in details.subject_alt_names
    assert "Email: admin@example.com" in details.subject_alt_names


def test_parse_computes_thumbprints(basic_certificate):
    """Test that SHA-256 and SHA-1 thumbprints are computed."""
    details = X509Parser.parse(basic_certificate)

    # Thumbprints should be hex strings
    assert len(details.thumbprint_sha256) == 64  # SHA-256 = 32 bytes = 64 hex chars
    assert len(details.thumbprint_sha1) == 40  # SHA-1 = 20 bytes = 40 hex chars
    assert details.thumbprint_sha256.isupper()
    assert details.thumbprint_sha1.isupper()


def test_parse_extracts_public_key_info(basic_certificate):
    """Test that public key algorithm and size are extracted."""
    details = X509Parser.parse(basic_certificate)

    assert details.public_key_algorithm == "RSA"
    assert details.public_key_size == 2048
    assert "RSA" in details.signature_algorithm


def test_parse_extracts_all_extensions(certificate_with_extensions):
    """Test that all extensions are listed."""
    details = X509Parser.parse(certificate_with_extensions)

    assert len(details.all_extensions) > 0

    # Check that extension OIDs are present
    ext_oids = [ext["oid"] for ext in details.all_extensions]
    assert ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string in ext_oids
    assert ExtensionOID.KEY_USAGE.dotted_string in ext_oids
    assert ExtensionOID.EXTENDED_KEY_USAGE.dotted_string in ext_oids
    assert ExtensionOID.BASIC_CONSTRAINTS.dotted_string in ext_oids


def test_parse_handles_certificate_without_optional_extensions(sample_rsa_key):
    """Test parsing a minimal certificate without optional extensions."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Minimal Cert"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sample_rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2025, 1, 1, tzinfo=UTC))
        .sign(sample_rsa_key, hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    details = X509Parser.parse(cert_bytes)

    # Should not crash, and optional fields should be empty
    assert details.subject_dn["CN"] == "Minimal Cert"
    assert details.key_usage == []  # No key usage extension
    assert details.extended_key_usage == []
    assert details.subject_alt_names == []
    assert details.crl_distribution_points == []
    assert details.ocsp_responders == []


def test_parse_raises_on_invalid_certificate():
    """Test that parsing invalid certificate data raises ValueError."""
    invalid_cert = b"not a certificate"

    with pytest.raises(ValueError, match="Failed to parse certificate"):
        X509Parser.parse(invalid_cert)


def test_parse_handles_multiple_same_dn_attributes(sample_rsa_key):
    """Test handling of multiple DN attributes with the same OID."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU1"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU2"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ]
    )

    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sample_rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2025, 1, 1, tzinfo=UTC))
        .sign(sample_rsa_key, hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    details = X509Parser.parse(cert_bytes)

    # Multiple OUs should be combined
    assert "OU1" in details.subject_dn["OU"]
    assert "OU2" in details.subject_dn["OU"]

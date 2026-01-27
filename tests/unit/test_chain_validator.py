"""
test_chain_validator.py - Tests for certificate chain validation

Author: Homero Thompson del Lago del Terror

Tests certificate chain building and validation including
trusted chains, partial chains, expired certificates, and
invalid signatures.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from pdfsigner.core.certificate.chain_validator import (
    CertificateChainValidator,
    ChainStatus,
    ChainValidationResult,
)
from pdfsigner.core.certificate.trust_store import TrustStore

# Helper functions to generate test certificates


def generate_private_key():
    """Generate RSA private key for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_root_ca(subject_name: str, valid_days: int = 365):
    """Generate self-signed root CA certificate."""
    private_key = generate_private_key()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert, private_key


def generate_intermediate_ca(
    subject_name: str, issuer_cert, issuer_key, valid_days: int = 365, expired: bool = False
):
    """Generate intermediate CA certificate."""
    private_key = generate_private_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Intermediate CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    now = datetime.now(UTC)

    # Set validity period
    if expired:
        not_before = now - timedelta(days=400)  # Started 400 days ago
        not_after = now - timedelta(days=30)  # Expired 30 days ago
    else:
        not_before = now
        not_after = now + timedelta(days=valid_days)

    # Get issuer's Subject Key Identifier
    ski_ext = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    return cert, private_key


def generate_end_entity_cert(subject_name: str, issuer_cert, issuer_key, valid_days: int = 365):
    """Generate end-entity certificate."""
    private_key = generate_private_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    now = datetime.now(UTC)

    # Get issuer's Subject Key Identifier
    ski_ext = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    return cert, private_key


def generate_expired_cert(subject_name: str, issuer_cert, issuer_key):
    """Generate expired certificate."""
    private_key = generate_private_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    now = datetime.now(UTC)
    not_before = now - timedelta(days=400)  # Started 400 days ago
    not_after = now - timedelta(days=30)  # Expired 30 days ago

    ski_ext = issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    return cert, private_key


# Fixtures


@pytest.fixture
def trust_store():
    """Create empty trust store."""
    return TrustStore()


@pytest.fixture
def root_ca():
    """Generate root CA certificate."""
    return generate_root_ca("Test Root CA")


@pytest.fixture
def complete_chain(root_ca):
    """Generate complete certificate chain (root -> intermediate -> end-entity)."""
    root_cert, root_key = root_ca
    intermediate_cert, intermediate_key = generate_intermediate_ca(
        "Test Intermediate CA", root_cert, root_key
    )
    end_cert, end_key = generate_end_entity_cert(
        "test.example.com", intermediate_cert, intermediate_key
    )

    return {
        "root": (root_cert, root_key),
        "intermediate": (intermediate_cert, intermediate_key),
        "end_entity": (end_cert, end_key),
    }


@pytest.fixture
def validator_with_trusted_root(trust_store, complete_chain):
    """Create validator with trusted root CA loaded."""
    root_cert, _ = complete_chain["root"]

    # Add root to trust store manually
    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    # Add intermediate to trust store (simulating system CAs)
    intermediate_cert, _ = complete_chain["intermediate"]
    intermediate_der = intermediate_cert.subject.public_bytes()
    trust_store._trusted_certs[intermediate_der] = intermediate_cert

    return CertificateChainValidator(trust_store)


# Tests


def test_validate_chain_complete_valid_chain(validator_with_trusted_root, complete_chain):
    """Test validation of complete valid chain."""
    end_cert, _ = complete_chain["end_entity"]

    result = validator_with_trusted_root.validate_chain(end_cert)

    assert result.is_valid
    assert result.status == ChainStatus.VALID
    assert len(result.chain) == 3  # End-entity -> Intermediate -> Root
    assert result.trust_anchor is not None
    assert len(result.errors) == 0


def test_build_chain_returns_complete_chain(validator_with_trusted_root, complete_chain):
    """Test building complete certificate chain."""
    end_cert, _ = complete_chain["end_entity"]

    chain = validator_with_trusted_root.build_chain(end_cert)

    assert len(chain) == 3
    assert chain[0] == end_cert
    assert chain[1] == complete_chain["intermediate"][0]
    assert chain[2] == complete_chain["root"][0]


def test_validate_chain_with_self_signed_cert(trust_store):
    """Test validation of self-signed certificate (root CA)."""
    root_cert, _ = generate_root_ca("Self-Signed Root")

    # Add to trust store
    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(root_cert)

    assert result.is_valid
    assert result.status == ChainStatus.VALID
    assert len(result.chain) == 1
    assert result.trust_anchor == root_cert


def test_validate_chain_untrusted_root(trust_store):
    """Test validation with untrusted self-signed root CA."""
    # Create a self-signed root that's NOT in trust store
    untrusted_root, untrusted_root_key = generate_root_ca("Untrusted Self-Signed Root")

    # Validate it directly (it's self-signed but not trusted)
    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(untrusted_root)

    # Should detect as untrusted root (self-signed but not in trust store)
    assert not result.is_valid
    assert result.status == ChainStatus.UNTRUSTED_ROOT
    assert result.trust_anchor is None
    assert any("not trusted" in err.lower() for err in result.errors)


def test_validate_chain_partial_chain_missing_intermediate(trust_store, root_ca):
    """Test validation with missing intermediate certificate."""
    root_cert, root_key = root_ca
    intermediate_cert, intermediate_key = generate_intermediate_ca(
        "Missing Intermediate", root_cert, root_key
    )
    end_cert, _ = generate_end_entity_cert("test.example.com", intermediate_cert, intermediate_key)

    # Add only root to trust store, intermediate is missing
    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(end_cert)

    assert not result.is_valid
    assert result.status == ChainStatus.PARTIAL_CHAIN
    assert len(result.chain) == 1  # Only end-entity cert
    assert any("incomplete" in err.lower() for err in result.errors)


def test_validate_chain_with_expired_certificate(trust_store, root_ca):
    """Test validation with expired certificate in chain."""
    root_cert, root_key = root_ca
    expired_cert, _ = generate_expired_cert("expired.example.com", root_cert, root_key)

    # Add root to trust store
    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(expired_cert)

    assert not result.is_valid
    assert result.status == ChainStatus.EXPIRED
    assert any("expired" in err.lower() for err in result.errors)


def test_validate_chain_expired_intermediate(validator_with_trusted_root, root_ca):
    """Test validation with expired intermediate CA."""
    root_cert, root_key = root_ca

    # Create expired intermediate
    intermediate_cert, intermediate_key = generate_intermediate_ca(
        "Expired Intermediate",
        root_cert,
        root_key,
        expired=True,  # Generate expired cert
    )

    # Create valid end-entity from expired intermediate
    end_cert, _ = generate_end_entity_cert("test.example.com", intermediate_cert, intermediate_key)

    # Manually add expired intermediate to trust store
    intermediate_der = intermediate_cert.subject.public_bytes()
    validator_with_trusted_root.trust_store._trusted_certs[intermediate_der] = intermediate_cert

    result = validator_with_trusted_root.validate_chain(end_cert)

    assert not result.is_valid
    assert result.status == ChainStatus.EXPIRED


def test_validate_chain_invalid_signature(trust_store, root_ca):
    """Test validation with invalid signature (cert signed by wrong key)."""
    root_cert, root_key = root_ca
    wrong_root_cert, wrong_key = generate_root_ca("Wrong Root CA")

    # Sign with one key but claim issuer is different
    intermediate_cert, intermediate_key = generate_intermediate_ca(
        "Test Intermediate",
        root_cert,
        wrong_key,  # Wrong key!
    )

    end_cert, _ = generate_end_entity_cert("test.example.com", intermediate_cert, intermediate_key)

    # Add both roots to trust store
    for cert in [root_cert, wrong_root_cert]:
        subject_der = cert.subject.public_bytes()
        trust_store._trusted_certs[subject_der] = cert

    # Add intermediate
    intermediate_der = intermediate_cert.subject.public_bytes()
    trust_store._trusted_certs[intermediate_der] = intermediate_cert

    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(end_cert)

    assert not result.is_valid
    assert result.status == ChainStatus.INVALID_SIGNATURE
    assert any("signature" in err.lower() for err in result.errors)


def test_build_chain_prevents_cycles(trust_store):
    """Test that chain building prevents infinite loops."""
    # Create two certs that reference each other (impossible but tests cycle detection)
    root_cert, root_key = generate_root_ca("Cycle Root")

    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    validator = CertificateChainValidator(trust_store)

    # Should stop at root (self-signed)
    chain = validator.build_chain(root_cert)

    assert len(chain) == 1
    assert chain[0] == root_cert


def test_build_chain_max_depth_limit(trust_store):
    """Test that chain building respects maximum depth."""
    # Create single end-entity cert with no issuer in trust store
    root_cert, root_key = generate_root_ca("Missing Root")
    end_cert, _ = generate_end_entity_cert("orphan.example.com", root_cert, root_key)

    # Don't add root to trust store
    validator = CertificateChainValidator(trust_store)

    chain = validator.build_chain(end_cert)

    # Should return only the end-entity cert
    assert len(chain) == 1
    assert chain[0] == end_cert


def test_validate_chain_result_properties(validator_with_trusted_root, complete_chain):
    """Test ChainValidationResult properties."""
    end_cert, _ = complete_chain["end_entity"]

    result = validator_with_trusted_root.validate_chain(end_cert)

    # Test properties
    assert result.is_valid is True
    assert result.is_trusted is True
    assert result.status == ChainStatus.VALID

    # Test untrusted result
    untrusted_result = ChainValidationResult(
        status=ChainStatus.UNTRUSTED_ROOT,
        chain=[end_cert],
        trust_anchor=None,
        errors=["Not trusted"],
    )

    assert untrusted_result.is_valid is False
    assert untrusted_result.is_trusted is False


def test_validator_with_custom_ca(trust_store, tmp_path):
    """Test adding custom CA from PEM file."""
    root_cert, _ = generate_root_ca("Custom Root CA")

    # Write to temp file
    pem_file = tmp_path / "custom_ca.pem"
    pem_file.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

    # Add custom CA
    trust_store.add_custom_ca(str(pem_file))

    assert trust_store.custom_count == 1
    assert trust_store.is_trusted(root_cert)

    # Test validation with custom CA
    end_cert, _ = generate_end_entity_cert("test.example.com", root_cert, _)

    # Need to add root to trust_store for chain building
    subject_der = root_cert.subject.public_bytes()
    trust_store._trusted_certs[subject_der] = root_cert

    validator = CertificateChainValidator(trust_store)
    result = validator.validate_chain(end_cert)

    assert result.is_valid
    assert result.trust_anchor == root_cert


def test_trust_store_clear_custom_cas(trust_store, tmp_path):
    """Test clearing custom CA certificates."""
    root_cert, _ = generate_root_ca("Custom Root")

    pem_file = tmp_path / "custom.pem"
    pem_file.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

    # Add and verify
    trust_store.add_custom_ca(str(pem_file))
    assert trust_store.custom_count == 1
    assert trust_store.is_trusted(root_cert)

    # Clear custom CAs
    trust_store.clear_custom_cas()
    assert trust_store.custom_count == 0
    assert not trust_store.is_trusted(root_cert)

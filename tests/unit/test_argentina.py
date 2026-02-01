"""
test_argentina.py - Unit tests for Argentine compliance module

Tests for:
- Argentine CA Registry
- Argentine Certificate Validator
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pdfsigner.core.argentina import (
    ArgentineValidationStatus,
    CertifierType,
    get_argentine_ca_registry,
    get_argentine_validator,
)


class TestArgentineCARegistry:
    """Test suite for Argentine CA Registry."""

    def test_singleton_instance(self):
        """Test that get_argentine_ca_registry returns singleton instance."""
        registry1 = get_argentine_ca_registry()
        registry2 = get_argentine_ca_registry()
        assert registry1 is registry2

    def test_get_all_certifiers(self):
        """Test getting all registered certifiers."""
        registry = get_argentine_ca_registry()
        certifiers = registry.get_all_certifiers()

        # Should have all 8 certifiers
        assert len(certifiers) == 8

        # Check names
        names = {c.name for c in certifiers}
        assert "AFIP" in names
        assert "RENAPER" in names
        assert "FDR" in names
        assert "Andreani" in names
        assert "E-CERT NIC Argentina" in names

    def test_get_governmental_certifiers(self):
        """Test getting only governmental certifiers."""
        registry = get_argentine_ca_registry()
        gov_certifiers = registry.get_governmental_certifiers()

        # Should have 4 governmental certifiers
        assert len(gov_certifiers) == 4

        # All should be governmental type
        for certifier in gov_certifiers:
            assert certifier.certifier_type == CertifierType.GOVERNMENTAL
            assert certifier.cost == "Gratis"

    def test_get_private_certifiers(self):
        """Test getting only private certifiers."""
        registry = get_argentine_ca_registry()
        private_certifiers = registry.get_private_certifiers()

        # Should have 4 private certifiers
        assert len(private_certifiers) == 4

        # All should be private type
        for certifier in private_certifiers:
            assert certifier.certifier_type == CertifierType.PRIVATE
            assert "USD" in certifier.cost

    def test_find_certifier_by_issuer_exact_match(self):
        """Test finding certifier by exact issuer DN match."""
        registry = get_argentine_ca_registry()

        # Test AFIP exact match
        certifier = registry.find_certifier_by_issuer("CN=AC AFIP")
        assert certifier is not None
        assert certifier.name == "AFIP"

    def test_find_certifier_by_issuer_fuzzy_match(self):
        """Test finding certifier by fuzzy issuer DN match."""
        registry = get_argentine_ca_registry()

        # Test AFIP fuzzy match
        certifier = registry.find_certifier_by_issuer(
            "CN=Autoridad Certificante AFIP, O=AFIP, C=AR"
        )
        assert certifier is not None
        assert certifier.name == "AFIP"

        # Test RENAPER fuzzy match
        certifier = registry.find_certifier_by_issuer("CN=AC RENAPER, O=RENAPER")
        assert certifier is not None
        assert certifier.name == "RENAPER"

    def test_find_certifier_not_found(self):
        """Test finding certifier with unknown issuer."""
        registry = get_argentine_ca_registry()

        # Unknown CA
        certifier = registry.find_certifier_by_issuer("CN=Unknown CA, O=Unknown")
        assert certifier is None

    def test_is_licensed_certifier(self):
        """Test checking if issuer is licensed."""
        registry = get_argentine_ca_registry()

        # Licensed certifier
        assert registry.is_licensed_certifier("CN=AC AFIP") is True

        # Unknown certifier
        assert registry.is_licensed_certifier("CN=Unknown CA") is False

    def test_get_certifier_by_name(self):
        """Test getting certifier by exact name."""
        registry = get_argentine_ca_registry()

        # Exact name match
        certifier = registry.get_certifier_by_name("AFIP")
        assert certifier is not None
        assert certifier.name == "AFIP"
        assert certifier.certifier_type == CertifierType.GOVERNMENTAL

        # Not found
        certifier = registry.get_certifier_by_name("NonExistent")
        assert certifier is None


class TestArgentineCertificateValidator:
    """Test suite for Argentine Certificate Validator."""

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return get_argentine_validator()

    @pytest.fixture
    def rsa_key_2048(self):
        """Generate RSA 2048-bit key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    @pytest.fixture
    def rsa_key_1024(self):
        """Generate weak RSA 1024-bit key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend(),
        )

    def create_test_certificate(
        self,
        private_key,
        issuer_name: str = "CN=AC AFIP",
        subject_name: str = "CN=Test User",
        hash_algorithm=hashes.SHA256(),
        days_valid: int = 365,
    ) -> bytes:
        """Create test X.509 certificate.

        Args:
            private_key: Private key for signing
            issuer_name: Issuer DN
            subject_name: Subject DN
            hash_algorithm: Hash algorithm for signature
            days_valid: Certificate validity period in days

        Returns:
            DER-encoded certificate
        """
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name.split("=")[1]),
            ]
        )

        # Build certificate
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name.split("=")[1]),
                    ]
                )
            )
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=days_valid))
        )

        # Sign certificate
        cert = cert_builder.sign(private_key, hash_algorithm, default_backend())

        return cert.public_bytes(serialization.Encoding.DER)

    def test_singleton_instance(self):
        """Test that get_argentine_validator returns singleton instance."""
        validator1 = get_argentine_validator()
        validator2 = get_argentine_validator()
        assert validator1 is validator2

    def test_validate_compliant_certificate(self, validator, rsa_key_2048):
        """Test validation of compliant certificate (licensed CA, SHA-256, RSA 2048)."""
        cert_der = self.create_test_certificate(
            rsa_key_2048,
            issuer_name="CN=AC AFIP",
            hash_algorithm=hashes.SHA256(),
        )

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.VALID
        assert result.has_legal_validity is True
        assert result.algorithm_compliant is True
        assert result.certifier is not None
        assert result.certifier.name == "AFIP"
        assert result.key_algorithm == "RSA"
        assert result.key_size == 2048
        assert len(result.issues) == 0

    def test_validate_weak_key_size(self, validator, rsa_key_1024):
        """Test validation of certificate with weak key size."""
        cert_der = self.create_test_certificate(
            rsa_key_1024,
            issuer_name="CN=AC AFIP",
            hash_algorithm=hashes.SHA256(),
        )

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.INVALID_ALGORITHM
        assert result.has_legal_validity is False
        assert result.algorithm_compliant is False
        assert result.key_size == 1024
        assert any("1024 bits is below minimum 2048 bits" in issue for issue in result.issues)

    def test_validate_unknown_ca(self, validator, rsa_key_2048):
        """Test validation of certificate from unknown CA."""
        cert_der = self.create_test_certificate(
            rsa_key_2048,
            issuer_name="CN=Unknown CA",
            hash_algorithm=hashes.SHA256(),
        )

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.VALID_UNKNOWN_CA
        assert result.has_legal_validity is False
        assert result.algorithm_compliant is True
        assert result.certifier is None
        assert any("not a recognized Argentine CA" in issue for issue in result.issues)

    def test_validate_expired_certificate(self, validator, rsa_key_2048):
        """Test validation of expired certificate."""
        # Create certificate that expired 1 day ago
        private_key = rsa_key_2048
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
            ]
        )

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=366))
            .not_valid_after(datetime.now(UTC) - timedelta(days=1))
        )

        cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.EXPIRED
        assert result.has_legal_validity is False
        assert any("expired" in issue.lower() for issue in result.issues)

    def test_validate_not_yet_valid_certificate(self, validator, rsa_key_2048):
        """Test validation of not yet valid certificate."""
        # Create certificate that will be valid in 1 day
        private_key = rsa_key_2048
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
            ]
        )

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) + timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        )

        cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.NOT_YET_VALID
        assert result.has_legal_validity is False
        assert any("not yet valid" in issue.lower() for issue in result.issues)

    def test_validate_sha384_certificate(self, validator, rsa_key_2048):
        """Test validation of certificate with SHA-384 (allowed)."""
        cert_der = self.create_test_certificate(
            rsa_key_2048,
            issuer_name="CN=AC AFIP",
            hash_algorithm=hashes.SHA384(),
        )

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.VALID
        assert result.algorithm_compliant is True
        assert "sha384" in result.hash_algorithm.lower()

    def test_validate_sha512_certificate(self, validator, rsa_key_2048):
        """Test validation of certificate with SHA-512 (allowed)."""
        cert_der = self.create_test_certificate(
            rsa_key_2048,
            issuer_name="CN=AC AFIP",
            hash_algorithm=hashes.SHA512(),
        )

        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.VALID
        assert result.algorithm_compliant is True
        assert "sha512" in result.hash_algorithm.lower()

    def test_validate_invalid_certificate_data(self, validator):
        """Test validation with invalid certificate data."""
        result = validator.validate(b"invalid certificate data")

        assert result.status == ArgentineValidationStatus.ERROR
        assert result.has_legal_validity is False
        assert len(result.issues) > 0

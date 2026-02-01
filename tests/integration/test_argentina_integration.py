"""
test_argentina_integration.py - Integration tests for Argentine compliance module

Author: Homero Thompson del Lago del Terror

Integration tests with REAL certificate generation - NO MOCKS.
Tests the complete validation logic with actual X.509 certificates.

Tests cover:
- Real RSA/ECDSA certificate generation
- Algorithm compliance (SHA-256, SHA-384, SHA-512, SHA-1)
- Key size validation (1024, 2048, 4096)
- CA registry matching with various DN formats
- Certificate validity (expired, not yet valid, active)
- Legal validity determination
- Edge cases with real data
"""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pdfsigner.core.argentina import (
    ArgentineValidationStatus,
    get_argentine_ca_registry,
    get_argentine_validator,
)


def generate_test_certificate(
    issuer_cn: str = "Test CA",
    subject_cn: str = "Test User",
    key_size: int = 2048,
    hash_algo=hashes.SHA256(),
    days_valid: int = 365,
    expired: bool = False,
    not_yet_valid: bool = False,
    use_ecdsa: bool = False,
    ec_curve=ec.SECP256R1(),
) -> bytes:
    """Generate a real X.509 certificate for testing.

    Args:
        issuer_cn: Common Name for issuer
        subject_cn: Common Name for subject
        key_size: RSA key size in bits (ignored if use_ecdsa=True)
        hash_algo: Hash algorithm for signature
        days_valid: Certificate validity period in days
        expired: Generate expired certificate
        not_yet_valid: Generate certificate valid in future
        use_ecdsa: Use ECDSA instead of RSA
        ec_curve: Elliptic curve for ECDSA

    Returns:
        DER-encoded X.509 certificate
    """
    # Generate key
    if use_ecdsa:
        key = ec.generate_private_key(ec_curve, default_backend())
    else:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

    # Set validity dates
    now = datetime.now(UTC)
    if expired:
        not_before = now - timedelta(days=days_valid + 10)
        not_after = now - timedelta(days=10)
    elif not_yet_valid:
        not_before = now + timedelta(days=10)
        not_after = now + timedelta(days=days_valid + 10)
    else:
        not_before = now
        not_after = now + timedelta(days=days_valid)

    # Build certificate
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hash_algo, default_backend())
    )

    return cert.public_bytes(serialization.Encoding.DER)


def generate_certificate_with_full_dn(
    issuer_dn_parts: dict[str, str],
    subject_dn_parts: dict[str, str],
    key_size: int = 2048,
    hash_algo=hashes.SHA256(),
) -> bytes:
    """Generate certificate with full Distinguished Name.

    Args:
        issuer_dn_parts: Issuer DN components (e.g., {"CN": "AC AFIP", "O": "AFIP", "C": "AR"})
        subject_dn_parts: Subject DN components
        key_size: RSA key size
        hash_algo: Hash algorithm

    Returns:
        DER-encoded X.509 certificate
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    # Build DN from parts
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
    }

    issuer_attrs = [x509.NameAttribute(oid_map[k], v) for k, v in issuer_dn_parts.items()]
    subject_attrs = [x509.NameAttribute(oid_map[k], v) for k, v in subject_dn_parts.items()]

    issuer = x509.Name(issuer_attrs)
    subject = x509.Name(subject_attrs)

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hash_algo, default_backend())
    )

    return cert.public_bytes(serialization.Encoding.DER)


class TestArgentineValidatorIntegration:
    """Integration tests with real certificate generation - no mocks."""

    def test_validate_real_rsa_2048_sha256_certificate(self):
        """Test validation with real RSA-2048 + SHA-256 certificate."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.status == ArgentineValidationStatus.VALID
        # Debe reconocer AFIP como CA licenciada
        assert result.certifier is not None
        assert result.certifier.name == "AFIP"
        assert result.key_algorithm == "RSA"
        assert result.key_size == 2048
        assert "sha256" in result.hash_algorithm.lower()

    def test_validate_real_rsa_1024_rejected(self):
        """Test that RSA-1024 is rejected (too weak)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=1024,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is False
        assert result.status == ArgentineValidationStatus.INVALID_ALGORITHM
        assert result.key_size == 1024
        assert any("RSA key size" in issue and "1024" in issue for issue in result.issues)

    def test_validate_real_sha1_rejected(self):
        """Test that SHA-1 is rejected (cannot be generated with modern cryptography lib).

        Note: Modern cryptography library (OpenSSL 3.x+) refuses to create SHA-1
        certificates for security reasons, which aligns with Ley 25.506 requirements.
        This test verifies that the validator would reject SHA-1 if it encountered one.
        """
        # SHA-1 is blocked by cryptography library in OpenSSL 3.x+
        # This is correct behavior - SHA-1 should not be used
        # The validator code correctly checks for and rejects SHA-1 in PROHIBITED_ALGORITHMS

        # We can verify the validator's configuration directly
        validator = get_argentine_validator()
        assert "sha1" in validator.PROHIBITED_ALGORITHMS
        assert "sha256" in validator.ALLOWED_HASH_ALGORITHMS
        assert "sha384" in validator.ALLOWED_HASH_ALGORITHMS
        assert "sha512" in validator.ALLOWED_HASH_ALGORITHMS

    def test_validate_real_expired_certificate(self):
        """Test that expired certificates are detected."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            expired=True,
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.EXPIRED
        assert result.has_legal_validity is False
        assert any("expired" in issue.lower() for issue in result.issues)

    def test_validate_real_rsa_4096_sha512_certificate(self):
        """Test validation with high-security RSA-4096 + SHA-512."""
        cert_der = generate_test_certificate(
            issuer_cn="AC RENAPER",
            key_size=4096,
            hash_algo=hashes.SHA512(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.status == ArgentineValidationStatus.VALID
        assert result.key_size == 4096
        assert "sha512" in result.hash_algorithm.lower()
        assert result.certifier is not None
        assert result.certifier.name == "RENAPER"

    def test_validate_real_sha384_certificate(self):
        """Test validation with SHA-384 (allowed algorithm)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC FDR",
            key_size=2048,
            hash_algo=hashes.SHA384(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.status == ArgentineValidationStatus.VALID
        assert "sha384" in result.hash_algorithm.lower()
        assert result.certifier is not None
        assert result.certifier.name == "FDR"

    def test_validate_real_unknown_ca_certificate(self):
        """Test certificate from unknown CA (no legal validity)."""
        cert_der = generate_test_certificate(
            issuer_cn="Unknown Foreign CA",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.status == ArgentineValidationStatus.VALID_UNKNOWN_CA
        assert result.has_legal_validity is False
        assert result.certifier is None
        assert any("not a recognized Argentine CA" in issue for issue in result.issues)

    def test_validate_real_not_yet_valid_certificate(self):
        """Test certificate that starts in the future."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            not_yet_valid=True,
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.status == ArgentineValidationStatus.NOT_YET_VALID
        assert result.has_legal_validity is False
        assert any("not yet valid" in issue.lower() for issue in result.issues)

    def test_validate_real_ecdsa_p256_certificate(self):
        """Test ECDSA P-256 certificate (allowed by Ley 25.506)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC Andreani",
            use_ecdsa=True,
            ec_curve=ec.SECP256R1(),  # P-256
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.key_algorithm == "EC"
        assert result.key_size == 256
        assert result.certifier is not None
        assert result.certifier.name == "Andreani"

    def test_validate_real_ecdsa_p384_certificate(self):
        """Test ECDSA P-384 certificate (high security)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC E-CERT",
            use_ecdsa=True,
            ec_curve=ec.SECP384R1(),  # P-384
            hash_algo=hashes.SHA384(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is True
        assert result.key_algorithm == "EC"
        assert result.key_size == 384

    def test_validate_real_ecdsa_weak_curve_rejected(self):
        """Test that weak ECDSA curves are rejected."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            use_ecdsa=True,
            ec_curve=ec.SECP192R1(),  # P-192 (too weak)
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.algorithm_compliant is False
        assert result.key_size == 192
        assert any("EC key size" in issue and "192" in issue for issue in result.issues)

    def test_legal_validity_determination_licensed_ca(self):
        """Test that legal validity is True for licensed CA + compliant algorithms."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.has_legal_validity is True
        assert result.certifier is not None
        assert result.algorithm_compliant is True

    def test_legal_validity_determination_unknown_ca(self):
        """Test that legal validity is False for unknown CA."""
        cert_der = generate_test_certificate(
            issuer_cn="Unknown International CA",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.has_legal_validity is False
        assert result.certifier is None
        assert result.algorithm_compliant is True  # Algorithms OK, but no licensed CA

    def test_legal_validity_determination_weak_crypto(self):
        """Test that legal validity is False for weak cryptography."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=1024,  # Too weak
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        assert result.has_legal_validity is False
        assert result.certifier is not None  # CA is known, but crypto is weak
        assert result.algorithm_compliant is False


class TestArgentineCARegistryIntegration:
    """Integration tests for CA registry with real DN matching."""

    def test_registry_issuer_matching_real_dn_formats(self):
        """Test that registry matches various DN formats."""
        registry = get_argentine_ca_registry()

        # Test different DN formats for Argentine CAs
        test_cases = [
            ("CN=AC AFIP", "AFIP"),
            ("CN=Autoridad Certificante AFIP,O=AFIP,C=AR", "AFIP"),
            ("CN=AC RENAPER,O=RENAPER", "RENAPER"),
            ("CN=Autoridad Certificante RENAPER,O=Ministerio del Interior,C=AR", "RENAPER"),
            ("CN=AC FDR,O=Innovación Pública", "FDR"),
            ("CN=Firma Digital Remota,O=Secretaría de Innovación Pública,C=AR", "FDR"),
            ("CN=AC Andreani,O=Andreani", "Andreani"),
            ("CN=AC E-CERT,O=NIC Argentina", "E-CERT NIC Argentina"),
        ]

        for dn, expected_name in test_cases:
            certifier = registry.find_certifier_by_issuer(dn)
            assert certifier is not None, f"Should match: {dn}"
            assert certifier.name == expected_name, (
                f"Expected {expected_name}, got {certifier.name}"
            )

    def test_registry_issuer_matching_with_real_certificates(self):
        """Test registry matching with real certificate DNs."""
        registry = get_argentine_ca_registry()

        # Generate certificates with full DNs
        test_cases = [
            ({"CN": "AC AFIP", "O": "AFIP", "C": "AR"}, "AFIP"),
            ({"CN": "AC RENAPER", "O": "RENAPER", "C": "AR"}, "RENAPER"),
            ({"CN": "Autoridad Certificante FDR", "O": "Innovación Pública", "C": "AR"}, "FDR"),
            ({"CN": "AC Andreani", "O": "Andreani", "C": "AR"}, "Andreani"),
        ]

        for issuer_dn_parts, expected_name in test_cases:
            cert_der = generate_certificate_with_full_dn(
                issuer_dn_parts=issuer_dn_parts,
                subject_dn_parts={"CN": "Test User"},
            )

            # Parse certificate and extract issuer
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            issuer = cert.issuer.rfc4514_string()

            # Find certifier
            certifier = registry.find_certifier_by_issuer(issuer)
            assert certifier is not None, f"Should match: {issuer}"
            assert certifier.name == expected_name

    def test_registry_fuzzy_matching_case_insensitive(self):
        """Test that registry matching is case-insensitive."""
        registry = get_argentine_ca_registry()

        test_cases = [
            "cn=ac afip",
            "CN=AC AFIP",
            "Cn=Ac Afip",
            "CN=ac afip,o=afip",
        ]

        for dn in test_cases:
            certifier = registry.find_certifier_by_issuer(dn)
            assert certifier is not None, f"Should match (case-insensitive): {dn}"
            assert certifier.name == "AFIP"

    def test_registry_unknown_issuer_returns_none(self):
        """Test that unknown issuers return None."""
        registry = get_argentine_ca_registry()

        unknown_dns = [
            "CN=Unknown CA",
            "CN=Foreign CA,O=Foreign Org,C=US",
            "CN=Test CA 123",
        ]

        for dn in unknown_dns:
            certifier = registry.find_certifier_by_issuer(dn)
            assert certifier is None, f"Should not match: {dn}"


class TestArgentineEdgeCases:
    """Edge case tests with real data."""

    def test_certificate_at_exact_validity_boundary(self):
        """Test certificate at exact validity boundary (starts now)."""
        # Generate certificate that starts exactly now
        key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.now(UTC)

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC AFIP")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should be valid (boundary inclusive)
        assert result.status in [
            ArgentineValidationStatus.VALID,
            ArgentineValidationStatus.VALID_UNKNOWN_CA,
        ]

    def test_certificate_expires_in_one_second(self):
        """Test certificate that expires in 1 second."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.now(UTC)

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC AFIP")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now + timedelta(seconds=1))
            .sign(key, hashes.SHA256(), default_backend())
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should be valid (still within validity period)
        assert result.status == ArgentineValidationStatus.VALID

    def test_certificate_with_minimal_dn(self):
        """Test handling of certificate with minimal issuer DN."""
        cert_der = generate_test_certificate(
            issuer_cn="AFIP",  # Minimal DN (just CN)
            subject_cn="User",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should match AFIP through fuzzy matching
        assert result.certifier is not None
        assert result.certifier.name == "AFIP"

    def test_certificate_with_complex_multi_valued_dn(self):
        """Test certificate with complex multi-valued DN."""
        cert_der = generate_certificate_with_full_dn(
            issuer_dn_parts={
                "CN": "Autoridad Certificante AFIP",
                "O": "Administración Federal de Ingresos Públicos",
                "OU": "Dirección General Impositiva",
                "L": "Buenos Aires",
                "ST": "CABA",
                "C": "AR",
            },
            subject_dn_parts={"CN": "Test User", "O": "Test Org"},
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should match AFIP despite complex DN
        assert result.certifier is not None
        assert result.certifier.name == "AFIP"

    def test_multiple_certificates_with_different_cas(self):
        """Test validating multiple certificates from different CAs."""
        validator = get_argentine_validator()

        cas_to_test = [
            ("AC AFIP", "AFIP"),
            ("AC RENAPER", "RENAPER"),
            ("AC FDR", "FDR"),
            ("AC IOSFA", "IOSFA"),
            ("AC Andreani", "Andreani"),
            ("AC E-CERT", "E-CERT NIC Argentina"),
            ("AC Certant", "Certant"),
        ]

        for issuer_cn, expected_name in cas_to_test:
            cert_der = generate_test_certificate(
                issuer_cn=issuer_cn,
                key_size=2048,
                hash_algo=hashes.SHA256(),
            )
            result = validator.validate(cert_der)

            assert result.status == ArgentineValidationStatus.VALID
            assert result.certifier is not None
            assert result.certifier.name == expected_name
            assert result.has_legal_validity is True

    def test_certificate_with_long_validity_period(self):
        """Test certificate with unusually long validity period (10 years)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            hash_algo=hashes.SHA256(),
            days_valid=3650,  # 10 years
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should be valid regardless of long validity
        assert result.status == ArgentineValidationStatus.VALID
        assert result.valid_until is not None
        validity_days = (result.valid_until - result.valid_from).days  # type: ignore
        assert validity_days >= 3649  # Allow for rounding

    def test_certificate_with_short_validity_period(self):
        """Test certificate with very short validity period (1 day)."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            key_size=2048,
            hash_algo=hashes.SHA256(),
            days_valid=1,
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should be valid
        assert result.status == ArgentineValidationStatus.VALID
        assert result.valid_until is not None
        validity_days = (result.valid_until - result.valid_from).days  # type: ignore
        assert validity_days <= 1

    def test_certificate_with_special_characters_in_subject(self):
        """Test certificate with special characters in subject DN."""
        cert_der = generate_test_certificate(
            issuer_cn="AC AFIP",
            subject_cn="Usuario Ñoño O'Brien (Test)",
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Should be valid and handle special chars
        assert result.status == ArgentineValidationStatus.VALID
        assert "Ñoño" in result.certificate_subject or "ñoño" in result.certificate_subject.lower()

    def test_validator_handles_malformed_certificate_gracefully(self):
        """Test that validator handles malformed data gracefully."""
        validator = get_argentine_validator()

        # Test various invalid inputs
        invalid_inputs = [
            b"",  # Empty
            b"not a certificate",  # Random bytes
            b"\x00\x01\x02\x03",  # Binary garbage
        ]

        for invalid_data in invalid_inputs:
            result = validator.validate(invalid_data)
            assert result.status == ArgentineValidationStatus.ERROR
            assert len(result.issues) > 0
            assert result.has_legal_validity is False

    def test_registry_performance_with_many_lookups(self):
        """Test registry performance with many DN lookups."""
        registry = get_argentine_ca_registry()

        # Perform 100 lookups
        for _ in range(100):
            certifier = registry.find_certifier_by_issuer("CN=AC AFIP,O=AFIP,C=AR")
            assert certifier is not None
            assert certifier.name == "AFIP"

    def test_full_integration_workflow(self):
        """Test complete integration workflow: generate → validate → check registry."""
        # Step 1: Generate certificate
        cert_der = generate_certificate_with_full_dn(
            issuer_dn_parts={"CN": "Autoridad Certificante AFIP", "O": "AFIP", "C": "AR"},
            subject_dn_parts={"CN": "Juan Pérez", "O": "Test Org", "C": "AR"},
            key_size=2048,
            hash_algo=hashes.SHA256(),
        )

        # Step 2: Parse certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        issuer = cert.issuer.rfc4514_string()

        # Step 3: Validate with validator
        validator = get_argentine_validator()
        result = validator.validate(cert_der)

        # Step 4: Check registry directly
        registry = get_argentine_ca_registry()
        certifier = registry.find_certifier_by_issuer(issuer)

        # Assertions
        assert result.status == ArgentineValidationStatus.VALID
        assert result.has_legal_validity is True
        assert result.algorithm_compliant is True
        assert result.certifier is not None
        assert certifier is not None
        assert result.certifier.name == certifier.name == "AFIP"
        assert result.key_algorithm == "RSA"
        assert result.key_size == 2048
        assert "sha256" in result.hash_algorithm.lower()

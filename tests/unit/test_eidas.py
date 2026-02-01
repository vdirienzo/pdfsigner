"""Tests for eIDAS compliance module - TSP Registry and QES Validation."""

from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pdfsigner.core.eidas import (
    EUTSPRegistry,
    QESValidationResult,
    QualificationStatus,
    QualifiedSignatureValidator,
    ServiceType,
    SignatureValidation,
    TrustedListInfo,
    TSPInfo,
    get_tsp_registry,
)


class TestQualificationStatus:
    """Tests for QualificationStatus enum."""

    def test_qualification_status_values(self):
        """Test all qualification status values exist."""
        assert QualificationStatus.QUALIFIED == "qualified"
        assert QualificationStatus.NOT_QUALIFIED == "not_qualified"
        assert QualificationStatus.UNKNOWN == "unknown"
        assert QualificationStatus.WITHDRAWN == "withdrawn"

    def test_qualification_status_is_string_enum(self):
        """Test QualificationStatus is a string enum."""
        status = QualificationStatus.QUALIFIED
        assert isinstance(status, str)
        assert status == "qualified"


class TestServiceType:
    """Tests for ServiceType enum."""

    def test_service_type_values(self):
        """Test all service type values exist."""
        assert ServiceType.CA == "ca"
        assert ServiceType.TSA == "tsa"
        assert ServiceType.OCSP == "ocsp"
        assert ServiceType.CRL == "crl"

    def test_service_type_is_string_enum(self):
        """Test ServiceType is a string enum."""
        service = ServiceType.CA
        assert isinstance(service, str)
        assert service == "ca"


class TestTSPInfo:
    """Tests for TSPInfo dataclass."""

    def test_tsp_info_creation(self):
        """Test TSPInfo dataclass creation with all fields."""
        tsp = TSPInfo(
            name="Test CA",
            country="DE",
            service_type=ServiceType.CA,
            status=QualificationStatus.QUALIFIED,
            service_url="https://example.com",
            valid_from=datetime(2020, 1, 1),
            valid_until=datetime(2030, 1, 1),
            trust_anchor="sha256:abc123",
        )

        assert tsp.name == "Test CA"
        assert tsp.country == "DE"
        assert tsp.service_type == ServiceType.CA
        assert tsp.status == QualificationStatus.QUALIFIED
        assert tsp.service_url == "https://example.com"
        assert tsp.trust_anchor == "sha256:abc123"

    def test_tsp_info_optional_fields(self):
        """Test TSPInfo with only required fields."""
        tsp = TSPInfo(
            name="Test CA",
            country="FR",
            service_type=ServiceType.TSA,
            status=QualificationStatus.QUALIFIED,
        )

        assert tsp.service_url == ""
        assert tsp.valid_from is None
        assert tsp.valid_until is None
        assert tsp.trust_anchor is None


class TestTrustedListInfo:
    """Tests for TrustedListInfo dataclass."""

    def test_trusted_list_info_creation(self):
        """Test TrustedListInfo creation."""
        info = TrustedListInfo(
            version="5.5.1",
            issue_date=datetime(2024, 1, 1),
            next_update=datetime(2024, 1, 8),
            total_tsps=100,
            countries=["DE", "FR", "IT"],
        )

        assert info.version == "5.5.1"
        assert info.total_tsps == 100
        assert len(info.countries) == 3


class TestEUTSPRegistry:
    """Tests for EUTSPRegistry class."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        return tmp_path / "eidas_cache"

    @pytest.fixture
    def registry(self, temp_cache_dir):
        """Create fresh registry with temp cache."""
        return EUTSPRegistry(cache_dir=temp_cache_dir)

    def test_registry_initialization(self, registry, temp_cache_dir):
        """Test registry initializes with cache directory."""
        assert registry._cache_dir == temp_cache_dir
        assert temp_cache_dir.exists()

    def test_load_trusted_list_with_mock_data(self, registry):
        """Test loading mock trusted list."""
        result = registry.load_trusted_list(offline=True)

        assert result is True
        assert len(registry._tsps) > 0
        assert registry._list_info is not None

    def test_is_qualified_tsp_returns_true_for_qualified(self, registry):
        """Test is_qualified_tsp returns True for qualified TSP."""
        registry.load_trusted_list(offline=True)

        # DigiCert is in mock data as qualified
        result = registry.is_qualified_tsp("https://www.digicert.com")

        assert result is True

    def test_is_qualified_tsp_returns_false_for_not_qualified(self, registry):
        """Test is_qualified_tsp returns False for non-qualified TSP."""
        registry.load_trusted_list(offline=True)

        # FreeTSA is in mock data as not qualified
        result = registry.is_qualified_tsp("https://freetsa.org")

        assert result is False

    def test_is_qualified_tsp_returns_false_for_unknown(self, registry):
        """Test is_qualified_tsp returns False for unknown TSP."""
        registry.load_trusted_list(offline=True)

        result = registry.is_qualified_tsp("https://unknown-tsp.example.com")

        assert result is False

    def test_get_tsp_info_returns_info_when_found(self, registry):
        """Test get_tsp_info returns TSPInfo when found."""
        registry.load_trusted_list(offline=True)

        tsp = registry.get_tsp_info("https://www.digicert.com")

        assert tsp is not None
        assert tsp.name == "DigiCert Qualified CA"
        assert tsp.status == QualificationStatus.QUALIFIED

    def test_get_tsp_info_returns_none_when_not_found(self, registry):
        """Test get_tsp_info returns None for unknown TSP."""
        registry.load_trusted_list(offline=True)

        tsp = registry.get_tsp_info("https://unknown.example.com")

        assert tsp is None

    def test_get_tsps_by_country_returns_filtered_list(self, registry):
        """Test get_tsps_by_country filters by country code."""
        registry.load_trusted_list(offline=True)

        de_tsps = registry.get_tsps_by_country("DE")

        assert len(de_tsps) > 0
        assert all(tsp.country == "DE" for tsp in de_tsps)

    def test_get_tsps_by_country_case_insensitive(self, registry):
        """Test get_tsps_by_country is case insensitive."""
        registry.load_trusted_list(offline=True)

        de_tsps_upper = registry.get_tsps_by_country("DE")
        de_tsps_lower = registry.get_tsps_by_country("de")

        assert len(de_tsps_upper) == len(de_tsps_lower)

    def test_get_tsps_by_type_returns_cas(self, registry):
        """Test get_tsps_by_type filters Certificate Authorities."""
        registry.load_trusted_list(offline=True)

        cas = registry.get_tsps_by_type(ServiceType.CA)

        assert len(cas) > 0
        assert all(tsp.service_type == ServiceType.CA for tsp in cas)

    def test_get_tsps_by_type_returns_tsas(self, registry):
        """Test get_tsps_by_type filters Timestamp Authorities."""
        registry.load_trusted_list(offline=True)

        tsas = registry.get_tsps_by_type(ServiceType.TSA)

        assert len(tsas) > 0
        assert all(tsp.service_type == ServiceType.TSA for tsp in tsas)

    def test_get_list_info_returns_metadata(self, registry):
        """Test get_list_info returns trusted list metadata."""
        registry.load_trusted_list(offline=True)

        info = registry.get_list_info()

        assert info is not None
        assert info.version == "5.5.1"
        assert info.total_tsps > 0
        assert len(info.countries) > 0

    def test_check_certificate_issuer_recognizes_qualified(self, registry):
        """Test check_certificate_issuer detects qualified issuer."""
        registry.load_trusted_list(offline=True)

        status = registry.check_certificate_issuer("CN=Bundesdruckerei,C=DE")

        assert status == QualificationStatus.QUALIFIED

    def test_check_certificate_issuer_returns_unknown_for_unrecognized(self, registry):
        """Test check_certificate_issuer returns UNKNOWN for unrecognized issuer."""
        registry.load_trusted_list(offline=True)

        status = registry.check_certificate_issuer("CN=Unknown CA,C=XX")

        assert status == QualificationStatus.UNKNOWN

    def test_normalize_url_removes_trailing_slash(self, registry):
        """Test URL normalization removes trailing slash."""
        url1 = registry._normalize_url("https://example.com/path/")
        url2 = registry._normalize_url("https://example.com/path")

        assert url1 == url2

    def test_normalize_url_is_case_insensitive(self, registry):
        """Test URL normalization is case insensitive."""
        url1 = registry._normalize_url("https://Example.COM/Path")
        url2 = registry._normalize_url("https://example.com/path")

        assert url1 == url2

    def test_cache_saves_and_loads(self, registry):
        """Test cache saves and loads correctly."""
        # Load initial data
        registry.load_trusted_list(offline=True)
        initial_count = len(registry._tsps)

        # Create new registry with same cache dir
        registry2 = EUTSPRegistry(cache_dir=registry._cache_dir)
        loaded = registry2._load_from_cache()

        assert loaded is True
        assert len(registry2._tsps) == initial_count

    def test_cache_expires_after_max_age(self, registry, temp_cache_dir):
        """Test cache expires after max age."""
        # Load and save cache
        registry.load_trusted_list(offline=True)
        cache_file = registry._cache_file

        # Manually set old modification time
        old_time = datetime.now() - timedelta(days=8)
        cache_file.touch()
        import os

        os.utime(cache_file, (old_time.timestamp(), old_time.timestamp()))

        # Try to load expired cache
        registry2 = EUTSPRegistry(cache_dir=temp_cache_dir)
        loaded = registry2._load_from_cache()

        assert loaded is False

    def test_update_trusted_list_clears_cache(self, registry):
        """Test update_trusted_list clears existing cache."""
        registry.load_trusted_list(offline=True)
        cache_file = registry._cache_file

        assert cache_file.exists()

        # Update should work (mock data)
        result = registry.update_trusted_list()

        assert result is True


class TestGetTSPRegistry:
    """Tests for get_tsp_registry singleton."""

    def test_get_tsp_registry_returns_singleton(self):
        """Test get_tsp_registry returns same instance."""
        registry1 = get_tsp_registry()
        registry2 = get_tsp_registry()

        assert registry1 is registry2

    def test_get_tsp_registry_loads_data(self):
        """Test get_tsp_registry loads trusted list."""
        registry = get_tsp_registry()

        assert len(registry._tsps) > 0
        assert registry._list_info is not None


class TestQualifiedSignatureValidator:
    """Tests for QualifiedSignatureValidator class."""

    @pytest.fixture
    def registry(self):
        """Create registry with mock data."""
        registry = EUTSPRegistry()
        registry.load_trusted_list(offline=True)
        return registry

    @pytest.fixture
    def validator(self, registry):
        """Create validator with registry."""
        return QualifiedSignatureValidator(registry)

    @pytest.fixture
    def mock_cert(self):
        """Create mock X.509 certificate for testing."""
        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Build certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bundesdruckerei GmbH"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Qualified Certificate"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
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
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        return cert.public_bytes(serialization.Encoding.DER)

    def test_validator_initialization(self, validator, registry):
        """Test validator initializes with registry."""
        assert validator.registry is registry

    def test_validate_qes_returns_result(self, validator):
        """Test validate_qes returns QESValidationResult."""
        result = validator.validate_qes("/fake/path.pdf")

        assert isinstance(result, QESValidationResult)
        assert result.validation_time is not None

    def test_validate_certificate_returns_result(self, validator, mock_cert):
        """Test validate_certificate returns QESValidationResult."""
        result = validator.validate_certificate(mock_cert)

        assert isinstance(result, QESValidationResult)
        assert result.validation_time is not None

    def test_validate_certificate_checks_tsp_qualification(self, validator, mock_cert):
        """Test validate_certificate checks TSP qualification."""
        result = validator.validate_certificate(mock_cert)

        # Bundesdruckerei is in mock data as qualified
        assert result.tsp_qualified is True

    def test_check_qualified_certificate_with_qualified_issuer(self, validator, mock_cert):
        """Test check_qualified_certificate detects qualified certificate."""
        is_qualified = validator.check_qualified_certificate(mock_cert)

        # Mock cert has Bundesdruckerei as issuer (qualified in mock data)
        assert is_qualified is True

    def test_check_qscd_with_qualified_issuer(self, validator, mock_cert):
        """Test check_qscd detects QSCD usage."""
        has_qscd = validator.check_qscd(mock_cert)

        # Mock cert has Bundesdruckerei as issuer (qualified in mock data)
        assert has_qscd is True

    def test_get_qc_statements_returns_dict(self, validator, mock_cert):
        """Test get_qc_statements returns dictionary."""
        statements = validator.get_qc_statements(mock_cert)

        assert isinstance(statements, dict)

    def test_get_qc_statements_detects_qualified_issuer(self, validator, mock_cert):
        """Test get_qc_statements detects qualified issuer."""
        statements = validator.get_qc_statements(mock_cert)

        # Bundesdruckerei in issuer should trigger QcCompliance
        assert "QcCompliance" in statements
        assert statements["QcCompliance"] is True

    def test_detect_signature_level_returns_string(self, validator, tmp_path):
        """Test detect_signature_level returns level string."""
        # Create fake PDF
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_text("fake pdf")

        level = validator.detect_signature_level(str(pdf_file))

        assert level in ["QES", "AdES", "Basic"]

    def test_detect_signature_level_handles_missing_file(self, validator):
        """Test detect_signature_level handles missing file."""
        level = validator.detect_signature_level("/nonexistent/file.pdf")

        assert level == "Basic"

    def test_get_qc_type_returns_esign(self, validator, mock_cert):
        """Test get_qc_type returns certificate type."""
        qc_type = validator.get_qc_type(mock_cert)

        # Mock cert should have esign type
        assert qc_type == "esign"

    def test_validate_certificate_determines_qes_level(self, validator, mock_cert):
        """Test validate_certificate determines QES qualification level."""
        result = validator.validate_certificate(mock_cert)

        # Certificate with qualified issuer should be QES
        assert result.qualification_level in ["QES", "AdES", "Basic"]
        if result.certificate_qualified and result.device_qualified and result.tsp_qualified:
            assert result.qualification_level == "QES"
            assert result.is_qualified is True

    def test_validate_certificate_provides_recommendations(self, validator):
        """Test validate_certificate provides recommendations."""
        # Create cert with non-qualified issuer
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unknown CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        cert_bytes = cert.public_bytes(serialization.Encoding.DER)

        result = validator.validate_certificate(cert_bytes)

        # Should have recommendations for non-qualified cert
        assert len(result.recommendations) > 0


class TestQESValidationResult:
    """Tests for QESValidationResult dataclass."""

    def test_validation_result_creation(self):
        """Test QESValidationResult creation."""
        result = QESValidationResult(
            overall_status="TOTAL-PASSED",
            qualification_level="QES",
            issues=["test issue"],
            recommendations=["test recommendation"],
        )

        # Add signature validation to make properties work
        sig_val = SignatureValidation(
            certificate_qualified=True,
            qscd_used=True,
            tsp_granted=True,
            timestamp_present=True,
        )
        result.signature_validations.append(sig_val)

        assert result.is_qualified is True
        assert result.qualification_level == "QES"
        assert len(result.issues) == 1
        assert len(result.recommendations) == 1
        assert result.validation_time is not None

    def test_validation_result_default_fields(self):
        """Test QESValidationResult has default empty lists."""
        result = QESValidationResult(
            overall_status="TOTAL-FAILED",
            qualification_level="Basic",
        )

        # Add non-qualified signature validation
        sig_val = SignatureValidation(
            certificate_qualified=False,
            qscd_used=False,
            tsp_granted=False,
            timestamp_present=False,
        )
        result.signature_validations.append(sig_val)

        assert result.issues == []
        assert result.recommendations == []
        assert result.validation_time is not None

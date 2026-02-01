"""
test_eidas_production.py - Comprehensive tests for production eIDAS integration

Author: Homero Thompson del Lago del Terror

Tests the real EU Trusted List integration including:
- LOTL fetching and parsing
- TSL parsing
- TSP registry with real data
- PDF signature extraction
- QES validation

Pytest markers:
- compliance: marks tests as compliance-related (GDPR, HIPAA, eIDAS)
"""

import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pdfsigner.core.eidas.lotl_fetcher import LOTLFetcher
from pdfsigner.core.eidas.pdf_signature_extractor import (
    ExtractedSignature,
    PDFSignatureExtractor,
)
from pdfsigner.core.eidas.qualified_validator import (
    QESValidationResult,
    QualifiedSignatureValidator,
    SignatureValidation,
)
from pdfsigner.core.eidas.tsl_parser import (
    ServiceInfo,
    ServiceStatus,
    ServiceType,
    TSLParser,
    TSPInfo,
)
from pdfsigner.core.eidas.tsp_registry import (
    EUTSPRegistry,
    QualificationStatus,
)

# --- Fixtures ---


@pytest.fixture
def mock_lotl_xml():
    """Mock LOTL XML data."""
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
    <SchemeInformation>
        <TSLVersionIdentifier>5</TSLVersionIdentifier>
        <TSLSequenceNumber>123</TSLSequenceNumber>
        <ListIssueDateTime>2024-01-15T10:00:00Z</ListIssueDateTime>
        <NextUpdate>
            <dateTime>2024-01-22T10:00:00Z</dateTime>
        </NextUpdate>
        <SchemeOperatorName>
            <Name xml:lang="en">European Commission</Name>
        </SchemeOperatorName>
        <SchemeTerritory>EU</SchemeTerritory>
    </SchemeInformation>
    <TrustServiceProviderList>
        <TrustServiceProvider>
            <TSPInformation>
                <OtherTSLPointer>
                    <TSLLocation>https://tsl.germany.de/tsl.xml</TSLLocation>
                    <ServiceDigitalIdentities>
                        <ServiceDigitalIdentity>
                            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</ServiceTypeIdentifier>
                        </ServiceDigitalIdentity>
                    </ServiceDigitalIdentities>
                    <AdditionalInformation>
                        <SchemeTerritory>DE</SchemeTerritory>
                        <SchemeOperatorName>
                            <Name xml:lang="en">Germany</Name>
                        </SchemeOperatorName>
                        <MimeType>application/vnd.etsi.tsl+xml</MimeType>
                    </AdditionalInformation>
                </OtherTSLPointer>
            </TSPInformation>
        </TrustServiceProvider>
    </TrustServiceProviderList>
</TrustServiceStatusList>
"""


@pytest.fixture
def mock_tsl_xml():
    """Mock country TSL XML data."""
    cert_der = b"MOCK_CERT_DATA_12345"
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
    <SchemeInformation>
        <SchemeTerritory>DE</SchemeTerritory>
    </SchemeInformation>
    <TrustServiceProviderList>
        <TrustServiceProvider>
            <TSPInformation>
                <TSPName>
                    <Name xml:lang="en">Test TSP Provider</Name>
                </TSPName>
                <TSPAddress>
                    <PostalAddress>
                        <StreetAddress>Test Street 1</StreetAddress>
                        <PostalCode>12345</PostalCode>
                        <Locality>Berlin</Locality>
                    </PostalAddress>
                </TSPAddress>
            </TSPInformation>
            <TSPServices>
                <TSPService>
                    <ServiceInformation>
                        <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                        <ServiceName>
                            <Name xml:lang="en">Test CA Service</Name>
                        </ServiceName>
                        <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                        <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
                        <ServiceSupplyPoints>
                            <ServiceSupplyPoint>https://test.ca/service</ServiceSupplyPoint>
                        </ServiceSupplyPoints>
                        <ServiceDigitalIdentity>
                            <DigitalId>
                                <X509Certificate>{cert_b64}</X509Certificate>
                            </DigitalId>
                        </ServiceDigitalIdentity>
                    </ServiceInformation>
                </TSPService>
            </TSPServices>
        </TrustServiceProvider>
    </TrustServiceProviderList>
</TrustServiceStatusList>
""".encode()


@pytest.fixture
def test_certificate():
    """Generate a test X.509 certificate."""
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
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
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )

    return cert


# --- LOTL Fetcher Tests ---


@pytest.mark.compliance
def test_lotl_fetcher_initialization():
    """Test LOTLFetcher initialization."""
    fetcher = LOTLFetcher()
    assert fetcher.cache_dir.exists()
    assert fetcher.timeout == 30
    assert fetcher.cache_ttl == timedelta(hours=24)


@pytest.mark.compliance
def test_lotl_fetcher_custom_config(tmp_path):
    """Test LOTLFetcher with custom configuration."""
    cache_dir = tmp_path / "custom_cache"
    fetcher = LOTLFetcher(cache_dir=cache_dir, cache_ttl_hours=48, timeout=60)

    assert fetcher.cache_dir == cache_dir
    assert fetcher.cache_ttl == timedelta(hours=48)
    assert fetcher.timeout == 60


@pytest.mark.compliance
def test_lotl_fetcher_cache_directory_creation(tmp_path):
    """Test cache directory is created automatically."""
    cache_dir = tmp_path / "eidas_cache"
    fetcher = LOTLFetcher(cache_dir=cache_dir)

    assert cache_dir.exists()
    assert cache_dir.is_dir()


@pytest.mark.compliance
def test_lotl_parse_xml_success(mock_lotl_xml):
    """Test successful LOTL XML parsing."""
    fetcher = LOTLFetcher()
    lotl_data = fetcher._parse_lotl_xml(mock_lotl_xml)

    assert lotl_data.version == "5"
    assert lotl_data.sequence_number == 123
    assert lotl_data.territory == "EU"
    assert len(lotl_data.tsl_pointers) > 0


@pytest.mark.compliance
def test_lotl_parse_xml_extracts_pointers(mock_lotl_xml):
    """Test TSL pointers are extracted correctly."""
    fetcher = LOTLFetcher()
    lotl_data = fetcher._parse_lotl_xml(mock_lotl_xml)

    pointer = lotl_data.tsl_pointers[0]
    assert pointer.country_code == "DE"
    assert pointer.country_name == "Germany"
    assert pointer.tsl_url == "https://tsl.germany.de/tsl.xml"
    assert pointer.mime_type == "application/vnd.etsi.tsl+xml"


@pytest.mark.compliance
def test_lotl_parse_datetime_formats():
    """Test datetime parsing with various formats."""
    fetcher = LOTLFetcher()

    # Test different datetime formats
    dt1 = fetcher._parse_datetime("2024-01-15T10:00:00Z")
    assert isinstance(dt1, datetime)

    dt2 = fetcher._parse_datetime("2024-01-15T10:00:00.123Z")
    assert isinstance(dt2, datetime)

    dt3 = fetcher._parse_datetime("2024-01-15T10:00:00+01:00")
    assert isinstance(dt3, datetime)


@pytest.mark.compliance
def test_lotl_parse_datetime_fallback():
    """Test datetime parsing falls back gracefully."""
    fetcher = LOTLFetcher()

    # Invalid format should return current time
    dt = fetcher._parse_datetime("invalid-date")
    assert isinstance(dt, datetime)


@pytest.mark.compliance
def test_lotl_cache_validity_check(tmp_path):
    """Test cache validity checking."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "eu-lotl.xml"

    fetcher = LOTLFetcher(cache_dir=cache_dir, cache_ttl_hours=1)

    # No cache file
    assert not fetcher._is_cache_valid(cache_file)

    # Fresh cache file
    cache_file.write_text("test")
    assert fetcher._is_cache_valid(cache_file)


@pytest.mark.compliance
def test_lotl_get_country_tsl_url(mock_lotl_xml):
    """Test getting TSL URL for a specific country."""
    fetcher = LOTLFetcher()

    with patch.object(fetcher, "fetch_lotl") as mock_fetch:
        mock_fetch.return_value = fetcher._parse_lotl_xml(mock_lotl_xml)

        url = fetcher.get_country_tsl_url("DE")
        assert url == "https://tsl.germany.de/tsl.xml"


@pytest.mark.compliance
def test_lotl_get_country_tsl_url_not_found(mock_lotl_xml):
    """Test getting TSL URL for non-existent country."""
    fetcher = LOTLFetcher()

    with patch.object(fetcher, "fetch_lotl") as mock_fetch:
        mock_fetch.return_value = fetcher._parse_lotl_xml(mock_lotl_xml)

        url = fetcher.get_country_tsl_url("XX")
        assert url is None


@pytest.mark.compliance
def test_lotl_get_all_tsl_urls(mock_lotl_xml):
    """Test getting all TSL URLs."""
    fetcher = LOTLFetcher()

    with patch.object(fetcher, "fetch_lotl") as mock_fetch:
        mock_fetch.return_value = fetcher._parse_lotl_xml(mock_lotl_xml)

        urls = fetcher.get_all_tsl_urls()
        assert isinstance(urls, dict)
        assert "DE" in urls
        assert urls["DE"] == "https://tsl.germany.de/tsl.xml"


# --- TSL Parser Tests ---


@pytest.mark.compliance
def test_tsl_parser_initialization():
    """Test TSLParser initialization."""
    parser = TSLParser()
    assert parser is not None


@pytest.mark.compliance
def test_tsl_parser_parse_success(mock_tsl_xml):
    """Test successful TSL parsing."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    assert len(tsps) > 0
    assert isinstance(tsps[0], TSPInfo)


@pytest.mark.compliance
def test_tsl_parser_extracts_tsp_info(mock_tsl_xml):
    """Test TSP information extraction."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    tsp = tsps[0]
    assert tsp.name == "Test TSP Provider"
    assert tsp.country_code == "DE"
    assert tsp.postal_address is not None


@pytest.mark.compliance
def test_tsl_parser_extracts_services(mock_tsl_xml):
    """Test service extraction from TSL."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    tsp = tsps[0]
    assert len(tsp.services) > 0

    service = tsp.services[0]
    assert service.name == "Test CA Service"
    assert service.status == ServiceStatus.GRANTED
    assert service.service_type == ServiceType.CA_QC


@pytest.mark.compliance
def test_tsl_parser_service_supply_points(mock_tsl_xml):
    """Test service supply point extraction."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    service = tsps[0].services[0]
    assert len(service.service_supply_points) > 0
    assert service.service_supply_points[0] == "https://test.ca/service"


@pytest.mark.compliance
def test_tsl_parser_certificate_extraction(mock_tsl_xml):
    """Test certificate extraction from service."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    service = tsps[0].services[0]
    assert service.certificate_der is not None
    assert service.certificate_der == b"MOCK_CERT_DATA_12345"


@pytest.mark.compliance
def test_tsl_parser_service_status_parsing():
    """Test service status parsing from URI."""
    assert (
        ServiceStatus.from_uri("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
        == ServiceStatus.GRANTED
    )

    assert (
        ServiceStatus.from_uri("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn")
        == ServiceStatus.WITHDRAWN
    )


@pytest.mark.compliance
def test_tsl_parser_service_type_parsing():
    """Test service type parsing from URI."""
    service_type = ServiceType.from_uri("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
    assert service_type == ServiceType.CA_QC

    service_type = ServiceType.from_uri("http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST")
    assert service_type == ServiceType.TSA_QTST


@pytest.mark.compliance
def test_tsl_parser_service_type_unknown():
    """Test handling of unknown service type."""
    service_type = ServiceType.from_uri("http://unknown.service.type")
    assert service_type is None


@pytest.mark.compliance
def test_tsl_parser_datetime_parsing():
    """Test datetime parsing in TSL parser."""
    parser = TSLParser()

    dt = parser._parse_datetime("2020-01-01T00:00:00Z")
    assert isinstance(dt, datetime)
    assert dt.year == 2020


@pytest.mark.compliance
def test_tsp_info_qualified_services(mock_tsl_xml):
    """Test getting qualified services from TSP."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    tsp = tsps[0]
    qualified = tsp.get_qualified_services()

    assert len(qualified) > 0
    assert all(s.status == ServiceStatus.GRANTED for s in qualified)


@pytest.mark.compliance
def test_tsp_info_ca_services(mock_tsl_xml):
    """Test getting CA services from TSP."""
    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    tsp = tsps[0]
    ca_services = tsp.get_ca_services()

    assert len(ca_services) > 0
    assert all(s.is_ca() for s in ca_services)


# --- TSP Registry Tests ---


@pytest.mark.compliance
def test_tsp_registry_initialization(tmp_path):
    """Test TSP registry initialization."""
    registry = EUTSPRegistry(cache_dir=tmp_path)
    assert registry._cache_dir.exists()


@pytest.mark.compliance
def test_tsp_registry_mock_data_loading():
    """Test loading mock TSP data."""
    registry = EUTSPRegistry(use_mock_data=True)
    result = registry.load_trusted_list(offline=True)

    assert result is True
    assert len(registry._tsps) > 0


@pytest.mark.compliance
def test_tsp_registry_is_qualified_tsp():
    """Test checking if TSP is qualified."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    # Check qualified TSP
    is_qualified = registry.is_qualified_tsp("https://www.digicert.com")
    assert is_qualified is True


@pytest.mark.compliance
def test_tsp_registry_get_tsp_info():
    """Test getting TSP information."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    tsp_info = registry.get_tsp_info("https://www.digicert.com")
    assert tsp_info is not None
    assert tsp_info.name == "DigiCert Qualified CA"


@pytest.mark.compliance
def test_tsp_registry_get_tsps_by_country():
    """Test getting TSPs by country."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    de_tsps = registry.get_tsps_by_country("DE")
    assert len(de_tsps) > 0
    assert all(tsp.country == "DE" for tsp in de_tsps)


@pytest.mark.compliance
def test_tsp_registry_get_tsps_by_type():
    """Test getting TSPs by service type."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    from pdfsigner.core.eidas.tsp_registry import ServiceType

    ca_tsps = registry.get_tsps_by_type(ServiceType.CA)
    assert len(ca_tsps) > 0
    assert all(tsp.service_type == ServiceType.CA for tsp in ca_tsps)


@pytest.mark.compliance
def test_tsp_registry_check_certificate_issuer():
    """Test checking certificate issuer qualification."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    status = registry.check_certificate_issuer("CN=DigiCert Qualified CA")
    assert status == QualificationStatus.QUALIFIED


@pytest.mark.compliance
def test_tsp_registry_check_unknown_issuer():
    """Test checking unknown certificate issuer."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    status = registry.check_certificate_issuer("CN=Unknown CA")
    assert status == QualificationStatus.UNKNOWN


@pytest.mark.compliance
def test_tsp_registry_find_tsp_by_certificate(test_certificate):
    """Test finding TSP by certificate."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    tsp = registry.find_tsp_by_certificate(cert_der)

    # May be None for test certificate
    assert tsp is None or isinstance(tsp, type(registry._tsps[next(iter(registry._tsps))]))


@pytest.mark.compliance
def test_tsp_registry_list_info():
    """Test getting trusted list metadata."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    list_info = registry.get_list_info()
    assert list_info is not None
    assert list_info.version is not None
    assert list_info.total_tsps > 0


@pytest.mark.compliance
def test_tsp_registry_cache_save_load(tmp_path):
    """Test caching functionality."""
    cache_dir = tmp_path / "cache"
    registry = EUTSPRegistry(cache_dir=cache_dir, use_mock_data=True)

    # Load and save
    registry.load_trusted_list(offline=True)
    assert registry._save_to_cache()

    # Create new registry and load from cache
    registry2 = EUTSPRegistry(cache_dir=cache_dir, use_mock_data=True)
    registry2._load_from_cache()

    assert len(registry2._tsps) > 0


# --- PDF Signature Extractor Tests ---


@pytest.mark.compliance
def test_signature_extractor_initialization():
    """Test PDFSignatureExtractor initialization."""
    extractor = PDFSignatureExtractor()
    assert extractor is not None


@pytest.mark.compliance
def test_signature_extractor_file_not_found():
    """Test extraction with non-existent file."""
    extractor = PDFSignatureExtractor()

    with pytest.raises(FileNotFoundError):
        extractor.extract_signatures("/nonexistent/file.pdf")


@pytest.mark.compliance
def test_signature_extractor_get_count_nonexistent():
    """Test getting signature count for non-existent file."""
    extractor = PDFSignatureExtractor()

    with pytest.raises(FileNotFoundError):
        extractor.get_signature_count("/nonexistent/file.pdf")


@pytest.mark.compliance
def test_signature_extractor_has_signatures_nonexistent():
    """Test has_signatures for non-existent file."""
    extractor = PDFSignatureExtractor()

    assert not extractor.has_signatures("/nonexistent/file.pdf")


@pytest.mark.compliance
def test_extracted_signature_dataclass():
    """Test ExtractedSignature dataclass."""
    sig = ExtractedSignature(
        field_name="Signature1",
        signing_time=datetime.now(),
        signer_name="Test Signer",
        certificate_der=b"test_cert",
        certificate=Mock(),
        signature_bytes=b"test_sig",
        has_timestamp=True,
        coverage="full",
    )

    assert sig.field_name == "Signature1"
    assert sig.signer_name == "Test Signer"
    assert sig.has_timestamp is True


# --- Qualified Validator Tests ---


@pytest.mark.compliance
def test_qualified_validator_initialization():
    """Test QualifiedSignatureValidator initialization."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)
    assert validator.registry == registry


@pytest.mark.compliance
def test_qualified_validator_validate_certificate(test_certificate):
    """Test certificate validation."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    result = validator.validate_certificate(cert_der)

    assert isinstance(result, QESValidationResult)
    assert result.qualification_level in ["QES", "AdES", "Basic"]


@pytest.mark.compliance
def test_qualified_validator_check_qscd(test_certificate):
    """Test QSCD checking."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    has_qscd = validator.check_qscd(cert_der)

    assert isinstance(has_qscd, bool)


@pytest.mark.compliance
def test_qualified_validator_check_qualified_certificate(test_certificate):
    """Test qualified certificate checking."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    is_qualified = validator.check_qualified_certificate(cert_der)

    assert isinstance(is_qualified, bool)


@pytest.mark.compliance
def test_qualified_validator_get_qc_statements(test_certificate):
    """Test QC statements extraction."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    statements = validator.get_qc_statements(cert_der)

    assert isinstance(statements, dict)


@pytest.mark.compliance
def test_qualified_validator_detect_signature_level():
    """Test signature level detection."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    level = validator.detect_signature_level("/nonexistent/file.pdf")
    assert level == "Basic"


@pytest.mark.compliance
def test_qualified_validator_get_qc_type(test_certificate):
    """Test QC type extraction."""
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    qc_type = validator.get_qc_type(cert_der)

    assert qc_type is None or qc_type in ["esign", "eseal", "web"]


@pytest.mark.compliance
def test_qes_validation_result_properties():
    """Test QESValidationResult properties."""
    result = QESValidationResult(
        overall_status="TOTAL-PASSED",
        qualification_level="QES",
    )

    # Add a signature validation
    sig_val = SignatureValidation(
        certificate_qualified=True,
        qscd_used=True,
        tsp_granted=True,
        timestamp_present=True,
    )
    result.signature_validations.append(sig_val)

    assert result.is_qualified is True
    assert result.certificate_qualified is True
    assert result.device_qualified is True
    assert result.tsp_qualified is True
    assert result.timestamp_qualified is True


@pytest.mark.compliance
def test_qes_validation_result_not_qualified():
    """Test QESValidationResult for non-qualified signature."""
    result = QESValidationResult(
        overall_status="TOTAL-FAILED",
        qualification_level="Basic",
    )

    sig_val = SignatureValidation(
        certificate_qualified=False,
        qscd_used=False,
        tsp_granted=False,
    )
    result.signature_validations.append(sig_val)

    assert result.is_qualified is False
    assert result.qualification_level == "Basic"


@pytest.mark.compliance
def test_signature_validation_dataclass():
    """Test SignatureValidation dataclass."""
    validation = SignatureValidation(
        field_name="Signature1",
        signer_name="Test Signer",
        certificate_qualified=True,
        qscd_used=True,
        tsp_granted=True,
        signature_valid=True,
        qualification_level="QES",
    )

    assert validation.field_name == "Signature1"
    assert validation.qualification_level == "QES"
    assert validation.certificate_qualified is True


# --- Integration Tests ---


@pytest.mark.compliance
def test_integration_registry_with_mock_data():
    """Test full integration with mock data."""
    registry = EUTSPRegistry(use_mock_data=True)
    assert registry.load_trusted_list(offline=True)

    validator = QualifiedSignatureValidator(registry)
    assert validator.registry == registry


@pytest.mark.compliance
def test_integration_lotl_to_tsp_registry(mock_lotl_xml, mock_tsl_xml):
    """Test integration from LOTL to TSP registry."""
    fetcher = LOTLFetcher()
    lotl_data = fetcher._parse_lotl_xml(mock_lotl_xml)

    parser = TSLParser()
    tsps = parser.parse(mock_tsl_xml)

    assert len(lotl_data.tsl_pointers) > 0
    assert len(tsps) > 0


@pytest.mark.compliance
def test_integration_end_to_end_mock(test_certificate):
    """Test end-to-end validation with mock data."""
    # Setup registry
    registry = EUTSPRegistry(use_mock_data=True)
    registry.load_trusted_list(offline=True)

    # Create validator
    validator = QualifiedSignatureValidator(registry)

    # Validate certificate
    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = test_certificate.public_bytes(Encoding.DER)
    result = validator.validate_certificate(cert_der)

    # Check result structure
    assert isinstance(result, QESValidationResult)
    assert result.qualification_level is not None
    assert len(result.signature_validations) > 0


@pytest.mark.compliance
def test_singleton_factories():
    """Test singleton factory functions."""
    from pdfsigner.core.eidas.lotl_fetcher import get_lotl_fetcher
    from pdfsigner.core.eidas.pdf_signature_extractor import get_signature_extractor
    from pdfsigner.core.eidas.tsp_registry import get_tsp_registry

    # Get instances
    fetcher1 = get_lotl_fetcher()
    fetcher2 = get_lotl_fetcher()
    assert fetcher1 is fetcher2

    extractor1 = get_signature_extractor()
    extractor2 = get_signature_extractor()
    assert extractor1 is extractor2

    registry1 = get_tsp_registry(use_mock_data=True)
    registry2 = get_tsp_registry(use_mock_data=True)
    assert registry1 is registry2


@pytest.mark.compliance
def test_service_info_helper_methods():
    """Test ServiceInfo helper methods."""
    # CA service
    ca_service = ServiceInfo(
        name="Test CA",
        service_type=ServiceType.CA_QC,
        service_type_uri="http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
        status=ServiceStatus.GRANTED,
        status_start_date=datetime.now(),
    )

    assert ca_service.is_qualified()
    assert ca_service.is_ca()
    assert not ca_service.is_tsa()

    # TSA service
    tsa_service = ServiceInfo(
        name="Test TSA",
        service_type=ServiceType.TSA_QTST,
        service_type_uri="http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
        status=ServiceStatus.GRANTED,
        status_start_date=datetime.now(),
    )

    assert tsa_service.is_qualified()
    assert not tsa_service.is_ca()
    assert tsa_service.is_tsa()


@pytest.mark.compliance
def test_error_handling_invalid_xml():
    """Test error handling for invalid XML."""
    parser = TSLParser()

    with pytest.raises(ValueError, match="Failed to parse TSL XML"):
        parser.parse(b"<invalid>xml</invalid")


@pytest.mark.compliance
def test_error_handling_missing_data():
    """Test error handling for missing data in XML."""
    minimal_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
    <SchemeInformation>
        <SchemeTerritory>XX</SchemeTerritory>
    </SchemeInformation>
</TrustServiceStatusList>
"""

    parser = TSLParser()
    tsps = parser.parse(minimal_xml)

    # Should handle gracefully
    assert len(tsps) == 0


@pytest.mark.compliance
def test_cache_expiry_logic(tmp_path):
    """Test cache expiry logic."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "eu-lotl.xml"

    # Create old cache file
    cache_file.write_text("old data")

    fetcher = LOTLFetcher(cache_dir=cache_dir, cache_ttl_hours=0)

    # Should be invalid due to 0 TTL
    assert not fetcher._is_cache_valid(cache_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

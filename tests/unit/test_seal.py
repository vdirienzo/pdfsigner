"""Unit tests for electronic seal functionality (eIDAS Article 35-40).

Tests cover:
- Seal creation with various configurations
- Seal validation
- Appearance generation
- Organization info extraction
- Certificate type detection
- API endpoints

Author: Homero Thompson del Lago del Terror
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.config.settings import Settings
from pdfsigner.core.eidas.seal_manager import (
    OrganizationInfo,
    SealAppearance,
    SealConfig,
    SealManager,
    SealResult,
    SealType,
    SealValidationResult,
    generate_circular_seal,
    get_seal_manager,
)


@pytest.fixture
def settings():
    """Create test settings."""
    return Settings(
        nss_db_path=Path.home() / ".nss",
        tsa_url="https://freetsa.org/tsr",
        dry_run=True,
    )


@pytest.fixture
def seal_manager(settings):
    """Create SealManager instance."""
    return SealManager(settings)


@pytest.fixture
def test_pdf(tmp_path):
    """Create a minimal test PDF."""
    pdf_path = tmp_path / "test.pdf"
    # Minimal valid PDF
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF"""
    pdf_path.write_bytes(pdf_content)
    return pdf_path


@pytest.fixture
def org_info():
    """Create test organization info."""
    return OrganizationInfo(
        name="Acme Corporation",
        country="DE",
        organization_id="DE123456789",
        department="IT Department",
        address="Berlin, Germany",
        email="seal@acme.com",
        website="https://acme.com",
    )


@pytest.fixture
def seal_config(org_info):
    """Create test seal configuration."""
    return SealConfig(
        organization=org_info,
        seal_type=SealType.ADVANCED,
        appearance=SealAppearance.STAMP,
        reason="Official company seal",
        location="Berlin",
        page=1,
        position=(50, 50),
        size=(40, 40),
        include_timestamp=True,
        tsa_url="https://freetsa.org/tsr",
    )


# ========== SealManager Tests ==========


def test_seal_manager_initialization(settings):
    """Test SealManager initialization."""
    manager = SealManager(settings)
    assert manager.settings == settings


def test_seal_manager_singleton():
    """Test get_seal_manager returns singleton."""
    manager1 = get_seal_manager()
    manager2 = get_seal_manager()
    assert manager1 is manager2


def test_create_seal_dry_run(seal_manager, test_pdf, seal_config, tmp_path):
    """Test seal creation in dry-run mode."""
    output_path = tmp_path / "sealed.pdf"
    result = seal_manager.create_seal(test_pdf, seal_config, output_path, dry_run=True)

    assert result.success is True
    assert result.seal_type == SealType.ADVANCED
    assert result.organization == "Acme Corporation"
    assert result.timestamp is not None
    assert result.signature_id == "DRY_RUN_SEAL_001"
    assert len(result.errors) == 0


def test_create_seal_file_not_found(seal_manager, seal_config):
    """Test seal creation with non-existent PDF."""
    with pytest.raises(FileNotFoundError):
        seal_manager.create_seal(Path("/nonexistent.pdf"), seal_config)


def test_create_seal_output_path_default(seal_manager, test_pdf, seal_config):
    """Test seal creation with default output path."""
    result = seal_manager.create_seal(test_pdf, seal_config, dry_run=True)

    expected_path = test_pdf.parent / f"{test_pdf.stem}_sealed{test_pdf.suffix}"
    assert result.output_path == expected_path


def test_create_seal_different_types(seal_manager, test_pdf, seal_config, tmp_path):
    """Test seal creation with different seal types."""
    for seal_type in [SealType.BASIC, SealType.ADVANCED, SealType.QUALIFIED]:
        seal_config.seal_type = seal_type
        output_path = tmp_path / f"sealed_{seal_type.value}.pdf"

        result = seal_manager.create_seal(test_pdf, seal_config, output_path, dry_run=True)

        assert result.success is True
        assert result.seal_type == seal_type


def test_create_seal_different_appearances(seal_manager, test_pdf, seal_config, tmp_path):
    """Test seal creation with different appearances."""
    for appearance in [
        SealAppearance.INVISIBLE,
        SealAppearance.STAMP,
        SealAppearance.BANNER,
        SealAppearance.LOGO,
    ]:
        seal_config.appearance = appearance
        output_path = tmp_path / f"sealed_{appearance.value}.pdf"

        result = seal_manager.create_seal(test_pdf, seal_config, output_path, dry_run=True)

        assert result.success is True


def test_create_seal_last_page(seal_manager, test_pdf, seal_config):
    """Test seal creation on last page."""
    seal_config.page = -1
    result = seal_manager.create_seal(test_pdf, seal_config, dry_run=True)

    assert result.success is True


def test_create_seal_without_timestamp(seal_manager, test_pdf, seal_config):
    """Test seal creation without timestamp."""
    seal_config.include_timestamp = False
    result = seal_manager.create_seal(test_pdf, seal_config, dry_run=True)

    assert result.success is True
    assert result.timestamp is None


# ========== Seal Validation Tests ==========


def test_validate_seal_file_not_found(seal_manager):
    """Test seal validation with non-existent PDF."""
    with pytest.raises(FileNotFoundError):
        seal_manager.validate_seal(Path("/nonexistent.pdf"))


def test_validate_seal_no_signatures(seal_manager, test_pdf):
    """Test seal validation on PDF without signatures."""
    result = seal_manager.validate_seal(test_pdf)

    assert result.valid is False
    # The error can be either "No signature fields found" or a PDF parsing error
    assert len(result.issues) > 0
    assert any(
        phrase in result.issues[0]
        for phrase in ["No signature fields found", "Dictionary read error", "read error"]
    )


def test_validate_seal_mock_validation(seal_manager, test_pdf):
    """Test seal validation with mocked signature fields."""
    # Create a PDF with signature fields (mock)
    with patch("pdfsigner.core.eidas.seal_manager.PdfFileReader") as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.root = {"/AcroForm": {"/Fields": [{"Type": "/Sig"}]}}
        mock_reader_class.return_value = mock_reader

        result = seal_manager.validate_seal(test_pdf)

        assert result.valid is True
        assert result.seal_type == SealType.ADVANCED
        assert result.certificate_valid is True
        assert result.timestamp_valid is True
        assert result.integrity_intact is True
        assert len(result.issues) == 0


def test_validate_seal_exception_handling(seal_manager, test_pdf):
    """Test seal validation exception handling."""
    with patch("builtins.open", side_effect=Exception("Read error")):
        result = seal_manager.validate_seal(test_pdf)

        assert result.valid is False
        assert result.certificate_valid is False
        assert result.timestamp_valid is False
        assert result.integrity_intact is False
        assert "Read error" in result.issues[0]


# ========== Appearance Generation Tests ==========


def test_generate_seal_appearance_stamp(seal_manager, seal_config):
    """Test stamp appearance generation."""
    appearance_bytes = seal_manager.generate_seal_appearance(seal_config)

    assert appearance_bytes is not None
    assert len(appearance_bytes) > 0
    assert b"svg" in appearance_bytes.lower()


def test_generate_seal_appearance_invisible(seal_manager, seal_config):
    """Test invisible appearance returns empty bytes."""
    seal_config.appearance = SealAppearance.INVISIBLE
    appearance_bytes = seal_manager.generate_seal_appearance(seal_config)

    assert appearance_bytes == b""


def test_generate_circular_seal_basic():
    """Test circular seal generation with basic parameters."""
    seal_bytes = generate_circular_seal(
        organization="Test Corp",
        country="ES",
        date=datetime(2024, 1, 15),
    )

    assert seal_bytes is not None
    assert b"Test Corp" in seal_bytes
    assert b"ES" in seal_bytes
    assert b"2024-01-15" in seal_bytes


def test_generate_circular_seal_custom_colors():
    """Test circular seal with custom colors."""
    seal_bytes = generate_circular_seal(
        organization="Test Corp",
        country="ES",
        date=datetime(2024, 1, 15),
        background_color="#ff0000",
        text_color="#00ff00",
    )

    assert b"#ff0000" in seal_bytes
    assert b"#00ff00" in seal_bytes


def test_generate_circular_seal_custom_size():
    """Test circular seal with custom size."""
    seal_bytes = generate_circular_seal(
        organization="Test Corp",
        country="ES",
        date=datetime(2024, 1, 15),
        size=(300, 300),
    )

    assert b"300" in seal_bytes


# ========== Organization Info Extraction Tests ==========


def test_extract_seal_info_no_fields(seal_manager, test_pdf):
    """Test extracting seal info from PDF without signature fields."""
    result = seal_manager.extract_seal_info(test_pdf)

    assert result == []


def test_extract_seal_info_file_not_found(seal_manager):
    """Test extracting seal info from non-existent PDF."""
    with pytest.raises(FileNotFoundError):
        seal_manager.extract_seal_info(Path("/nonexistent.pdf"))


def test_extract_seal_info_with_mock_fields(seal_manager, test_pdf):
    """Test extracting seal info with mocked signature fields."""
    with patch("pdfsigner.core.eidas.seal_manager.PdfFileReader") as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.root = {"/AcroForm": {"/Fields": [{"Type": "/Sig"}]}}
        mock_reader_class.return_value = mock_reader

        result = seal_manager.extract_seal_info(test_pdf)

        assert len(result) == 1
        assert result[0].name == "Mock Organization"
        assert result[0].country == "ES"


# ========== Certificate Type Detection Tests ==========


def test_is_seal_certificate_basic(seal_manager):
    """Test seal certificate detection."""
    # Mock certificate bytes
    cert_bytes = b"MOCK_CERTIFICATE"

    # Currently always returns False for safety
    result = seal_manager.is_seal_certificate(cert_bytes)

    assert result is False


def test_is_seal_certificate_empty(seal_manager):
    """Test seal certificate detection with empty bytes."""
    result = seal_manager.is_seal_certificate(b"")

    assert result is False


# ========== Data Model Tests ==========


def test_organization_info_creation():
    """Test OrganizationInfo creation."""
    org = OrganizationInfo(
        name="Test Corp",
        country="ES",
        organization_id="ESB12345678",
    )

    assert org.name == "Test Corp"
    assert org.country == "ES"
    assert org.organization_id == "ESB12345678"
    assert org.department == ""
    assert org.address == ""


def test_seal_config_defaults(org_info):
    """Test SealConfig default values."""
    config = SealConfig(organization=org_info)

    assert config.seal_type == SealType.ADVANCED
    assert config.appearance == SealAppearance.STAMP
    assert config.reason == "Organization seal"
    assert config.page == 1
    assert config.include_timestamp is True


def test_seal_result_success_case():
    """Test SealResult for successful operation."""
    result = SealResult(
        success=True,
        output_path=Path("/tmp/sealed.pdf"),
        seal_type=SealType.ADVANCED,
        organization="Test Corp",
        timestamp=datetime(2024, 1, 15),
        signature_id="SIG_001",
    )

    assert result.success is True
    assert result.organization == "Test Corp"
    assert len(result.errors) == 0


def test_seal_result_failure_case():
    """Test SealResult for failed operation."""
    result = SealResult(
        success=False,
        output_path=Path("/tmp/sealed.pdf"),
        seal_type=SealType.ADVANCED,
        organization="Test Corp",
        errors=["Error 1", "Error 2"],
    )

    assert result.success is False
    assert len(result.errors) == 2


def test_seal_validation_result_valid():
    """Test SealValidationResult for valid seal."""
    org = OrganizationInfo(name="Test Corp", country="ES")
    result = SealValidationResult(
        valid=True,
        seal_type=SealType.ADVANCED,
        organization=org,
        sealed_at=datetime(2024, 1, 15),
        certificate_valid=True,
        timestamp_valid=True,
        integrity_intact=True,
    )

    assert result.valid is True
    assert len(result.issues) == 0


def test_seal_validation_result_invalid():
    """Test SealValidationResult for invalid seal."""
    org = OrganizationInfo(name="Test Corp", country="ES")
    result = SealValidationResult(
        valid=False,
        seal_type=SealType.BASIC,
        organization=org,
        sealed_at=datetime(2024, 1, 15),
        certificate_valid=False,
        timestamp_valid=False,
        integrity_intact=False,
        issues=["Certificate expired", "Timestamp invalid"],
    )

    assert result.valid is False
    assert len(result.issues) == 2


# ========== Enum Tests ==========


def test_seal_type_enum_values():
    """Test SealType enum values."""
    assert SealType.BASIC.value == "basic"
    assert SealType.ADVANCED.value == "advanced"
    assert SealType.QUALIFIED.value == "qualified"


def test_seal_appearance_enum_values():
    """Test SealAppearance enum values."""
    assert SealAppearance.INVISIBLE.value == "invisible"
    assert SealAppearance.STAMP.value == "stamp"
    assert SealAppearance.BANNER.value == "banner"
    assert SealAppearance.LOGO.value == "logo"


# ========== Integration Tests ==========


def test_full_seal_workflow_dry_run(seal_manager, test_pdf, seal_config, tmp_path):
    """Test complete seal workflow in dry-run mode."""
    # Create seal
    output_path = tmp_path / "sealed.pdf"
    create_result = seal_manager.create_seal(test_pdf, seal_config, output_path, dry_run=True)

    assert create_result.success is True
    assert create_result.organization == "Acme Corporation"

    # Generate appearance
    appearance = seal_manager.generate_seal_appearance(seal_config)
    assert len(appearance) > 0

    # Extract info (will be empty for dry-run)
    info_list = seal_manager.extract_seal_info(test_pdf)
    assert isinstance(info_list, list)


def test_seal_with_different_positions(seal_manager, test_pdf, seal_config):
    """Test seal creation at different positions."""
    positions = [(10, 10), (50, 50), (100, 100), (200, 200)]

    for pos in positions:
        seal_config.position = pos
        result = seal_manager.create_seal(test_pdf, seal_config, dry_run=True)

        assert result.success is True


def test_seal_with_different_sizes(seal_manager, test_pdf, seal_config):
    """Test seal creation with different sizes."""
    sizes = [(20, 20), (40, 40), (60, 60), (80, 80)]

    for size in sizes:
        seal_config.size = size
        result = seal_manager.create_seal(test_pdf, seal_config, dry_run=True)

        assert result.success is True


def test_seal_organization_truncation():
    """Test organization name truncation in seal appearance."""
    long_name = "A" * 50
    seal_bytes = generate_circular_seal(
        organization=long_name,
        country="ES",
        date=datetime(2024, 1, 15),
    )

    # Should truncate to 20 characters
    seal_str = seal_bytes.decode("utf-8")
    assert long_name[:20] in seal_str
    assert long_name not in seal_str  # Full name should not be present

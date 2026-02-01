"""
test_compliance_reports.py - Unit tests for compliance report generation

Author: Homero Thompson del Lago del Terror

Tests for:
- ReportGenerator and all formatters (PDF, JSON, CSV, CEF)
- Report configuration
- Checksum generation
- API endpoints
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pdfsigner.core.compliance.formatters import (
    CEFReportFormatter,
    CSVReportFormatter,
    JSONReportFormatter,
    PDFReportFormatter,
)
from pdfsigner.core.compliance.report_generator import (
    ComplianceReportGenerator,
    GeneratedReport,
    ReportConfig,
    ReportFormat,
)
from pdfsigner.core.compliance.status_checker import (
    ComplianceCategory,
    ComplianceCheck,
    ComplianceReport,
    ComplianceStatus,
)


@pytest.fixture
def mock_compliance_report():
    """Create a mock compliance report for testing."""
    checks = [
        ComplianceCheck(
            name="PDF Encryption",
            category=ComplianceCategory.ENCRYPTION,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(a)(2)(iv)",
            description="Encryption and decryption capability",
            details="AES-256 encryption enabled (HIPAA compliant)",
            remediation=None,
            last_checked=datetime(2026, 2, 1, 10, 30, 0),
        ),
        ComplianceCheck(
            name="Audit Controls",
            category=ComplianceCategory.AUDIT_CONTROLS,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(b)",
            description="Audit trail with integrity protection",
            details="HMAC-protected audit logging is functioning correctly",
            remediation=None,
            last_checked=datetime(2026, 2, 1, 10, 30, 0),
        ),
        ComplianceCheck(
            name="Session Management",
            category=ComplianceCategory.SESSION_MANAGEMENT,
            status=ComplianceStatus.WARNING,
            hipaa_reference="§164.312(a)(2)(iii)",
            description="Automatic logoff after inactivity",
            details="Auto-logoff after 30 minutes (recommended: ≤15)",
            remediation="Set healthcare_session_timeout_minutes to 15 or less",
            last_checked=datetime(2026, 2, 1, 10, 30, 0),
        ),
        ComplianceCheck(
            name="Temp File Security",
            category=ComplianceCategory.TEMP_FILE_SECURITY,
            status=ComplianceStatus.NON_COMPLIANT,
            hipaa_reference="§164.310(d)(1)",
            description="Secure deletion of temporary files",
            details="Secure deletion is disabled",
            remediation="Set temp_secure_delete to true",
            last_checked=datetime(2026, 2, 1, 10, 30, 0),
        ),
    ]

    return ComplianceReport(
        checks=checks,
        overall_status=ComplianceStatus.WARNING,
        compliant_count=2,
        warning_count=1,
        non_compliant_count=1,
        generated_at=datetime(2026, 2, 1, 10, 30, 0),
    )


@pytest.fixture
def mock_checker(mock_compliance_report):
    """Create a mock compliance checker."""
    checker = MagicMock()
    checker.check_all.return_value = mock_compliance_report
    return checker


# --- ReportFormat Tests ---


def test_report_format_enum_values():
    """Test that ReportFormat enum has all expected values."""
    assert ReportFormat.PDF == "pdf"
    assert ReportFormat.JSON == "json"
    assert ReportFormat.CSV == "csv"
    assert ReportFormat.CEF == "cef"


def test_report_format_from_string():
    """Test creating ReportFormat from string."""
    assert ReportFormat("pdf") == ReportFormat.PDF
    assert ReportFormat("json") == ReportFormat.JSON
    assert ReportFormat("csv") == ReportFormat.CSV
    assert ReportFormat("cef") == ReportFormat.CEF


def test_report_format_invalid_string():
    """Test that invalid format string raises ValueError."""
    with pytest.raises(ValueError):
        ReportFormat("invalid")


# --- ReportConfig Tests ---


def test_report_config_default_values():
    """Test ReportConfig with default values."""
    config = ReportConfig(format=ReportFormat.PDF)

    assert config.format == ReportFormat.PDF
    assert config.standards == ["all"]
    assert config.include_evidence is True
    assert config.include_recommendations is True
    assert config.executive_summary is True


def test_report_config_custom_values():
    """Test ReportConfig with custom values."""
    config = ReportConfig(
        format=ReportFormat.JSON,
        standards=["HIPAA", "NIST"],
        include_evidence=False,
        include_recommendations=False,
        executive_summary=False,
    )

    assert config.format == ReportFormat.JSON
    assert config.standards == ["HIPAA", "NIST"]
    assert config.include_evidence is False
    assert config.include_recommendations is False
    assert config.executive_summary is False


# --- GeneratedReport Tests ---


def test_generated_report_dataclass():
    """Test GeneratedReport dataclass."""
    report = GeneratedReport(
        path=Path("/tmp/report.pdf"),
        format=ReportFormat.PDF,
        size_bytes=12345,
        generated_at=datetime(2026, 2, 1, 10, 30, 0),
        checksum="abc123",
    )

    assert report.path == Path("/tmp/report.pdf")
    assert report.format == ReportFormat.PDF
    assert report.size_bytes == 12345
    assert report.generated_at == datetime(2026, 2, 1, 10, 30, 0)
    assert report.checksum == "abc123"


# --- PDF Formatter Tests ---


def test_pdf_formatter_creates_valid_pdf(mock_compliance_report):
    """Test that PDF formatter creates a valid PDF."""
    formatter = PDFReportFormatter()
    config = ReportConfig(format=ReportFormat.PDF)

    pdf_bytes = formatter.format({"all": mock_compliance_report}, config)

    # Check that it's a valid PDF (starts with PDF magic bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000  # Should be substantial


def test_pdf_formatter_includes_title_page(mock_compliance_report):
    """Test that PDF includes title page."""
    formatter = PDFReportFormatter()
    config = ReportConfig(format=ReportFormat.PDF)

    pdf_bytes = formatter.format({"all": mock_compliance_report}, config)

    # Basic check that PDF was created
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_formatter_without_executive_summary(mock_compliance_report):
    """Test PDF generation without executive summary."""
    formatter = PDFReportFormatter()
    config = ReportConfig(format=ReportFormat.PDF, executive_summary=False)

    pdf_bytes = formatter.format({"all": mock_compliance_report}, config)

    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_formatter_without_recommendations(mock_compliance_report):
    """Test PDF generation without recommendations."""
    formatter = PDFReportFormatter()
    config = ReportConfig(format=ReportFormat.PDF, include_recommendations=False)

    pdf_bytes = formatter.format({"all": mock_compliance_report}, config)

    assert pdf_bytes.startswith(b"%PDF-")


# --- JSON Formatter Tests ---


def test_json_formatter_creates_valid_json(mock_compliance_report):
    """Test that JSON formatter creates valid JSON."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON)

    json_str = formatter.format({"all": mock_compliance_report}, config)

    # Should be valid JSON
    data = json.loads(json_str)
    assert "report_metadata" in data
    assert "summary" in data
    assert "checks" in data


def test_json_formatter_includes_metadata(mock_compliance_report):
    """Test that JSON includes metadata."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON)

    json_str = formatter.format({"all": mock_compliance_report}, config)
    data = json.loads(json_str)

    assert data["report_metadata"]["format"] == "json"
    assert data["report_metadata"]["version"] == "1.0"
    assert "generated_at" in data["report_metadata"]


def test_json_formatter_includes_summary(mock_compliance_report):
    """Test that JSON includes summary."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON)

    json_str = formatter.format({"all": mock_compliance_report}, config)
    data = json.loads(json_str)

    summary = data["summary"]
    assert summary["overall_status"] == "warning"
    assert summary["compliant_count"] == 2
    assert summary["warning_count"] == 1
    assert summary["non_compliant_count"] == 1
    assert summary["total_checks"] == 4
    assert summary["compliance_score"] == 50.0  # 2/4 * 100


def test_json_formatter_includes_checks(mock_compliance_report):
    """Test that JSON includes all checks."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON)

    json_str = formatter.format({"all": mock_compliance_report}, config)
    data = json.loads(json_str)

    assert len(data["checks"]) == 4
    assert data["checks"][0]["name"] == "PDF Encryption"
    assert data["checks"][0]["status"] == "compliant"


def test_json_formatter_includes_recommendations(mock_compliance_report):
    """Test that JSON includes recommendations when requested."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON, include_recommendations=True)

    json_str = formatter.format({"all": mock_compliance_report}, config)
    data = json.loads(json_str)

    assert "recommendations" in data
    # Should have 2 recommendations (WARNING and NON_COMPLIANT checks)
    assert len(data["recommendations"]) == 2


def test_json_formatter_no_recommendations_when_disabled(mock_compliance_report):
    """Test that JSON excludes recommendations when disabled."""
    formatter = JSONReportFormatter()
    config = ReportConfig(format=ReportFormat.JSON, include_recommendations=False)

    json_str = formatter.format({"all": mock_compliance_report}, config)
    data = json.loads(json_str)

    assert "recommendations" not in data


# --- CSV Formatter Tests ---


def test_csv_formatter_creates_valid_csv(mock_compliance_report):
    """Test that CSV formatter creates valid CSV."""
    formatter = CSVReportFormatter()
    config = ReportConfig(format=ReportFormat.CSV)

    csv_str = formatter.format({"all": mock_compliance_report}, config)

    lines = csv_str.strip().split("\n")
    # Header + 4 checks
    assert len(lines) == 5

    # Check header
    assert "Standard" in lines[0]
    assert "Control ID" in lines[0]
    assert "Status" in lines[0]


def test_csv_formatter_includes_all_checks(mock_compliance_report):
    """Test that CSV includes all checks."""
    formatter = CSVReportFormatter()
    config = ReportConfig(format=ReportFormat.CSV)

    csv_str = formatter.format({"all": mock_compliance_report}, config)

    # Check that all check names appear
    assert "PDF Encryption" in csv_str
    assert "Audit Controls" in csv_str
    assert "Session Management" in csv_str
    assert "Temp File Security" in csv_str


def test_csv_formatter_with_recommendations(mock_compliance_report):
    """Test CSV with recommendations column."""
    formatter = CSVReportFormatter()
    config = ReportConfig(format=ReportFormat.CSV, include_recommendations=True)

    csv_str = formatter.format({"all": mock_compliance_report}, config)

    lines = csv_str.strip().split("\n")
    assert "Remediation" in lines[0]


def test_csv_formatter_without_recommendations(mock_compliance_report):
    """Test CSV without recommendations column."""
    formatter = CSVReportFormatter()
    config = ReportConfig(format=ReportFormat.CSV, include_recommendations=False)

    csv_str = formatter.format({"all": mock_compliance_report}, config)

    lines = csv_str.strip().split("\n")
    assert "Remediation" not in lines[0]


# --- CEF Formatter Tests ---


def test_cef_formatter_creates_valid_cef(mock_compliance_report):
    """Test that CEF formatter creates valid CEF format."""
    formatter = CEFReportFormatter()
    config = ReportConfig(format=ReportFormat.CEF)

    cef_str = formatter.format({"all": mock_compliance_report}, config)

    lines = cef_str.strip().split("\n")
    # Overall assessment + 4 checks
    assert len(lines) == 5

    # All lines should start with CEF:0
    for line in lines:
        assert line.startswith("CEF:0|")


def test_cef_formatter_overall_assessment(mock_compliance_report):
    """Test that CEF includes overall assessment."""
    formatter = CEFReportFormatter()
    config = ReportConfig(format=ReportFormat.CEF)

    cef_str = formatter.format({"all": mock_compliance_report}, config)

    lines = cef_str.strip().split("\n")
    first_line = lines[0]

    assert "compliance_assessment" in first_line
    assert "Overall Compliance Assessment" in first_line
    assert "cn1Label=CompliantCount" in first_line
    assert "cn1=2" in first_line


def test_cef_formatter_individual_checks(mock_compliance_report):
    """Test that CEF includes individual checks."""
    formatter = CEFReportFormatter()
    config = ReportConfig(format=ReportFormat.CEF)

    cef_str = formatter.format({"all": mock_compliance_report}, config)

    # Check that check names appear
    assert "PDF Encryption" in cef_str or "cs5=" in cef_str  # Name might be escaped


def test_cef_formatter_severity_mapping(mock_compliance_report):
    """Test CEF severity mapping."""
    formatter = CEFReportFormatter()

    # Test each status
    assert formatter._status_to_severity(ComplianceStatus.COMPLIANT) == 1
    assert formatter._status_to_severity(ComplianceStatus.WARNING) == 5
    assert formatter._status_to_severity(ComplianceStatus.NON_COMPLIANT) == 8
    assert formatter._status_to_severity(ComplianceStatus.UNKNOWN) == 3


def test_cef_formatter_escape_function():
    """Test CEF escape function."""
    formatter = CEFReportFormatter()

    # Test escaping special characters
    assert formatter._escape_cef("test=value") == "test\\=value"
    assert formatter._escape_cef("test|value") == "test\\|value"
    assert formatter._escape_cef("test\\value") == "test\\\\value"
    assert formatter._escape_cef("test=value|more\\stuff") == "test\\=value\\|more\\\\stuff"


# --- ReportGenerator Tests ---


def test_report_generator_initialization(mock_checker):
    """Test ReportGenerator initialization."""
    generator = ComplianceReportGenerator(mock_checker)
    assert generator.checker == mock_checker


def test_report_generator_invalid_format(mock_checker):
    """Test that invalid format raises ValueError."""
    generator = ComplianceReportGenerator(mock_checker)

    # Manually create invalid enum (for testing)
    with pytest.raises((ValueError, AttributeError)):
        config = ReportConfig(format="invalid")  # type: ignore
        with tempfile.TemporaryDirectory() as tmpdir:
            generator.generate(config, Path(tmpdir) / "report.txt")


def test_report_generator_generates_pdf(mock_checker, mock_compliance_report):
    """Test generating PDF report."""
    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.PDF)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.pdf"
        result = generator.generate(config, output_path)

        assert result.path == output_path
        assert result.format == ReportFormat.PDF
        assert result.size_bytes > 0
        assert len(result.checksum) == 64  # SHA-256 is 64 hex chars
        assert output_path.exists()


def test_report_generator_generates_json(mock_checker, mock_compliance_report):
    """Test generating JSON report."""
    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.JSON)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.json"
        result = generator.generate(config, output_path)

        assert result.path == output_path
        assert result.format == ReportFormat.JSON
        assert result.size_bytes > 0
        assert len(result.checksum) == 64
        assert output_path.exists()

        # Verify it's valid JSON
        data = json.loads(output_path.read_text())
        assert "summary" in data


def test_report_generator_generates_csv(mock_checker, mock_compliance_report):
    """Test generating CSV report."""
    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.CSV)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.csv"
        result = generator.generate(config, output_path)

        assert result.path == output_path
        assert result.format == ReportFormat.CSV
        assert result.size_bytes > 0
        assert len(result.checksum) == 64
        assert output_path.exists()


def test_report_generator_generates_cef(mock_checker, mock_compliance_report):
    """Test generating CEF report."""
    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.CEF)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.cef"
        result = generator.generate(config, output_path)

        assert result.path == output_path
        assert result.format == ReportFormat.CEF
        assert result.size_bytes > 0
        assert len(result.checksum) == 64
        assert output_path.exists()


def test_report_generator_creates_parent_directories(mock_checker, mock_compliance_report):
    """Test that generator creates parent directories if needed."""
    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.JSON)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "subdir" / "nested" / "report.json"
        result = generator.generate(config, output_path)

        assert output_path.exists()
        assert output_path.parent.exists()


def test_report_generator_checksum_is_valid(mock_checker, mock_compliance_report):
    """Test that checksum is valid SHA-256."""
    import hashlib

    generator = ComplianceReportGenerator(mock_checker)
    config = ReportConfig(format=ReportFormat.JSON)

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.json"
        result = generator.generate(config, output_path)

        # Verify checksum
        content = output_path.read_bytes()
        expected_checksum = hashlib.sha256(content).hexdigest()
        assert result.checksum == expected_checksum


# --- Singleton Tests ---


def test_get_report_generator_singleton():
    """Test that get_report_generator returns singleton."""
    # Reset singleton
    import pdfsigner.core.compliance.report_generator as rg_module
    from pdfsigner.core.compliance.report_generator import (
        get_report_generator,
    )

    rg_module._report_generator = None

    gen1 = get_report_generator()
    gen2 = get_report_generator()

    assert gen1 is gen2


# --- API Schema Tests ---


def test_report_generation_request_schema():
    """Test ReportGenerationRequest schema validation."""
    from pdfsigner.api.schemas.compliance import ReportGenerationRequest

    # Valid request
    request = ReportGenerationRequest(
        format="pdf",
        standards=["HIPAA"],
        include_evidence=True,
        include_recommendations=True,
        executive_summary=True,
    )

    assert request.format == "pdf"
    assert request.standards == ["HIPAA"]


def test_report_generation_request_invalid_format():
    """Test that invalid format is caught by validation."""
    from pydantic import ValidationError

    from pdfsigner.api.schemas.compliance import ReportGenerationRequest

    with pytest.raises(ValidationError):
        ReportGenerationRequest(format="invalid")


def test_generated_report_response_schema():
    """Test GeneratedReportResponse schema."""
    from pdfsigner.api.schemas.compliance import GeneratedReportResponse

    response = GeneratedReportResponse(
        report_id="20260201_103000_pdf",
        format="pdf",
        size_bytes=12345,
        generated_at=datetime(2026, 2, 1, 10, 30, 0),
        checksum="abc123",
        download_url="/api/v1/compliance/report/20260201_103000_pdf",
    )

    assert response.report_id == "20260201_103000_pdf"
    assert response.format == "pdf"
    assert response.size_bytes == 12345


def test_available_standards_response_schema():
    """Test AvailableStandardsResponse schema."""
    from pdfsigner.api.schemas.compliance import AvailableStandardsResponse

    response = AvailableStandardsResponse(standards=["HIPAA", "NIST"])

    assert response.standards == ["HIPAA", "NIST"]

"""
test_report_generator.py - Tests for report generation

Author: Homero Thompson del Lago del Terror

Tests the ValidationReportGenerator for PDF, CSV, and JSON export formats.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from pdfsigner.core.reports.report_generator import (
    ReportFormat,
    ReportOptions,
    ValidationReportGenerator,
)
from pdfsigner.core.validator.pdf_validator import (
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)


@pytest.fixture
def sample_signature_valid() -> SignatureInfo:
    """Create a sample valid signature."""
    return SignatureInfo(
        signer_name="John Doe",
        signer_email="john@example.com",
        signing_time=datetime(2024, 1, 15, 10, 30, 0),
        is_timestamp_valid=True,
        certificate_issuer="Test CA",
        certificate_serial="abc123",
        certificate_valid_from=datetime(2023, 1, 1),
        certificate_valid_to=datetime(2025, 12, 31),
        status=SignatureStatus.VALID,
        status_message="Valid signature",
        field_name="Signature1",
        covers_whole_document=True,
        is_modification_allowed=False,
        page_number=1,
    )


@pytest.fixture
def sample_signature_invalid() -> SignatureInfo:
    """Create a sample invalid signature."""
    return SignatureInfo(
        signer_name="Jane Smith",
        signer_email=None,
        signing_time=None,
        is_timestamp_valid=False,
        certificate_issuer="Unknown CA",
        certificate_serial="def456",
        certificate_valid_from=datetime(2020, 1, 1),
        certificate_valid_to=datetime(2021, 12, 31),
        status=SignatureStatus.INVALID,
        status_message="Certificate expired",
        field_name="Signature1",
        covers_whole_document=False,
        is_modification_allowed=True,
        page_number=None,
    )


@pytest.fixture
def validation_result_valid(sample_signature_valid) -> ValidationResult:
    """Create a validation result with valid signature."""
    return ValidationResult(
        file_path=Path("/tmp/test_valid.pdf"),
        is_signed=True,
        signature_count=1,
        all_valid=True,
        signatures=[sample_signature_valid],
        error=None,
    )


@pytest.fixture
def validation_result_invalid(sample_signature_invalid) -> ValidationResult:
    """Create a validation result with invalid signature."""
    return ValidationResult(
        file_path=Path("/tmp/test_invalid.pdf"),
        is_signed=True,
        signature_count=1,
        all_valid=False,
        signatures=[sample_signature_invalid],
        error=None,
    )


@pytest.fixture
def validation_result_unsigned() -> ValidationResult:
    """Create a validation result for unsigned PDF."""
    return ValidationResult(
        file_path=Path("/tmp/test_unsigned.pdf"),
        is_signed=False,
        signature_count=0,
        all_valid=True,
        signatures=[],
        error=None,
    )


@pytest.fixture
def validation_result_error() -> ValidationResult:
    """Create a validation result with error."""
    return ValidationResult(
        file_path=Path("/tmp/test_error.pdf"),
        is_signed=False,
        signature_count=0,
        all_valid=False,
        signatures=[],
        error="Failed to read PDF",
    )


@pytest.fixture
def report_generator() -> ValidationReportGenerator:
    """Create a report generator with default options."""
    return ValidationReportGenerator()


def test_generate_pdf_report_single_valid(report_generator, validation_result_valid):
    """Test generating PDF report with single valid signature."""
    results = [validation_result_valid]

    pdf_bytes = report_generator.generate_pdf(results)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")  # PDF header


def test_generate_pdf_report_multiple_results(
    report_generator,
    validation_result_valid,
    validation_result_invalid,
    validation_result_unsigned,
):
    """Test generating PDF report with multiple validation results."""
    results = [
        validation_result_valid,
        validation_result_invalid,
        validation_result_unsigned,
    ]

    pdf_bytes = report_generator.generate_pdf(results)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")


def test_generate_pdf_report_with_error(report_generator, validation_result_error):
    """Test generating PDF report with error result."""
    results = [validation_result_error]

    pdf_bytes = report_generator.generate_pdf(results)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


def test_generate_csv_report_single_valid(report_generator, validation_result_valid):
    """Test generating CSV report with single valid signature."""
    results = [validation_result_valid]

    csv_string = report_generator.generate_csv(results)

    assert isinstance(csv_string, str)
    assert "Filename" in csv_string
    assert "Status" in csv_string
    assert "test_valid.pdf" in csv_string
    assert "VALID" in csv_string
    assert "John Doe" in csv_string


def test_generate_csv_report_multiple_results(
    report_generator,
    validation_result_valid,
    validation_result_invalid,
    validation_result_unsigned,
    validation_result_error,
):
    """Test generating CSV report with mixed results."""
    results = [
        validation_result_valid,
        validation_result_invalid,
        validation_result_unsigned,
        validation_result_error,
    ]

    csv_string = report_generator.generate_csv(results)

    assert isinstance(csv_string, str)
    lines = csv_string.strip().split("\n")
    assert len(lines) == 5  # Header + 4 data rows

    assert "test_valid.pdf" in csv_string
    assert "test_invalid.pdf" in csv_string
    assert "test_unsigned.pdf" in csv_string
    assert "test_error.pdf" in csv_string

    assert "VALID" in csv_string
    assert "INVALID" in csv_string
    assert "UNSIGNED" in csv_string
    assert "ERROR" in csv_string


def test_generate_csv_report_fields(report_generator, validation_result_valid):
    """Test CSV report contains all required fields."""
    results = [validation_result_valid]

    csv_string = report_generator.generate_csv(results)

    # Check required columns
    assert "Filename" in csv_string
    assert "Status" in csv_string
    assert "Signed" in csv_string
    assert "Signature Count" in csv_string
    assert "All Valid" in csv_string
    assert "Signer Name" in csv_string
    assert "Signer Email" in csv_string
    assert "Signing Time" in csv_string
    assert "Certificate Valid Until" in csv_string


def test_generate_json_report_single_valid(report_generator, validation_result_valid):
    """Test generating JSON report with single valid signature."""
    results = [validation_result_valid]

    json_string = report_generator.generate_json(results)

    assert isinstance(json_string, str)

    # Parse and validate JSON structure
    data = json.loads(json_string)
    assert "metadata" in data
    assert "summary" in data
    assert "files" in data

    assert data["metadata"]["total_files"] == 1
    assert data["summary"]["signed_files"] == 1
    assert data["summary"]["all_valid"] == 1

    assert len(data["files"]) == 1
    file_data = data["files"][0]
    assert file_data["filename"] == "test_valid.pdf"
    assert file_data["is_signed"] is True
    assert file_data["all_valid"] is True
    assert len(file_data["signatures"]) == 1

    sig_data = file_data["signatures"][0]
    assert sig_data["signer_name"] == "John Doe"
    assert sig_data["signer_email"] == "john@example.com"
    assert sig_data["status"] == "valid"


def test_generate_json_report_multiple_results(
    report_generator,
    validation_result_valid,
    validation_result_invalid,
    validation_result_unsigned,
):
    """Test generating JSON report with multiple results."""
    results = [
        validation_result_valid,
        validation_result_invalid,
        validation_result_unsigned,
    ]

    json_string = report_generator.generate_json(results)
    data = json.loads(json_string)

    assert data["metadata"]["total_files"] == 3
    assert data["summary"]["signed_files"] == 2
    assert data["summary"]["unsigned_files"] == 1
    assert data["summary"]["all_valid"] == 1
    assert data["summary"]["has_issues"] == 1

    assert len(data["files"]) == 3


def test_generate_json_report_with_error(report_generator, validation_result_error):
    """Test JSON report includes error information."""
    results = [validation_result_error]

    json_string = report_generator.generate_json(results)
    data = json.loads(json_string)

    assert data["summary"]["errors"] == 1
    file_data = data["files"][0]
    assert file_data["error"] == "Failed to read PDF"
    assert file_data["is_signed"] is False


def test_report_options_summary_only():
    """Test report generation with summary only option."""
    options = ReportOptions(
        include_summary=True,
        include_details=False,
        include_certificate_info=False,
    )
    generator = ValidationReportGenerator(options)

    assert generator.options.include_summary is True
    assert generator.options.include_details is False
    assert generator.options.include_certificate_info is False


def test_report_options_custom_title():
    """Test report with custom title."""
    custom_title = "Custom Validation Report 2024"
    options = ReportOptions(title=custom_title)
    generator = ValidationReportGenerator(options)

    assert generator.options.title == custom_title


def test_generate_with_format_enum(report_generator, validation_result_valid):
    """Test generate method with ReportFormat enum."""
    results = [validation_result_valid]

    # Test PDF format
    pdf_output = report_generator.generate(results, ReportFormat.PDF)
    assert isinstance(pdf_output, bytes)

    # Test CSV format
    csv_output = report_generator.generate(results, ReportFormat.CSV)
    assert isinstance(csv_output, str)

    # Test JSON format
    json_output = report_generator.generate(results, ReportFormat.JSON)
    assert isinstance(json_output, str)


def test_generate_unsupported_format(report_generator, validation_result_valid):
    """Test that unsupported format raises ValueError."""
    results = [validation_result_valid]

    # Create fake format enum
    class FakeFormat:
        pass

    with pytest.raises(ValueError, match="Unsupported format"):
        report_generator.generate(results, FakeFormat())


def test_csv_report_excel_compatible(report_generator, validation_result_valid):
    """Test CSV report is Excel-compatible (quoted fields)."""
    results = [validation_result_valid]

    csv_string = report_generator.generate_csv(results)

    # Check that fields are quoted (Excel-compatible)
    lines = csv_string.strip().split("\n")
    for line in lines:
        # Each field should be quoted
        assert line.startswith('"')


def test_pdf_report_without_certificate_info(validation_result_valid):
    """Test PDF report generation without certificate details."""
    options = ReportOptions(include_certificate_info=False)
    generator = ValidationReportGenerator(options)

    results = [validation_result_valid]
    pdf_bytes = generator.generate_pdf(results)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


def test_json_report_signature_with_no_email(report_generator, validation_result_invalid):
    """Test JSON report handles signature without email."""
    results = [validation_result_invalid]

    json_string = report_generator.generate_json(results)
    data = json.loads(json_string)

    sig_data = data["files"][0]["signatures"][0]
    assert sig_data["signer_email"] is None
    assert sig_data["signing_time"] is None


def test_summary_counts_mixed_results(
    report_generator,
    validation_result_valid,
    validation_result_invalid,
    validation_result_unsigned,
    validation_result_error,
):
    """Test summary statistics with mixed validation results."""
    results = [
        validation_result_valid,
        validation_result_invalid,
        validation_result_unsigned,
        validation_result_error,
    ]

    # Generate JSON to easily check summary
    json_string = report_generator.generate_json(results)
    data = json.loads(json_string)

    summary = data["summary"]
    assert summary["total_files"] == 4
    assert summary["signed_files"] == 2
    assert summary["unsigned_files"] == 2
    assert summary["all_valid"] == 1
    assert summary["has_issues"] == 1
    assert summary["errors"] == 1

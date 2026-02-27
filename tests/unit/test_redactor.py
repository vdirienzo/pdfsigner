"""
Tests for PDF redactor module.

Tests cover:
- RedactionRegion validation
- Region-based redaction
- Pattern-based redaction
- Text removal verification
- Preview generation
- Audit logging integration
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import fitz  # PyMuPDF
import pytest

from pdfsigner.core.detection.pii_types import PIIMatch, PIIType, RedactionRegion
from pdfsigner.core.detection.redactor import (
    PDFRedactor,
    RedactionResult,
    get_pdf_redactor,
)
from pdfsigner.exceptions import PDFCorruptedError


class TestRedactionRegion:
    """Tests for RedactionRegion dataclass."""

    def test_valid_region_creation(self):
        """Test creating a valid redaction region."""
        region = RedactionRegion(
            page=0,
            x0=100.0,
            y0=200.0,
            x1=300.0,
            y1=250.0,
        )
        assert region.page == 0
        assert region.x0 == 100.0
        assert region.y0 == 200.0
        assert region.x1 == 300.0
        assert region.y1 == 250.0
        assert region.fill_color == (0, 0, 0)

    def test_region_with_replacement_text(self):
        """Test region with replacement text."""
        region = RedactionRegion(
            page=0,
            x0=100.0,
            y0=200.0,
            x1=300.0,
            y1=250.0,
            replacement_text="[REDACTED]",
        )
        assert region.replacement_text == "[REDACTED]"

    def test_region_with_custom_color(self):
        """Test region with custom fill color."""
        region = RedactionRegion(
            page=0,
            x0=100.0,
            y0=200.0,
            x1=300.0,
            y1=250.0,
            fill_color=(1.0, 0.0, 0.0),  # Red
        )
        assert region.fill_color == (1.0, 0.0, 0.0)

    def test_invalid_coordinates_x_raises(self):
        """Test that invalid X coordinates raise ValueError."""
        with pytest.raises(ValueError, match="Invalid coordinates"):
            RedactionRegion(
                page=0,
                x0=300.0,  # x0 > x1
                y0=200.0,
                x1=100.0,
                y1=250.0,
            )

    def test_invalid_coordinates_y_raises(self):
        """Test that invalid Y coordinates raise ValueError."""
        with pytest.raises(ValueError, match="Invalid coordinates"):
            RedactionRegion(
                page=0,
                x0=100.0,
                y0=300.0,  # y0 > y1
                x1=200.0,
                y1=250.0,
            )

    def test_invalid_color_component_raises(self):
        """Test that color components outside 0-1 range raise ValueError."""
        with pytest.raises(ValueError, match="Color components must be in range 0-1"):
            RedactionRegion(
                page=0,
                x0=100.0,
                y0=200.0,
                x1=300.0,
                y1=250.0,
                fill_color=(1.5, 0.0, 0.0),  # Invalid: > 1.0
            )

    def test_negative_color_component_raises(self):
        """Test that negative color components raise ValueError."""
        with pytest.raises(ValueError, match="Color components must be in range 0-1"):
            RedactionRegion(
                page=0,
                x0=100.0,
                y0=200.0,
                x1=300.0,
                y1=250.0,
                fill_color=(-0.1, 0.0, 0.0),  # Invalid: < 0.0
            )


class TestPIIMatchToRedactionRegion:
    """Tests for PIIMatch.to_redaction_region() conversion."""

    def test_convert_pii_match_to_region(self):
        """Test converting PIIMatch to RedactionRegion."""
        match = PIIMatch(
            pii_type=PIIType.SSN,
            value="123-45-6789",
            redacted_value="***-**-6789",
            confidence=0.95,
            start_pos=0,
            end_pos=11,
            page=0,
            bbox=(100.0, 200.0, 300.0, 220.0),
        )

        region = match.to_redaction_region()
        assert region.page == 0
        assert region.x0 == 100.0
        assert region.y0 == 200.0
        assert region.x1 == 300.0
        assert region.y1 == 220.0
        assert region.replacement_text == "***-**-6789"

    def test_convert_with_custom_text(self):
        """Test converting with custom replacement text."""
        match = PIIMatch(
            pii_type=PIIType.CREDIT_CARD,
            value="4111111111111111",
            redacted_value="****-****-****-1111",
            confidence=0.9,
            start_pos=0,
            end_pos=16,
            page=1,
            bbox=(50.0, 100.0, 150.0, 120.0),
        )

        region = match.to_redaction_region(replacement_text="[CC REDACTED]")
        assert region.replacement_text == "[CC REDACTED]"

    def test_convert_without_bbox_raises(self):
        """Test that converting without bbox raises ValueError."""
        match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="user@example.com",
            redacted_value="***@example.com",
            confidence=0.8,
            start_pos=0,
            end_pos=15,
            page=None,  # Missing
            bbox=None,  # Missing
        )

        with pytest.raises(ValueError, match="missing bbox or page"):
            match.to_redaction_region()


class TestRedactionResult:
    """Tests for RedactionResult dataclass."""

    def test_successful_result_str(self):
        """Test string representation of successful result."""
        result = RedactionResult(
            success=True,
            output_path="/tmp/doc_redacted.pdf",
            redaction_count=5,
            pages_affected=[0, 1, 2],
            input_path="/tmp/doc.pdf",
        )
        str_repr = str(result)
        assert "✓" in str_repr
        assert "5 regions" in str_repr
        assert "3 pages" in str_repr

    def test_failed_result_str(self):
        """Test string representation of failed result."""
        result = RedactionResult(
            success=False,
            output_path=None,
            redaction_count=0,
            errors=["File not found", "Invalid PDF"],
            input_path="/tmp/doc.pdf",
        )
        str_repr = str(result)
        assert "✗" in str_repr
        assert "failed" in str_repr.lower()


class TestPDFRedactor:
    """Tests for PDFRedactor class."""

    def test_redactor_initialization(self):
        """Test PDFRedactor initialization with defaults."""
        redactor = PDFRedactor()
        assert redactor.default_fill_color == (0, 0, 0)
        assert redactor.default_text_color == (1, 1, 1)

    def test_redactor_custom_colors(self):
        """Test PDFRedactor with custom colors."""
        redactor = PDFRedactor(
            default_fill_color=(0.5, 0.5, 0.5),
            default_text_color=(0.0, 0.0, 1.0),
        )
        assert redactor.default_fill_color == (0.5, 0.5, 0.5)
        assert redactor.default_text_color == (0.0, 0.0, 1.0)

    def test_singleton_get_pdf_redactor(self):
        """Test get_pdf_redactor returns singleton instance."""
        redactor1 = get_pdf_redactor()
        redactor2 = get_pdf_redactor()
        assert redactor1 is redactor2

    def test_redact_regions_file_not_found(self):
        """Test redacting non-existent file raises FileNotFoundError."""
        redactor = PDFRedactor()
        regions = [RedactionRegion(page=0, x0=100, y0=200, x1=300, y1=220)]

        with pytest.raises(FileNotFoundError):
            redactor.redact_regions("/nonexistent/file.pdf", regions, "/tmp/output.pdf")

    def test_redact_regions_empty_list(self):
        """Test redacting with empty regions list returns success."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            # Create a minimal valid PDF
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((50, 50), "Test content")
            doc.save(tmp.name)
            doc.close()

            try:
                redactor = PDFRedactor()
                result = redactor.redact_regions(
                    tmp.name,
                    [],  # Empty regions
                    tmp.name + "_out.pdf",
                )

                assert result.success
                assert result.redaction_count == 0
                assert len(result.pages_affected) == 0
            finally:
                Path(tmp.name).unlink(missing_ok=True)
                Path(tmp.name + "_out.pdf").unlink(missing_ok=True)

    def test_redact_regions_creates_output_file(self):
        """Test that redaction creates output file."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            # Create a test PDF
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "Sensitive: 123-45-6789")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()
                regions = [
                    RedactionRegion(
                        page=0, x0=100, y0=190, x1=300, y1=210, replacement_text="[REDACTED]"
                    )
                ]

                result = redactor.redact_regions(tmp.name, regions, output_path)

                assert result.success
                assert result.redaction_count == 1
                assert 0 in result.pages_affected
                assert Path(output_path).exists()

                # Verify output is valid PDF
                doc_out = fitz.open(output_path)
                assert len(doc_out) == 1
                doc_out.close()

            finally:
                Path(tmp.name).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)

    def test_redact_regions_removes_text(self):
        """Test that redaction actually removes underlying text."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            # Create a test PDF with text
            doc = fitz.open()
            page = doc.new_page()
            text_rect = page.insert_text((100, 200), "SECRET-DATA-123")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()
                regions = [
                    RedactionRegion(
                        page=0,
                        x0=95,
                        y0=185,
                        x1=250,
                        y1=215,
                    )
                ]

                result = redactor.redact_regions(tmp.name, regions, output_path)
                assert result.success

                # Verify text was removed (not just covered)
                doc_out = fitz.open(output_path)
                page_out = doc_out[0]
                text_after = page_out.get_text("text", clip=fitz.Rect(95, 185, 250, 215))
                doc_out.close()

                # Text should be removed or replaced
                assert "SECRET-DATA-123" not in text_after

            finally:
                Path(tmp.name).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)

    def test_redact_regions_multiple_pages(self):
        """Test redacting regions on multiple pages."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            # Create multi-page PDF
            doc = fitz.open()
            for i in range(3):
                page = doc.new_page()
                page.insert_text((100, 200), f"Page {i} sensitive data")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()
                regions = [
                    RedactionRegion(page=0, x0=100, y0=190, x1=300, y1=210),
                    RedactionRegion(page=1, x0=100, y0=190, x1=300, y1=210),
                    RedactionRegion(page=2, x0=100, y0=190, x1=300, y1=210),
                ]

                result = redactor.redact_regions(tmp.name, regions, output_path)

                assert result.success
                assert result.redaction_count == 3
                assert set(result.pages_affected) == {0, 1, 2}

            finally:
                Path(tmp.name).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)

    def test_redact_regions_invalid_page_number(self):
        """Test redacting with invalid page number logs error but continues."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            # Create single-page PDF
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "Test content")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()
                regions = [
                    RedactionRegion(page=0, x0=100, y0=190, x1=300, y1=210),  # Valid
                    RedactionRegion(page=5, x0=100, y0=190, x1=300, y1=210),  # Invalid
                ]

                result = redactor.redact_regions(tmp.name, regions, output_path)

                assert result.success  # Should still succeed
                assert result.redaction_count == 1  # Only valid region
                assert len(result.errors) > 0  # Should log error
                assert any("Invalid page number" in err for err in result.errors)

            finally:
                Path(tmp.name).unlink(missing_ok=True)
                Path(output_path).unlink(missing_ok=True)

    def test_redact_by_pattern_no_detector(self):
        """Test pattern-based redaction fails gracefully without detector."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "SSN: 123-45-6789")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()

                # Set the module to None in sys.modules to trigger ImportError
                # on `from pdfsigner.core.detection.pdf_scanner import PDFScanner`
                with patch.dict(
                    "sys.modules",
                    {"pdfsigner.core.detection.pdf_scanner": None},
                ):
                    result = redactor.redact_by_pattern(
                        tmp.name,
                        pii_types=["ssn"],
                        output_path=output_path,
                    )

                    assert not result.success
                    assert "PII detector not available" in result.errors[0]

            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def test_redact_by_pattern_no_valid_types(self):
        """Test pattern-based redaction with no valid PII types."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "Test content")
            doc.save(tmp.name)
            doc.close()

            output_path = tmp.name + "_redacted.pdf"

            try:
                redactor = PDFRedactor()
                result = redactor.redact_by_pattern(
                    tmp.name,
                    pii_types=["invalid_type"],
                    output_path=output_path,
                )

                assert not result.success
                assert "No valid PII types" in result.errors[0]

            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def test_preview_redactions_generates_png(self):
        """Test preview generation returns PNG data."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "Preview test")
            doc.save(tmp.name)
            doc.close()

            try:
                redactor = PDFRedactor()
                regions = [RedactionRegion(page=0, x0=100, y0=190, x1=300, y1=210)]

                png_data = redactor.preview_redactions(tmp.name, regions, page_num=0)

                assert isinstance(png_data, bytes)
                assert len(png_data) > 0
                # PNG signature
                assert png_data[:8] == b"\x89PNG\r\n\x1a\n"

            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def test_preview_redactions_invalid_page_raises(self):
        """Test preview with invalid page number raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((100, 200), "Test")
            doc.save(tmp.name)
            doc.close()

            try:
                redactor = PDFRedactor()
                regions = [RedactionRegion(page=0, x0=100, y0=190, x1=300, y1=210)]

                with pytest.raises(ValueError, match="Invalid page number"):
                    redactor.preview_redactions(tmp.name, regions, page_num=10)

            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def test_preview_redactions_corrupted_pdf_raises(self):
        """Test preview with corrupted PDF raises PDFCorruptedError."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(b"Not a valid PDF")
            tmp.flush()

            try:
                redactor = PDFRedactor()
                regions = [RedactionRegion(page=0, x0=100, y0=190, x1=300, y1=210)]

                with pytest.raises(PDFCorruptedError):
                    redactor.preview_redactions(tmp.name, regions)

            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def test_log_redaction_event_success(self):
        """Test redaction event logging on success."""
        from pdfsigner.core.detection.redactor import _log_redaction_event

        # Mock both the AuditLogger and AuditEvent at the correct import location
        with (
            patch("pdfsigner.core.audit.audit_logger.AuditLogger") as mock_audit_logger,
            patch("pdfsigner.core.audit.audit_event.AuditEvent") as mock_audit_event,
        ):
            mock_logger_instance = Mock()
            mock_audit_logger.get_instance.return_value = mock_logger_instance
            mock_event_instance = Mock()
            mock_event_instance.details = {
                "operation": "redaction",
                "pii_types": ["ssn", "credit_card"],
                "redaction_count": 5,
                "pages_affected": [0, 1, 2],
            }
            mock_audit_event.return_value = mock_event_instance

            _log_redaction_event(
                pdf_path=Path("/tmp/test.pdf"),
                pii_types=["ssn", "credit_card"],
                redaction_count=5,
                pages_affected=[0, 1, 2],
            )

            # Verify AuditLogger was called to log the event
            mock_logger_instance.log_event.assert_called_once()

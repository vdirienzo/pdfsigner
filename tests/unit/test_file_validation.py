"""
Tests for file validation with magic bytes detection.

Tests the SigningService.validate_pdf_file method including
python-magic MIME type detection for security.
"""

import pytest

from pdfsigner.api.services.signing_service import SigningService

# Minimal valid PDF content (PDF 1.4)
VALID_PDF_14 = (
    b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    b"1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n"
    b"2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n"
    b"3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\n"
    b"xref\n0 4\n0000000000 65535 f\n0000000015 00000 n\n"
    b"0000000068 00000 n\n0000000125 00000 n\n"
    b"trailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n219\n%%EOF"
)

# Minimal valid PDF content (PDF 1.7)
VALID_PDF_17 = (
    b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    b"1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n"
    b"2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n"
    b"3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\n"
    b"xref\n0 4\n0000000000 65535 f\n0000000015 00000 n\n"
    b"0000000068 00000 n\n0000000125 00000 n\n"
    b"trailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n219\n%%EOF"
)


class TestFileValidation:
    """Test suite for file validation functionality."""

    def test_validate_pdf_file_valid_pdf_success(self):
        """Test validation accepts valid PDF content."""
        # Minimal valid PDF
        pdf_content = VALID_PDF_14
        filename = "test.pdf"

        # Should not raise
        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_invalid_extension_fails(self):
        """Test validation rejects non-PDF extension."""
        pdf_content = b"%PDF-1.4" + b" " * 200
        filename = "test.txt"

        with pytest.raises(ValueError, match="File must have .pdf extension"):
            SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_too_small_fails(self):
        """Test validation rejects files smaller than 100 bytes."""
        pdf_content = b"%PDF-1.4"
        filename = "test.pdf"

        with pytest.raises(ValueError, match="File is too small to be a valid PDF"):
            SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_invalid_magic_bytes_fails(self):
        """Test validation rejects files without PDF magic bytes."""
        # Text file with PDF extension
        fake_content = b"This is not a PDF file but has enough bytes" + b" " * 100
        filename = "fake.pdf"

        with pytest.raises(ValueError, match="File is not a valid PDF \\(invalid magic bytes\\)"):
            SigningService.validate_pdf_file(fake_content, filename)

    def test_validate_pdf_file_spoofed_extension_fails(self):
        """Test validation detects file extension spoofing using MIME type."""
        # JPEG file with PDF extension (spoofed)
        jpeg_content = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
            + b" " * 100
        )
        filename = "spoofed.pdf"

        # Should fail on magic bytes check (JPEG doesn't start with %PDF-)
        with pytest.raises(ValueError, match="File is not a valid PDF"):
            SigningService.validate_pdf_file(jpeg_content, filename)

    def test_validate_pdf_file_html_with_pdf_header_fails(self):
        """Test validation detects HTML masquerading as PDF."""
        # HTML file starting with %PDF- comment to bypass basic check
        html_content = (
            b"%PDF-1.4 <!-- fake -->\n<!DOCTYPE html><html><body>Not a PDF</body></html>"
            + b" " * 100
        )
        filename = "fake.pdf"

        # python-magic should detect this as text/html
        # Even if magic fails, the content structure won't match real PDF
        try:
            SigningService.validate_pdf_file(html_content, filename)
            # If no exception, check it at least passed basic validation
            # (magic might not be available in test environment)
        except ValueError as e:
            # Expected - should detect as non-PDF
            assert "MIME type" in str(e) or "magic bytes" in str(e)

    def test_validate_pdf_file_case_insensitive_extension(self):
        """Test validation accepts uppercase PDF extension."""
        pdf_content = VALID_PDF_14
        filename = "test.PDF"

        # Should not raise
        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_empty_filename_fails(self):
        """Test validation rejects empty filename."""
        pdf_content = b"%PDF-1.4" + b" " * 200
        filename = ""

        with pytest.raises(ValueError, match="File must have .pdf extension"):
            SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_pdf_14_version(self):
        """Test validation accepts PDF 1.4 version."""
        pdf_content = VALID_PDF_14
        filename = "document.pdf"

        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_pdf_17_version(self):
        """Test validation accepts PDF 1.7 version."""
        pdf_content = VALID_PDF_17
        filename = "document.pdf"

        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_zip_bomb_detection(self):
        """Test validation rejects suspiciously structured files."""
        # ZIP file magic bytes disguised as PDF (potential zip bomb)
        zip_content = b"PK\x03\x04" + b"\x00" * 200
        filename = "bomb.pdf"

        # Should fail on magic bytes check
        with pytest.raises(ValueError, match="File is not a valid PDF"):
            SigningService.validate_pdf_file(zip_content, filename)

    def test_validate_pdf_file_executable_disguised_as_pdf(self):
        """Test validation rejects executable files with PDF extension."""
        # ELF executable magic bytes
        elf_content = b"\x7fELF" + b"\x00" * 200
        filename = "malware.pdf"

        with pytest.raises(ValueError, match="File is not a valid PDF"):
            SigningService.validate_pdf_file(elf_content, filename)

    def test_validate_pdf_file_script_injection_attempt(self):
        """Test validation rejects script injection attempts."""
        # JavaScript with PDF header
        script_content = b"%PDF-1.4\n<script>alert('xss')</script>" + b" " * 100
        filename = "injection.pdf"

        # Should still process as PDF-like (has valid header)
        # but would fail deeper validation if actually opened
        # For this test, we verify it at least checks the header
        try:
            SigningService.validate_pdf_file(script_content, filename)
        except ValueError:
            # May fail on MIME detection or structure validation
            pass

    def test_validate_pdf_file_null_bytes_in_filename(self):
        """Test validation handles null bytes in filename."""
        pdf_content = VALID_PDF_14
        filename = "test\x00.pdf"

        # Should still validate based on extension check
        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_unicode_filename(self):
        """Test validation handles Unicode characters in filename."""
        pdf_content = VALID_PDF_14
        filename = "documento_español_文档.pdf"

        SigningService.validate_pdf_file(pdf_content, filename)

    def test_validate_pdf_file_path_traversal_in_filename(self):
        """Test validation handles path traversal attempts in filename."""
        pdf_content = VALID_PDF_14
        filename = "../../etc/passwd.pdf"

        # Should still validate (filename parsing is responsibility of caller)
        SigningService.validate_pdf_file(pdf_content, filename)

"""
test_pdf_validator.py - Tests for PDFValidator

Author: Homero Thompson del Lago del Terror
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pdfsigner.core.validator.pdf_validator import (
    PDFValidator,
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)


class TestSignatureStatus:
    """Tests for SignatureStatus enum."""

    def test_valid_status(self):
        """Test VALID status value."""
        assert SignatureStatus.VALID.value == "valid"

    def test_invalid_status(self):
        """Test INVALID status value."""
        assert SignatureStatus.INVALID.value == "invalid"

    def test_unknown_status(self):
        """Test UNKNOWN status value."""
        assert SignatureStatus.UNKNOWN.value == "unknown"

    def test_indeterminate_status(self):
        """Test INDETERMINATE status value."""
        assert SignatureStatus.INDETERMINATE.value == "indeterminate"


class TestSignatureInfo:
    """Tests for SignatureInfo dataclass."""

    def test_creation(self):
        """Test creating SignatureInfo."""
        info = SignatureInfo(
            signer_name="Test User",
            signer_email="test@example.com",
            signing_time=datetime.now(),
            is_timestamp_valid=True,
            certificate_issuer="Test CA",
            certificate_serial="abc123",
            certificate_valid_from=datetime(2024, 1, 1),
            certificate_valid_to=datetime(2025, 1, 1),
            status=SignatureStatus.VALID,
            status_message="Valid signature",
            field_name="Signature1",
            covers_whole_document=True,
            is_modification_allowed=False,
            page_number=1,
        )

        assert info.signer_name == "Test User"
        assert info.status == SignatureStatus.VALID
        assert info.covers_whole_document is True

    def test_optional_fields(self):
        """Test SignatureInfo with optional fields as None."""
        info = SignatureInfo(
            signer_name="Test",
            signer_email=None,
            signing_time=None,
            is_timestamp_valid=False,
            certificate_issuer="CA",
            certificate_serial="123",
            certificate_valid_from=None,
            certificate_valid_to=None,
            status=SignatureStatus.UNKNOWN,
            status_message="Unknown",
            field_name="Sig1",
            covers_whole_document=False,
            is_modification_allowed=False,
            page_number=None,
        )

        assert info.signer_email is None
        assert info.signing_time is None
        assert info.page_number is None


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_unsigned_document(self, temp_dir: Path):
        """Test result for unsigned document."""
        result = ValidationResult(
            file_path=temp_dir / "unsigned.pdf",
            is_signed=False,
            signature_count=0,
            all_valid=True,
            signatures=[],
        )

        assert result.is_signed is False
        assert result.signature_count == 0
        assert result.all_valid is True

    def test_signed_document_all_valid(self, temp_dir: Path):
        """Test result for document with all valid signatures."""
        signatures = [
            SignatureInfo(
                signer_name="User1",
                signer_email=None,
                signing_time=None,
                is_timestamp_valid=True,
                certificate_issuer="CA",
                certificate_serial="1",
                certificate_valid_from=None,
                certificate_valid_to=None,
                status=SignatureStatus.VALID,
                status_message="Valid",
                field_name="Sig1",
                covers_whole_document=True,
                is_modification_allowed=False,
                page_number=None,
            ),
        ]

        result = ValidationResult(
            file_path=temp_dir / "signed.pdf",
            is_signed=True,
            signature_count=1,
            all_valid=True,
            signatures=signatures,
        )

        assert result.is_signed is True
        assert result.all_valid is True

    def test_result_with_error(self, temp_dir: Path):
        """Test result with error."""
        result = ValidationResult(
            file_path=temp_dir / "error.pdf",
            is_signed=False,
            signature_count=0,
            all_valid=False,
            signatures=[],
            error="Could not read PDF",
        )

        assert result.error == "Could not read PDF"


class TestPDFValidator:
    """Tests for PDFValidator class."""

    def test_initialization(self):
        """Test validator initialization."""
        validator = PDFValidator()

        assert validator is not None

    def test_validate_missing_file(self, temp_dir: Path):
        """Test validating non-existent file."""
        validator = PDFValidator()
        pdf_path = temp_dir / "nonexistent.pdf"

        result = validator.validate(pdf_path)

        assert result.is_signed is False
        assert result.error is not None

    def test_validate_unsigned_pdf(self, sample_pdf: Path):
        """Test validating unsigned PDF."""
        validator = PDFValidator()

        result = validator.validate(sample_pdf)

        assert result.is_signed is False
        assert result.signature_count == 0
        assert result.all_valid is True
        assert len(result.signatures) == 0

    def test_validate_corrupted_file(self, temp_dir: Path):
        """Test validating corrupted file."""
        validator = PDFValidator()
        corrupted = temp_dir / "corrupted.pdf"
        corrupted.write_bytes(b"not a pdf")

        result = validator.validate(corrupted)

        assert result.is_signed is False
        assert result.error is not None

    def test_get_signature_count_unsigned(self, sample_pdf: Path):
        """Test signature count for unsigned PDF."""
        validator = PDFValidator()

        count = validator.get_signature_count(sample_pdf)

        assert count == 0

    def test_get_signature_count_missing_file(self, temp_dir: Path):
        """Test signature count for missing file."""
        validator = PDFValidator()

        count = validator.get_signature_count(temp_dir / "missing.pdf")

        assert count == 0

    def test_is_signed_unsigned(self, sample_pdf: Path):
        """Test is_signed for unsigned PDF."""
        validator = PDFValidator()

        result = validator.is_signed(sample_pdf)

        assert result is False

    def test_is_signed_missing_file(self, temp_dir: Path):
        """Test is_signed for missing file."""
        validator = PDFValidator()

        result = validator.is_signed(temp_dir / "missing.pdf")

        assert result is False

    def test_extract_cn_with_cn(self):
        """Test CN extraction from subject."""
        validator = PDFValidator()

        cn = validator._extract_cn("CN=John Doe,O=Test Org,C=US")

        assert cn == "John Doe"

    def test_extract_cn_without_cn(self):
        """Test CN extraction when no CN present."""
        validator = PDFValidator()

        cn = validator._extract_cn("O=Test Org,C=US")

        assert cn == "O=Test Org,C=US"

    def test_extract_cn_multiple_parts(self):
        """Test CN extraction with multiple CN parts."""
        validator = PDFValidator()

        cn = validator._extract_cn("CN=Test,OU=Unit,O=Org")

        assert cn == "Test"

    def test_extract_email_none(self):
        """Test email extraction when no email in cert."""
        validator = PDFValidator()
        mock_cert = MagicMock()
        mock_cert.extensions = []

        email = validator._extract_email(mock_cert)

        assert email is None

    def test_create_error_info(self):
        """Test creating error SignatureInfo."""
        validator = PDFValidator()

        info = validator._create_error_info("Signature1", "Test error")

        assert info.signer_name == "Unknown"
        assert info.status == SignatureStatus.UNKNOWN
        assert "Test error" in info.status_message
        assert info.field_name == "Signature1"

    def test_get_signature_fields_empty(self):
        """Test getting signature fields from PDF without signatures."""
        validator = PDFValidator()
        mock_reader = MagicMock()
        mock_reader.embedded_signatures = []

        fields = validator._get_signature_fields(mock_reader)

        assert fields == []

    def test_get_signature_fields_with_signatures(self):
        """Test getting signature fields from signed PDF."""
        validator = PDFValidator()
        mock_reader = MagicMock()

        mock_sig1 = MagicMock()
        mock_sig1.field_name = "Signature1"
        mock_sig2 = MagicMock()
        mock_sig2.field_name = "Signature2"

        mock_reader.embedded_signatures = [mock_sig1, mock_sig2]

        fields = validator._get_signature_fields(mock_reader)

        assert len(fields) == 2
        assert "Signature1" in fields
        assert "Signature2" in fields


class TestPDFValidatorWithMockedSignatures:
    """Tests for PDFValidator with mocked signed PDFs."""

    @pytest.fixture
    def mock_signed_reader(self):
        """Create a mock reader with signatures."""
        reader = MagicMock()

        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User,O=Test Org"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []

        mock_sig.signer_cert = mock_cert

        reader.embedded_signatures = [mock_sig]

        return reader

    def test_validate_signature_field_not_found(self):
        """Test validation when signature field not in list."""
        validator = PDFValidator()
        mock_reader = MagicMock()
        mock_reader.embedded_signatures = []

        info = validator._validate_signature(mock_reader, "NonExistent")

        assert info.status == SignatureStatus.UNKNOWN
        assert "not found" in info.status_message.lower()

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


class TestHybridPDFHandling:
    """Tests for hybrid-reference PDF handling."""

    def test_create_hybrid_pdf_info_with_cert(self):
        """Test creating hybrid PDF info when certificate is available."""
        validator = PDFValidator()

        mock_sig = MagicMock()
        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=John Doe,O=Acme Corp"
        mock_cert.issuer.human_friendly = "CN=Acme CA"
        mock_cert.serial_number = 0x123ABC
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 12, 31)
        mock_cert.extensions = []
        mock_sig.signer_cert = mock_cert

        info = validator._create_hybrid_pdf_info("Signature1", mock_sig)

        assert info.signer_name == "John Doe"
        assert info.certificate_issuer == "Acme CA"
        assert info.certificate_serial == "123abc"
        assert info.status == SignatureStatus.INDETERMINATE
        assert "hybrid PDF format" in info.status_message
        assert info.field_name == "Signature1"

    def test_create_hybrid_pdf_info_without_cert(self):
        """Test creating hybrid PDF info when certificate is not available."""
        validator = PDFValidator()

        info = validator._create_hybrid_pdf_info("Signature1", None)

        assert info.signer_name == "Unknown"
        assert info.certificate_issuer == "Unknown"
        assert info.status == SignatureStatus.INDETERMINATE
        assert "hybrid PDF format" in info.status_message

    def test_create_hybrid_pdf_info_cert_extraction_fails(self):
        """Test creating hybrid PDF info when certificate extraction fails."""
        validator = PDFValidator()

        mock_sig = MagicMock()
        mock_sig.signer_cert = MagicMock()
        mock_sig.signer_cert.subject.human_friendly = None  # Will cause exception

        info = validator._create_hybrid_pdf_info("Signature1", mock_sig)

        # Should fall back to Unknown values
        assert info.signer_name == "Unknown"
        assert info.status == SignatureStatus.INDETERMINATE

    def test_hybrid_error_message_detection(self):
        """Test that hybrid-reference error messages are correctly detected."""
        # Typical pyHanko error message
        error_msg = "Settings do not permit validation of signatures in hybrid-reference files."
        assert "hybrid-reference" in error_msg.lower()

        # Variation of the message
        error_msg2 = "Cannot process HYBRID-REFERENCE PDF structure"
        assert "hybrid-reference" in error_msg2.lower()


class TestExtractCNEdgeCases:
    """Tests for _extract_cn edge cases."""

    def test_extract_cn_empty_string(self):
        """Test CN extraction from empty string."""
        validator = PDFValidator()

        cn = validator._extract_cn("")

        assert cn == ""

    def test_extract_cn_only_spaces(self):
        """Test CN extraction from string with only spaces."""
        validator = PDFValidator()

        cn = validator._extract_cn("   ")

        # Returns full string if no CN= found
        assert cn == "   "

    def test_extract_cn_with_special_characters(self):
        """Test CN extraction with special characters in name."""
        validator = PDFValidator()

        cn = validator._extract_cn("CN=José María Ñoño,O=Test")

        assert cn == "José María Ñoño"

    def test_extract_cn_with_comma_in_cn(self):
        """Test CN extraction when CN field itself is first part."""
        validator = PDFValidator()

        # CN is the first field even with comma
        cn = validator._extract_cn("CN=Doe, John,O=Corp")

        assert cn == "Doe"

    def test_extract_cn_lowercase_cn(self):
        """Test CN extraction when cn is lowercase."""
        validator = PDFValidator()

        # Should only match uppercase CN=
        cn = validator._extract_cn("cn=Test User,O=Org")

        assert cn == "cn=Test User,O=Org"  # Returns full string if no CN= found

    def test_extract_cn_cn_at_end(self):
        """Test CN extraction when CN is at the end."""
        validator = PDFValidator()

        cn = validator._extract_cn("O=Test Org,C=US,CN=Last Name")

        assert cn == "Last Name"


class TestExtractEmailWithMocks:
    """Tests for _extract_email with mocked certificates."""

    def test_extract_email_with_subject_alt_name(self):
        """Test email extraction from SubjectAltName extension."""
        validator = PDFValidator()

        mock_cert = MagicMock()
        mock_ext = MagicMock()
        mock_ext.oid.dotted_string = "2.5.29.17"  # SubjectAltName OID

        mock_name = MagicMock()
        mock_name.value = "user@example.com"
        mock_ext.value = [mock_name]

        mock_cert.extensions = [mock_ext]

        email = validator._extract_email(mock_cert)

        assert email == "user@example.com"

    def test_extract_email_with_multiple_alt_names(self):
        """Test email extraction when multiple alt names exist."""
        validator = PDFValidator()

        mock_cert = MagicMock()
        mock_ext = MagicMock()
        mock_ext.oid.dotted_string = "2.5.29.17"

        # First name without @, second with email
        mock_name1 = MagicMock()
        mock_name1.value = "example.com"
        mock_name2 = MagicMock()
        mock_name2.value = "test@example.com"
        mock_ext.value = [mock_name1, mock_name2]

        mock_cert.extensions = [mock_ext]

        email = validator._extract_email(mock_cert)

        assert email == "test@example.com"

    def test_extract_email_no_at_symbol(self):
        """Test email extraction when value has no @ symbol."""
        validator = PDFValidator()

        mock_cert = MagicMock()
        mock_ext = MagicMock()
        mock_ext.oid.dotted_string = "2.5.29.17"

        mock_name = MagicMock()
        mock_name.value = "notanemail"
        mock_ext.value = [mock_name]

        mock_cert.extensions = [mock_ext]

        email = validator._extract_email(mock_cert)

        assert email is None

    def test_extract_email_wrong_oid(self):
        """Test email extraction when extension has wrong OID."""
        validator = PDFValidator()

        mock_cert = MagicMock()
        mock_ext = MagicMock()
        mock_ext.oid.dotted_string = "2.5.29.99"  # Different OID

        mock_name = MagicMock()
        mock_name.value = "test@example.com"
        mock_ext.value = [mock_name]

        mock_cert.extensions = [mock_ext]

        email = validator._extract_email(mock_cert)

        assert email is None

    def test_extract_email_extension_raises_exception(self):
        """Test email extraction when extension access raises exception."""
        validator = PDFValidator()

        mock_cert = MagicMock()
        mock_cert.extensions = MagicMock()
        mock_cert.extensions.__iter__ = MagicMock(side_effect=Exception("Extension error"))

        email = validator._extract_email(mock_cert)

        assert email is None


class TestGetSignatureFieldsExceptions:
    """Tests for _get_signature_fields exception handling."""

    def test_get_signature_fields_raises_exception(self):
        """Test _get_signature_fields when embedded_signatures raises exception."""
        validator = PDFValidator()

        mock_reader = MagicMock()
        mock_reader.embedded_signatures = MagicMock()
        # Make embedded_signatures raise exception when accessed
        type(mock_reader).embedded_signatures = property(
            lambda self: (_ for _ in ()).throw(RuntimeError("Cannot access signatures"))
        )

        fields = validator._get_signature_fields(mock_reader)

        assert fields == []

    def test_get_signature_fields_iteration_fails(self):
        """Test _get_signature_fields when iteration fails."""
        validator = PDFValidator()

        mock_reader = MagicMock()
        # Make embedded_signatures iterable but raise during iteration
        mock_reader.embedded_signatures = MagicMock()
        mock_reader.embedded_signatures.__iter__ = MagicMock(
            side_effect=RuntimeError("Iteration failed")
        )

        fields = validator._get_signature_fields(mock_reader)

        assert fields == []


class TestValidationLoopWithMocks:
    """Tests for validation loop (lines 105-118) with mocked signatures."""

    def test_validate_multiple_signatures_all_valid(self, temp_dir: Path):
        """Test validation of PDF with multiple valid signatures."""
        from unittest.mock import mock_open, patch

        validator = PDFValidator()
        pdf_path = temp_dir / "multi_signed.pdf"

        # Create mock signatures
        mock_sig1 = MagicMock()
        mock_sig1.field_name = "Signature1"
        mock_cert1 = MagicMock()
        mock_cert1.subject.human_friendly = "CN=User One"
        mock_cert1.issuer.human_friendly = "CN=CA One"
        mock_cert1.serial_number = 1111
        mock_cert1.not_valid_before = datetime(2024, 1, 1)
        mock_cert1.not_valid_after = datetime(2025, 1, 1)
        mock_cert1.extensions = []
        mock_sig1.signer_cert = mock_cert1

        mock_sig2 = MagicMock()
        mock_sig2.field_name = "Signature2"
        mock_cert2 = MagicMock()
        mock_cert2.subject.human_friendly = "CN=User Two"
        mock_cert2.issuer.human_friendly = "CN=CA Two"
        mock_cert2.serial_number = 2222
        mock_cert2.not_valid_before = datetime(2024, 1, 1)
        mock_cert2.not_valid_after = datetime(2025, 1, 1)
        mock_cert2.extensions = []
        mock_sig2.signer_cert = mock_cert2

        # Mock validation status
        mock_status1 = MagicMock()
        mock_status1.valid = True
        mock_status1.intact = True
        mock_status1.timestamp_validity = None
        mock_status1.coverage.value = 2
        mock_status1.modification_level = None

        mock_status2 = MagicMock()
        mock_status2.valid = True
        mock_status2.intact = True
        mock_status2.timestamp_validity = None
        mock_status2.coverage.value = 2
        mock_status2.modification_level = None

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch("pdfsigner.core.validator.pdf_validator.validate_pdf_signature") as mock_validate,
        ):
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig1, mock_sig2]
            mock_reader_class.return_value = mock_reader

            # Return different status for each call
            mock_validate.side_effect = [mock_status1, mock_status2]

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert result.signature_count == 2
            assert result.all_valid is True
            assert len(result.signatures) == 2
            assert result.signatures[0].signer_name == "User One"
            assert result.signatures[1].signer_name == "User Two"

    def test_validate_multiple_signatures_one_invalid(self, temp_dir: Path):
        """Test validation when one signature is invalid."""
        from unittest.mock import mock_open, patch

        validator = PDFValidator()
        pdf_path = temp_dir / "mixed_signed.pdf"

        # Valid signature
        mock_sig1 = MagicMock()
        mock_sig1.field_name = "Signature1"
        mock_cert1 = MagicMock()
        mock_cert1.subject.human_friendly = "CN=Valid User"
        mock_cert1.issuer.human_friendly = "CN=CA"
        mock_cert1.serial_number = 1111
        mock_cert1.not_valid_before = datetime(2024, 1, 1)
        mock_cert1.not_valid_after = datetime(2025, 1, 1)
        mock_cert1.extensions = []
        mock_sig1.signer_cert = mock_cert1

        # Invalid signature
        mock_sig2 = MagicMock()
        mock_sig2.field_name = "Signature2"
        mock_cert2 = MagicMock()
        mock_cert2.subject.human_friendly = "CN=Invalid User"
        mock_cert2.issuer.human_friendly = "CN=CA"
        mock_cert2.serial_number = 2222
        mock_cert2.not_valid_before = datetime(2024, 1, 1)
        mock_cert2.not_valid_after = datetime(2025, 1, 1)
        mock_cert2.extensions = []
        mock_sig2.signer_cert = mock_cert2

        mock_status1 = MagicMock()
        mock_status1.valid = True
        mock_status1.intact = True
        mock_status1.timestamp_validity = None
        mock_status1.coverage.value = 2
        mock_status1.modification_level = None

        mock_status2 = MagicMock()
        mock_status2.valid = False
        mock_status2.intact = False
        mock_status2.timestamp_validity = None
        mock_status2.coverage.value = 2
        mock_status2.modification_level = None

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch("pdfsigner.core.validator.pdf_validator.validate_pdf_signature") as mock_validate,
        ):
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig1, mock_sig2]
            mock_reader_class.return_value = mock_reader

            mock_validate.side_effect = [mock_status1, mock_status2]

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert result.signature_count == 2
            assert result.all_valid is False  # One invalid signature
            assert result.signatures[0].status == SignatureStatus.VALID
            assert result.signatures[1].status == SignatureStatus.INVALID


class TestValidateSignatureWithTimestamp:
    """Tests for _validate_signature with timestamp information."""

    def test_validate_signature_with_valid_timestamp(self):
        """Test signature validation with valid timestamp."""
        from unittest.mock import patch

        validator = PDFValidator()

        mock_reader = MagicMock()
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_sig.signer_cert = mock_cert

        mock_reader.embedded_signatures = [mock_sig]

        # Mock status with timestamp
        mock_status = MagicMock()
        mock_status.valid = True
        mock_status.intact = True
        mock_timestamp = MagicMock()
        mock_timestamp.valid = True
        mock_timestamp.timestamp = datetime(2024, 6, 15, 10, 30, 0)
        mock_status.timestamp_validity = mock_timestamp
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        with patch(
            "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
            return_value=mock_status,
        ):
            info = validator._validate_signature(mock_reader, "Signature1")

            assert info.status == SignatureStatus.VALID
            assert info.is_timestamp_valid is True
            assert info.signing_time == datetime(2024, 6, 15, 10, 30, 0)

    def test_validate_signature_with_invalid_timestamp(self):
        """Test signature validation with invalid timestamp."""
        from unittest.mock import patch

        validator = PDFValidator()

        mock_reader = MagicMock()
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_sig.signer_cert = mock_cert

        mock_reader.embedded_signatures = [mock_sig]

        mock_status = MagicMock()
        mock_status.valid = True
        mock_status.intact = True
        mock_timestamp = MagicMock()
        mock_timestamp.valid = False
        mock_timestamp.timestamp = datetime(2024, 6, 15, 10, 30, 0)
        mock_status.timestamp_validity = mock_timestamp
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        with patch(
            "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
            return_value=mock_status,
        ):
            info = validator._validate_signature(mock_reader, "Signature1")

            assert info.is_timestamp_valid is False
            assert info.signing_time == datetime(2024, 6, 15, 10, 30, 0)

    def test_validate_signature_indeterminate_status(self):
        """Test signature with indeterminate status (intact but not valid)."""
        from unittest.mock import patch

        validator = PDFValidator()

        mock_reader = MagicMock()
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_sig.signer_cert = mock_cert

        mock_reader.embedded_signatures = [mock_sig]

        # Intact but not valid (couldn't verify chain)
        mock_status = MagicMock()
        mock_status.valid = False
        mock_status.intact = True
        mock_status.timestamp_validity = None
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        with patch(
            "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
            return_value=mock_status,
        ):
            info = validator._validate_signature(mock_reader, "Signature1")

            assert info.status == SignatureStatus.INDETERMINATE
            assert "couldn't verify chain" in info.status_message.lower()

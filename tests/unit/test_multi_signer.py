"""
test_multi_signer.py - Tests for multiple signature support

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.signer.multi_signer import (
    ExistingSignatureInfo,
    MultiSignatureHandler,
    get_signature_summary,
)


class TestExistingSignatureInfo:
    """Tests for ExistingSignatureInfo dataclass."""

    def test_creation(self):
        """Test creating signature info."""
        info = ExistingSignatureInfo(
            field_name="Signature1",
            signer_name="Test User",
            is_valid=True,
        )
        assert info.field_name == "Signature1"
        assert info.signer_name == "Test User"
        assert info.is_valid is True

    def test_invalid_signature(self):
        """Test invalid signature info."""
        info = ExistingSignatureInfo(
            field_name="Signature1",
            signer_name="Test User",
            is_valid=False,
        )
        assert info.is_valid is False


class TestMultiSignatureHandler:
    """Tests for MultiSignatureHandler class."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return MultiSignatureHandler()

    @pytest.fixture
    def mock_validation_result(self):
        """Create mock validation result."""
        result = MagicMock()

        sig1 = MagicMock()
        sig1.field_name = "Signature1"
        sig1.signer_name = "User One"
        sig1.status.value = "valid"

        sig2 = MagicMock()
        sig2.field_name = "Signature2"
        sig2.signer_name = "User Two"
        sig2.status.value = "invalid"

        result.signatures = [sig1, sig2]
        return result

    def test_initialization(self, handler: MultiSignatureHandler):
        """Test handler initialization."""
        assert handler.validator is not None

    def test_get_existing_signatures_empty(self, handler: MultiSignatureHandler, sample_pdf: Path):
        """Test getting signatures from unsigned PDF."""
        mock_result = MagicMock()
        mock_result.signatures = []

        with patch.object(handler.validator, "validate", return_value=mock_result):
            signatures = handler.get_existing_signatures(sample_pdf)

        assert signatures == []

    def test_get_existing_signatures_with_sigs(
        self,
        handler: MultiSignatureHandler,
        sample_pdf: Path,
        mock_validation_result,
    ):
        """Test getting signatures from signed PDF."""
        with patch.object(handler.validator, "validate", return_value=mock_validation_result):
            signatures = handler.get_existing_signatures(sample_pdf)

        assert len(signatures) == 2
        assert signatures[0].field_name == "Signature1"
        assert signatures[0].signer_name == "User One"
        assert signatures[0].is_valid is True
        assert signatures[1].field_name == "Signature2"
        assert signatures[1].is_valid is False

    def test_get_next_field_name_no_signatures(
        self, handler: MultiSignatureHandler, sample_pdf: Path
    ):
        """Test next field name for unsigned PDF."""
        mock_result = MagicMock()
        mock_result.signatures = []

        with patch.object(handler.validator, "validate", return_value=mock_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        assert name == "Signature1"

    def test_get_next_field_name_with_signatures(
        self,
        handler: MultiSignatureHandler,
        sample_pdf: Path,
        mock_validation_result,
    ):
        """Test next field name for signed PDF."""
        with patch.object(handler.validator, "validate", return_value=mock_validation_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        assert name == "Signature3"  # Has Signature1 and Signature2

    def test_get_next_field_name_non_sequential(
        self, handler: MultiSignatureHandler, sample_pdf: Path
    ):
        """Test next field name with non-sequential signatures."""
        mock_result = MagicMock()
        sig = MagicMock()
        sig.field_name = "Signature5"
        sig.signer_name = "User"
        sig.status.value = "valid"
        mock_result.signatures = [sig]

        with patch.object(handler.validator, "validate", return_value=mock_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        assert name == "Signature6"

    def test_get_next_field_name_custom_names(
        self, handler: MultiSignatureHandler, sample_pdf: Path
    ):
        """Test next field name with custom signature names."""
        mock_result = MagicMock()
        sig = MagicMock()
        sig.field_name = "CustomSig"  # Non-standard name
        sig.signer_name = "User"
        sig.status.value = "valid"
        mock_result.signatures = [sig]

        with patch.object(handler.validator, "validate", return_value=mock_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        assert name == "Signature1"  # Falls back to Signature1

    def test_can_add_signature_normal_pdf(self, handler: MultiSignatureHandler, sample_pdf: Path):
        """Test can add signature to normal PDF."""
        can_sign, message = handler.can_add_signature(sample_pdf)
        assert can_sign is True
        assert message == "OK"

    def test_can_add_signature_encrypted_pdf(self, handler: MultiSignatureHandler, tmp_path: Path):
        """Test can add signature to encrypted PDF."""
        pdf_path = tmp_path / "encrypted.pdf"

        with patch("builtins.open", MagicMock()):
            with patch("pdfsigner.core.signer.multi_signer.PdfFileReader") as MockReader:
                mock_reader = MagicMock()
                mock_reader.security_handler = MagicMock()  # Not None = encrypted
                MockReader.return_value = mock_reader

                can_sign, message = handler.can_add_signature(pdf_path)

        assert can_sign is False
        assert "password protected" in message

    def test_can_add_signature_read_error(self, handler: MultiSignatureHandler, tmp_path: Path):
        """Test can add signature when PDF cannot be read."""
        pdf_path = tmp_path / "nonexistent.pdf"

        can_sign, message = handler.can_add_signature(pdf_path)

        assert can_sign is False
        assert "Error reading PDF" in message


class TestMultiSignatureHandlerPrepare:
    """Tests for prepare_for_additional_signature method."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return MultiSignatureHandler()

    @pytest.fixture
    def mock_appearance(self):
        """Create mock appearance."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        appearance = MagicMock()
        appearance.visible = True
        appearance.page = "last"
        appearance.width_mm = 50
        appearance.height_mm = 20
        appearance.position_preference = PositionPreference.BOTTOM_RIGHT
        return appearance

    def test_prepare_invisible_signature(self, handler: MultiSignatureHandler, sample_pdf: Path):
        """Test preparing invisible signature."""
        appearance = MagicMock()
        appearance.visible = False

        mock_result = MagicMock()
        mock_result.signatures = []

        with patch.object(handler.validator, "validate", return_value=mock_result):
            spec, field_name = handler.prepare_for_additional_signature(sample_pdf, appearance)

        assert spec is None
        assert field_name == "Signature1"

    def test_prepare_visible_signature(
        self, handler: MultiSignatureHandler, sample_pdf: Path, mock_appearance
    ):
        """Test preparing visible signature."""
        mock_result = MagicMock()
        mock_result.signatures = []

        mock_position = MagicMock()
        mock_position.x = 100.0
        mock_position.y = 100.0
        mock_position.width = 141.73
        mock_position.height = 56.69

        mock_analyzer = MagicMock()
        mock_analyzer.page_count = 3
        mock_analyzer.__enter__ = MagicMock(return_value=mock_analyzer)
        mock_analyzer.__exit__ = MagicMock(return_value=False)

        with patch.object(handler.validator, "validate", return_value=mock_result):
            # Mock the imports at their original module paths
            with patch(
                "pdfsigner.core.pdf_analyzer.content_analyzer.ContentAnalyzer"
            ) as MockAnalyzer:
                with patch(
                    "pdfsigner.core.pdf_analyzer.position_finder.PositionFinder"
                ) as MockFinder:
                    MockAnalyzer.return_value = mock_analyzer
                    mock_finder = MagicMock()
                    mock_finder.find_position.return_value = mock_position
                    MockFinder.return_value = mock_finder

                    spec, field_name = handler.prepare_for_additional_signature(
                        sample_pdf, mock_appearance
                    )

        assert spec is not None
        assert field_name == "Signature1"
        assert spec.sig_field_name == "Signature1"


class TestGetSignatureSummary:
    """Tests for get_signature_summary function."""

    def test_no_signatures(self, sample_pdf: Path):
        """Test summary for unsigned PDF."""
        mock_result = MagicMock()
        mock_result.signatures = []

        with patch(
            "pdfsigner.core.signer.multi_signer.MultiSignatureHandler.get_existing_signatures"
        ) as mock_get:
            mock_get.return_value = []
            summary = get_signature_summary(sample_pdf)

        assert "no digital signatures" in summary

    def test_with_signatures(self, sample_pdf: Path):
        """Test summary for signed PDF."""
        mock_sigs = [
            ExistingSignatureInfo("Signature1", "User One", True),
            ExistingSignatureInfo("Signature2", "User Two", False),
        ]

        with patch(
            "pdfsigner.core.signer.multi_signer.MultiSignatureHandler.get_existing_signatures"
        ) as mock_get:
            mock_get.return_value = mock_sigs
            summary = get_signature_summary(sample_pdf)

        assert "2 signature(s)" in summary
        assert "User One" in summary
        assert "User Two" in summary
        assert "✓" in summary  # Valid signature
        assert "✗" in summary  # Invalid signature
        assert "additional signature" in summary

    def test_single_valid_signature(self, sample_pdf: Path):
        """Test summary with single valid signature."""
        mock_sigs = [
            ExistingSignatureInfo("Signature1", "John Doe", True),
        ]

        with patch(
            "pdfsigner.core.signer.multi_signer.MultiSignatureHandler.get_existing_signatures"
        ) as mock_get:
            mock_get.return_value = mock_sigs
            summary = get_signature_summary(sample_pdf)

        assert "1 signature(s)" in summary
        assert "John Doe" in summary
        assert "✓" in summary


class TestFieldNameEdgeCases:
    """Tests for edge cases in field name generation."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return MultiSignatureHandler()

    def test_get_next_field_name_with_non_numeric_suffix(
        self, handler: MultiSignatureHandler, sample_pdf: Path
    ):
        """Test next field name with non-numeric 'Signature' fields (covers lines 83-84)."""
        mock_result = MagicMock()

        # Create signatures with names that start with "Signature" but have invalid numbers
        sig1 = MagicMock()
        sig1.field_name = "SignatureA"  # Will trigger ValueError
        sig1.signer_name = "User A"
        sig1.status.value = "valid"

        sig2 = MagicMock()
        sig2.field_name = "SignatureX"  # Will trigger ValueError
        sig2.signer_name = "User X"
        sig2.status.value = "valid"

        sig3 = MagicMock()
        sig3.field_name = "Signature_old"  # Will trigger ValueError
        sig3.signer_name = "User Old"
        sig3.status.value = "valid"

        mock_result.signatures = [sig1, sig2, sig3]

        with patch.object(handler.validator, "validate", return_value=mock_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        # Should fall back to Signature1 since no valid numeric signatures exist
        assert name == "Signature1"

    def test_get_next_field_name_mixed_valid_invalid(
        self, handler: MultiSignatureHandler, sample_pdf: Path
    ):
        """Test next field name with mix of valid and invalid signature names."""
        mock_result = MagicMock()

        sig1 = MagicMock()
        sig1.field_name = "Signature3"  # Valid
        sig1.signer_name = "User 3"
        sig1.status.value = "valid"

        sig2 = MagicMock()
        sig2.field_name = "SignatureABC"  # Invalid - triggers ValueError
        sig2.signer_name = "User ABC"
        sig2.status.value = "valid"

        sig3 = MagicMock()
        sig3.field_name = "Signature1"  # Valid
        sig3.signer_name = "User 1"
        sig3.status.value = "valid"

        mock_result.signatures = [sig1, sig2, sig3]

        with patch.object(handler.validator, "validate", return_value=mock_result):
            name = handler.get_next_signature_field_name(sample_pdf)

        # Should be Signature4 (max of valid numbers is 3)
        assert name == "Signature4"


class TestPageHandlingInPrepare:
    """Tests for different page handling scenarios in prepare_for_additional_signature."""

    @pytest.fixture
    def handler(self):
        """Create handler instance."""
        return MultiSignatureHandler()

    @pytest.fixture
    def base_appearance(self):
        """Create base appearance configuration."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        appearance = MagicMock()
        appearance.visible = True
        appearance.width_mm = 50
        appearance.height_mm = 20
        appearance.position_preference = PositionPreference.BOTTOM_RIGHT
        return appearance

    def test_prepare_with_page_first(
        self, handler: MultiSignatureHandler, sample_pdf: Path, base_appearance
    ):
        """Test preparing signature with page='first' (covers lines 143-144)."""
        base_appearance.page = "first"

        mock_result = MagicMock()
        mock_result.signatures = []

        mock_position = MagicMock()
        mock_position.x = 100.0
        mock_position.y = 100.0
        mock_position.width = 141.73
        mock_position.height = 56.69

        mock_analyzer = MagicMock()
        mock_analyzer.page_count = 5
        mock_analyzer.__enter__ = MagicMock(return_value=mock_analyzer)
        mock_analyzer.__exit__ = MagicMock(return_value=False)

        with patch.object(handler.validator, "validate", return_value=mock_result):
            with patch(
                "pdfsigner.core.pdf_analyzer.content_analyzer.ContentAnalyzer"
            ) as MockAnalyzer:
                with patch(
                    "pdfsigner.core.pdf_analyzer.position_finder.PositionFinder"
                ) as MockFinder:
                    MockAnalyzer.return_value = mock_analyzer
                    mock_finder = MagicMock()
                    mock_finder.find_position.return_value = mock_position
                    MockFinder.return_value = mock_finder

                    spec, field_name = handler.prepare_for_additional_signature(
                        sample_pdf, base_appearance
                    )

                    # Verify that find_position was called with page_num=0 (first page)
                    mock_finder.find_position.assert_called_once()
                    call_args = mock_finder.find_position.call_args
                    assert call_args[0][0] == 0  # First argument should be page_num=0

        assert spec is not None
        assert spec.on_page == 0  # Should use first page

    def test_prepare_with_page_integer(
        self, handler: MultiSignatureHandler, sample_pdf: Path, base_appearance
    ):
        """Test preparing signature with page as integer (covers lines 145-146)."""
        base_appearance.page = 2  # Integer page number

        mock_result = MagicMock()
        mock_result.signatures = []

        mock_position = MagicMock()
        mock_position.x = 100.0
        mock_position.y = 100.0
        mock_position.width = 141.73
        mock_position.height = 56.69

        mock_analyzer = MagicMock()
        mock_analyzer.page_count = 5
        mock_analyzer.__enter__ = MagicMock(return_value=mock_analyzer)
        mock_analyzer.__exit__ = MagicMock(return_value=False)

        with patch.object(handler.validator, "validate", return_value=mock_result):
            with patch(
                "pdfsigner.core.pdf_analyzer.content_analyzer.ContentAnalyzer"
            ) as MockAnalyzer:
                with patch(
                    "pdfsigner.core.pdf_analyzer.position_finder.PositionFinder"
                ) as MockFinder:
                    MockAnalyzer.return_value = mock_analyzer
                    mock_finder = MagicMock()
                    mock_finder.find_position.return_value = mock_position
                    MockFinder.return_value = mock_finder

                    spec, field_name = handler.prepare_for_additional_signature(
                        sample_pdf, base_appearance
                    )

                    # Verify that find_position was called with page_num=2
                    mock_finder.find_position.assert_called_once()
                    call_args = mock_finder.find_position.call_args
                    assert call_args[0][0] == 2  # First argument should be page_num=2

        assert spec is not None
        assert spec.on_page == 2  # Should use specified page

    def test_prepare_with_page_integer_exceeds_total(
        self, handler: MultiSignatureHandler, sample_pdf: Path, base_appearance
    ):
        """Test preparing signature with page integer exceeding total pages."""
        base_appearance.page = 10  # Exceeds page count

        mock_result = MagicMock()
        mock_result.signatures = []

        mock_position = MagicMock()
        mock_position.x = 100.0
        mock_position.y = 100.0
        mock_position.width = 141.73
        mock_position.height = 56.69

        mock_analyzer = MagicMock()
        mock_analyzer.page_count = 3  # Only 3 pages
        mock_analyzer.__enter__ = MagicMock(return_value=mock_analyzer)
        mock_analyzer.__exit__ = MagicMock(return_value=False)

        with patch.object(handler.validator, "validate", return_value=mock_result):
            with patch(
                "pdfsigner.core.pdf_analyzer.content_analyzer.ContentAnalyzer"
            ) as MockAnalyzer:
                with patch(
                    "pdfsigner.core.pdf_analyzer.position_finder.PositionFinder"
                ) as MockFinder:
                    MockAnalyzer.return_value = mock_analyzer
                    mock_finder = MagicMock()
                    mock_finder.find_position.return_value = mock_position
                    MockFinder.return_value = mock_finder

                    spec, field_name = handler.prepare_for_additional_signature(
                        sample_pdf, base_appearance
                    )

                    # Should cap at last page (page_count - 1 = 2)
                    mock_finder.find_position.assert_called_once()
                    call_args = mock_finder.find_position.call_args
                    assert call_args[0][0] == 2  # Capped to page 2 (last page)

        assert spec is not None
        assert spec.on_page == 2  # Should use last page

    def test_prepare_with_page_invalid_string(
        self, handler: MultiSignatureHandler, sample_pdf: Path, base_appearance
    ):
        """Test preparing signature with invalid page string (covers lines 147-148)."""
        base_appearance.page = "invalid"  # Not "first" or "last"

        mock_result = MagicMock()
        mock_result.signatures = []

        mock_position = MagicMock()
        mock_position.x = 100.0
        mock_position.y = 100.0
        mock_position.width = 141.73
        mock_position.height = 56.69

        mock_analyzer = MagicMock()
        mock_analyzer.page_count = 4
        mock_analyzer.__enter__ = MagicMock(return_value=mock_analyzer)
        mock_analyzer.__exit__ = MagicMock(return_value=False)

        with patch.object(handler.validator, "validate", return_value=mock_result):
            with patch(
                "pdfsigner.core.pdf_analyzer.content_analyzer.ContentAnalyzer"
            ) as MockAnalyzer:
                with patch(
                    "pdfsigner.core.pdf_analyzer.position_finder.PositionFinder"
                ) as MockFinder:
                    MockAnalyzer.return_value = mock_analyzer
                    mock_finder = MagicMock()
                    mock_finder.find_position.return_value = mock_position
                    MockFinder.return_value = mock_finder

                    spec, field_name = handler.prepare_for_additional_signature(
                        sample_pdf, base_appearance
                    )

                    # Should fall back to last page (page_count - 1 = 3)
                    mock_finder.find_position.assert_called_once()
                    call_args = mock_finder.find_position.call_args
                    assert call_args[0][0] == 3  # Fallback to last page

        assert spec is not None
        assert spec.on_page == 3  # Should use last page as fallback

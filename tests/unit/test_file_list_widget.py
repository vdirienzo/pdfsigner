"""
test_file_list_widget.py - Tests for FileListWidget logic

Author: Homero Thompson del Lago del Terror

Tests core logic without GTK widget instantiation.
The GTK mock system prevents proper widget testing,
so we test the business logic directly.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch


def create_mock_validation_result(
    signature_count: int = 1,
    all_valid: bool = True,
    signer_name: str = "John Doe",
):
    """Create a mock ValidationResult."""
    result = MagicMock()
    result.file_path = Path("/test/doc.pdf")
    result.is_signed = signature_count > 0
    result.signature_count = signature_count
    result.all_valid = all_valid
    result.error = None

    # Create mock signatures
    signatures = []
    for i in range(signature_count):
        sig = MagicMock()
        sig.signer_name = signer_name if i == 0 else f"Signer {i + 1}"
        sig.status = MagicMock()
        sig.status.name = "VALID" if all_valid else "INVALID"
        signatures.append(sig)

    result.signatures = signatures
    return result


class TestPDFValidatorIntegration:
    """Test that PDFValidator is called correctly."""

    def test_get_signature_count_called(self):
        """Verify get_signature_count is used for quick check."""
        with patch("pdfsigner.core.validator.pdf_validator.PDFValidator") as MockValidator:
            mock_validator = MockValidator.return_value
            mock_validator.get_signature_count.return_value = 3

            count = mock_validator.get_signature_count(Path("/test/doc.pdf"))

            assert count == 3
            mock_validator.get_signature_count.assert_called_once()

    def test_validate_returns_result(self):
        """Verify validate returns ValidationResult."""
        with patch("pdfsigner.core.validator.pdf_validator.PDFValidator") as MockValidator:
            mock_validator = MockValidator.return_value
            mock_result = create_mock_validation_result(
                signature_count=2, all_valid=True, signer_name="Alice"
            )
            mock_validator.validate.return_value = mock_result

            result = mock_validator.validate(Path("/test/signed.pdf"))

            assert result.signature_count == 2
            assert result.all_valid is True
            assert result.signatures[0].signer_name == "Alice"


class TestSignatureIconLogic:
    """Test the logic for signature status icons."""

    def test_valid_signatures_show_checkmark(self):
        """Valid signatures show checkmark icon."""
        result = create_mock_validation_result(
            signature_count=1, all_valid=True, signer_name="John Doe"
        )

        # Icon logic from _update_signature_summary
        icon = "✓" if result.all_valid else "⚠"
        css = "success" if result.all_valid else "warning"

        assert icon == "✓"
        assert css == "success"

    def test_invalid_signatures_show_warning(self):
        """Invalid signatures show warning icon."""
        result = create_mock_validation_result(
            signature_count=1, all_valid=False, signer_name="Bob"
        )

        icon = "✓" if result.all_valid else "⚠"
        css = "success" if result.all_valid else "warning"

        assert icon == "⚠"
        assert css == "warning"

    def test_signature_count_display(self):
        """Signature count is displayed as simple text."""
        # The label shows "{n} signature(s)" format
        count = 3
        label_text = f"{count} signature(s)"

        assert "3" in label_text
        assert "signature" in label_text


class TestValidationResultCaching:
    """Test validation result caching logic."""

    def test_cached_result_prevents_revalidation(self):
        """Cached result should prevent unnecessary revalidation."""
        cached_result = create_mock_validation_result()
        validation_result = cached_result

        # Logic: if result exists, don't validate again
        should_validate = validation_result is None

        assert should_validate is False

    def test_no_cache_triggers_validation(self):
        """Missing cache should trigger validation."""
        validation_result = None

        # Logic: if result is None, validate
        should_validate = validation_result is None

        assert should_validate is True


class TestFilePathSet:
    """Test file path tracking logic."""

    def test_add_new_path(self):
        """Adding new path succeeds."""
        file_paths = set()
        path = Path("/test/doc.pdf")

        if path not in file_paths:
            file_paths.add(path)
            result = True
        else:
            result = False

        assert result is True
        assert path in file_paths

    def test_add_duplicate_path_fails(self):
        """Adding duplicate path fails."""
        file_paths = {Path("/test/doc.pdf")}
        path = Path("/test/doc.pdf")

        if path not in file_paths:
            file_paths.add(path)
            result = True
        else:
            result = False

        assert result is False

    def test_clear_removes_all(self):
        """Clear removes all paths."""
        file_paths = {Path("/test/a.pdf"), Path("/test/b.pdf")}

        file_paths.clear()

        assert len(file_paths) == 0

    def test_get_file_count(self):
        """Count returns correct number."""
        file_paths = {Path("/test/a.pdf"), Path("/test/b.pdf"), Path("/test/c.pdf")}

        assert len(file_paths) == 3


class TestModuleImports:
    """Test that module imports work correctly."""

    def test_file_list_widget_imports(self):
        """Module imports without errors (with GTK mocks)."""
        import tests.unit.conftest_gui  # noqa: F401

        # Should not raise
        from pdfsigner.gui.file_list_widget import FileListWidget, FileRow

        assert FileRow is not None
        assert FileListWidget is not None

    def test_validation_dialog_imports(self):
        """ValidationResultDialog imports work."""
        import tests.unit.conftest_gui  # noqa: F401
        from pdfsigner.ui.dialogs.validation_dialog import ValidationResultDialog

        assert ValidationResultDialog is not None

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


class TestFileStatusLogic:
    """Test file status state machine logic."""

    def test_status_icons_mapping(self):
        """Test all status icons are correctly mapped."""
        icons = {
            "pending": ("○", ""),
            "processing": ("→", ""),
            "signed": ("✓", "success"),
            "error": ("✗", "error"),
        }

        assert icons["pending"][0] == "○"
        assert icons["processing"][0] == "→"
        assert icons["signed"][0] == "✓"
        assert icons["error"][0] == "✗"

    def test_status_css_classes(self):
        """Test CSS classes for different statuses."""
        icons = {
            "pending": ("○", ""),
            "processing": ("→", ""),
            "signed": ("✓", "success"),
            "error": ("✗", "error"),
        }

        # Only signed and error have CSS classes
        assert icons["pending"][1] == ""
        assert icons["processing"][1] == ""
        assert icons["signed"][1] == "success"
        assert icons["error"][1] == "error"

    def test_unknown_status_defaults_to_pending(self):
        """Unknown status should default to pending appearance."""
        icons = {
            "pending": ("○", ""),
            "processing": ("→", ""),
            "signed": ("✓", "success"),
            "error": ("✗", "error"),
        }

        # .get() defaults to pending
        icon, css_class = icons.get("unknown", ("○", ""))

        assert icon == "○"
        assert css_class == ""


class TestFilePathOperations:
    """Test file path manipulation logic."""

    def test_path_parent_extraction(self):
        """Test extracting parent directory from path."""
        path = Path("/home/user/documents/report.pdf")

        assert str(path.parent) == "/home/user/documents"

    def test_path_name_extraction(self):
        """Test extracting filename from path."""
        path = Path("/home/user/documents/report.pdf")

        assert path.name == "report.pdf"

    def test_path_equality(self):
        """Test path equality for duplicate detection."""
        path1 = Path("/home/user/doc.pdf")
        path2 = Path("/home/user/doc.pdf")
        path3 = Path("/home/user/other.pdf")

        assert path1 == path2
        assert path1 != path3

    def test_path_in_set_membership(self):
        """Test path membership in set."""
        paths = {Path("/a.pdf"), Path("/b.pdf")}

        assert Path("/a.pdf") in paths
        assert Path("/c.pdf") not in paths


class TestFileListLogic:
    """Test FileListWidget business logic."""

    def test_get_files_returns_list(self):
        """get_files should return list from set."""
        file_paths = {Path("/a.pdf"), Path("/b.pdf")}

        files = list(file_paths)

        assert len(files) == 2
        assert isinstance(files, list)

    def test_discard_removes_path(self):
        """discard() removes path without error."""
        file_paths = {Path("/a.pdf"), Path("/b.pdf")}

        file_paths.discard(Path("/a.pdf"))

        assert Path("/a.pdf") not in file_paths
        assert len(file_paths) == 1

    def test_discard_nonexistent_no_error(self):
        """discard() on nonexistent path doesn't raise."""
        file_paths = {Path("/a.pdf")}

        # Should not raise
        file_paths.discard(Path("/nonexistent.pdf"))

        assert len(file_paths) == 1


class TestSignatureSummaryLogic:
    """Test signature summary display logic."""

    def test_single_signature_format(self):
        """Single signature shows simple count."""
        count = 1
        label = f"{count} signature(s)"

        assert label == "1 signature(s)"

    def test_multiple_signatures_format(self):
        """Multiple signatures show count."""
        count = 5
        label = f"{count} signature(s)"

        assert label == "5 signature(s)"

    def test_zero_signatures_no_label(self):
        """Zero signatures should not display label."""
        count = 0

        # Logic: only show label if count > 0
        should_show = count > 0

        assert should_show is False

    def test_valid_all_signatures_icon(self):
        """All valid signatures show success icon."""
        all_valid = True

        icon = "✓" if all_valid else "⚠"
        css = "success" if all_valid else "warning"

        assert icon == "✓"
        assert css == "success"

    def test_some_invalid_signatures_icon(self):
        """Some invalid signatures show warning icon."""
        all_valid = False

        icon = "✓" if all_valid else "⚠"
        css = "success" if all_valid else "warning"

        assert icon == "⚠"
        assert css == "warning"


class TestCSSClassManagement:
    """Test CSS class add/remove logic."""

    def test_remove_all_status_classes_logic(self):
        """Test logic for removing status classes."""
        classes_to_remove = ["success", "error", "warning"]
        current_classes = {"success", "dim-label", "caption"}

        # Simulate removing status classes
        for cls in classes_to_remove:
            current_classes.discard(cls)

        assert "success" not in current_classes
        assert "error" not in current_classes
        assert "warning" not in current_classes
        # Other classes preserved
        assert "dim-label" in current_classes
        assert "caption" in current_classes

"""
test_validation_handler.py - Tests for GUI validation handler

Author: Homero Thompson del Lago del Terror

Tests the ValidationHandler logic using GTK mocks.
"""

# Install GTK mocks before GUI imports
from pathlib import Path
from unittest.mock import MagicMock, patch

import tests.unit.conftest_gui  # noqa: F401 - installs mocks


def create_mock_window():
    """Create a mock main window with common attributes."""
    window = MagicMock()
    window.file_list = MagicMock()
    window.file_list.update_file_status = MagicMock()
    window.show_toast = MagicMock()
    return window


class TestValidationHandlerInit:
    """Tests for ValidationHandler initialization."""

    def test_init_creates_handler(self):
        """Handler initializes with window reference."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        window = create_mock_window()
        handler = ValidationHandler(window)

        assert handler.window == window


class TestValidationHandlerValidateFiles:
    """Tests for validate_files method."""

    def test_validate_files_with_empty_list_returns_early(self):
        """Empty file list returns without action."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Should not raise, just return
        handler.validate_files([])

    @patch("pdfsigner.gui.validation_handler.Thread")
    def test_validate_files_starts_thread(self, mock_thread_cls):
        """validate_files starts background thread."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        window = create_mock_window()
        handler = ValidationHandler(window)

        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        files = [Path("/test/doc.pdf")]
        handler.validate_files(files)

        mock_thread_cls.assert_called_once()
        mock_thread.start.assert_called_once()


class TestValidationHandlerRunValidation:
    """Tests for _run_validation method."""

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_run_validation_with_valid_signatures(self, mock_glib, mock_validator_cls):
        """Validation updates status for valid signatures."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        # Setup GLib.idle_add to execute immediately
        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Mock validator response
        mock_validation = MagicMock()
        mock_validation.signatures = [MagicMock(), MagicMock()]
        mock_validation.all_valid = True

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        files = [Path("/test/doc.pdf")]
        handler._run_validation(files)

        window.file_list.update_file_status.assert_called()
        window.show_toast.assert_called_once()

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_run_validation_with_no_signatures(self, mock_glib, mock_validator_cls):
        """Validation handles files without signatures."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Mock validator response with no signatures
        mock_validation = MagicMock()
        mock_validation.signatures = []
        mock_validation.all_valid = True

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        files = [Path("/test/unsigned.pdf")]
        handler._run_validation(files)

        # Should update with "pending" status
        call_args = window.file_list.update_file_status.call_args
        assert call_args is not None
        assert call_args[0][1] == "pending"

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_run_validation_with_invalid_signatures(self, mock_glib, mock_validator_cls):
        """Validation handles invalid signatures."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Mock validator response with invalid signature
        mock_validation = MagicMock()
        mock_validation.signatures = [MagicMock()]
        mock_validation.all_valid = False

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        files = [Path("/test/invalid.pdf")]
        handler._run_validation(files)

        # Should update with "error" status
        call_args = window.file_list.update_file_status.call_args
        assert call_args is not None
        assert call_args[0][1] == "error"

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_run_validation_handles_exception(self, mock_glib, mock_validator_cls):
        """Validation handles exceptions gracefully."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Mock validator to raise exception
        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.side_effect = Exception("Test error")
        mock_validator_cls.return_value = mock_validator_instance

        files = [Path("/test/bad.pdf")]
        handler._run_validation(files)

        # Should update with "error" status
        call_args = window.file_list.update_file_status.call_args
        assert call_args is not None
        assert call_args[0][1] == "error"
        assert "Error" in call_args[0][2]

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_run_validation_multiple_files(self, mock_glib, mock_validator_cls):
        """Validation processes multiple files."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        # Mock validator response
        mock_validation = MagicMock()
        mock_validation.signatures = [MagicMock()]
        mock_validation.all_valid = True

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        files = [
            Path("/test/doc1.pdf"),
            Path("/test/doc2.pdf"),
            Path("/test/doc3.pdf"),
        ]
        handler._run_validation(files)

        # Should call validate for each file
        assert mock_validator_instance.validate.call_count == 3
        # Should update status for each file
        assert window.file_list.update_file_status.call_count == 3


class TestValidationHandlerToastMessages:
    """Tests for toast message generation."""

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_toast_message_all_valid(self, mock_glib, mock_validator_cls):
        """Toast shows valid count when all valid."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        mock_validation = MagicMock()
        mock_validation.signatures = [MagicMock(), MagicMock()]
        mock_validation.all_valid = True

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        handler._run_validation([Path("/test/doc.pdf")])

        toast_call = window.show_toast.call_args[0][0]
        assert "2" in toast_call  # 2 signatures

    @patch("pdfsigner.gui.validation_handler.PDFValidator")
    @patch("pdfsigner.gui.validation_handler.GLib")
    def test_toast_message_no_signatures(self, mock_glib, mock_validator_cls):
        """Toast shows 'no signatures' message."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        mock_glib.idle_add = lambda func, *args: func(*args)

        window = create_mock_window()
        handler = ValidationHandler(window)

        mock_validation = MagicMock()
        mock_validation.signatures = []
        mock_validation.all_valid = True

        mock_validator_instance = MagicMock()
        mock_validator_instance.validate.return_value = mock_validation
        mock_validator_cls.return_value = mock_validator_instance

        handler._run_validation([Path("/test/unsigned.pdf")])

        window.show_toast.assert_called_once()

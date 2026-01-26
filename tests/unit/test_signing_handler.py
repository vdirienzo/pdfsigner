"""
test_signing_handler.py - Tests for GUI signing handler

Author: Homero Thompson del Lago del Terror

Tests the SigningHandler logic using GTK mocks.
"""

# Install GTK mocks FIRST before any other imports
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


def create_mock_progress():
    """Create a mock progress object."""
    progress = MagicMock()
    progress.current_file = "/test/file.pdf"
    progress.status = "success"
    progress.current = 1
    progress.total = 1
    return progress


class TestSigningHandlerInit:
    """Tests for SigningHandler initialization."""

    def test_init_creates_handler(self):
        """Handler initializes with window reference."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        assert handler.window == window
        assert handler._current_pin is None
        assert handler._progress_dialog is None

    def test_init_loads_settings(self):
        """Handler loads settings on init."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        assert handler.settings is not None


class TestSigningHandlerSignFiles:
    """Tests for sign_files method."""

    def test_sign_files_with_empty_list_returns_early(self):
        """Empty file list returns without action."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        # Should not raise, just return
        handler.sign_files([])

    @patch("pdfsigner.gui.signing_handler.SignatureOptionsDialog")
    def test_sign_files_opens_options_dialog(self, mock_options_dialog_cls):
        """sign_files opens the options dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        mock_options_dialog_cls.return_value = mock_dialog

        files = [Path("/test/doc.pdf")]
        handler.sign_files(files)

        mock_options_dialog_cls.assert_called_once_with(parent=window)
        mock_dialog.connect.assert_called_once()
        mock_dialog.present.assert_called_once()


class TestSigningHandlerOptionsResponse:
    """Tests for options dialog response handling."""

    def test_options_cancel_destroys_dialog(self):
        """Cancelling options destroys dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        mock_dialog = MagicMock()
        mock_dialog.get_appearance.return_value = None

        # Simulate CANCEL response (not OK = 1)
        handler._on_options_response(mock_dialog, 2, [Path("/test/doc.pdf")])

        mock_dialog.destroy.assert_called_once()

    @patch("pdfsigner.gui.signing_handler.PinDialog")
    def test_options_ok_proceeds_to_pin(self, mock_pin_dialog_cls):
        """OK response proceeds to PIN request."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        mock_options_dialog = MagicMock()
        mock_appearance = MagicMock()
        mock_appearance.visible = True
        mock_appearance.page = "last"
        mock_options_dialog.get_appearance.return_value = mock_appearance

        mock_pin_dialog = MagicMock()
        mock_pin_dialog_cls.return_value = mock_pin_dialog

        # Simulate OK response (1)
        files = [Path("/test/doc.pdf")]
        handler._on_options_response(mock_options_dialog, 1, files)

        mock_options_dialog.destroy.assert_called_once()
        mock_pin_dialog_cls.assert_called_once_with(parent=window)
        mock_pin_dialog.present.assert_called_once()


class TestSigningHandlerPinResponse:
    """Tests for PIN dialog response handling."""

    def test_pin_cancel_destroys_dialog(self):
        """Cancelling PIN destroys dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        mock_dialog = MagicMock()
        mock_dialog.get_pin.return_value = ""

        # Simulate CANCEL response (not OK)
        handler._on_pin_response(mock_dialog, 2, [Path("/test/doc.pdf")])

        mock_dialog.destroy.assert_called_once()

    def test_empty_pin_shows_error(self):
        """Empty PIN shows error message."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._show_error = MagicMock()

        mock_dialog = MagicMock()
        mock_dialog.get_pin.return_value = ""

        # Simulate OK response with empty PIN
        handler._on_pin_response(mock_dialog, 1, [Path("/test/doc.pdf")])

        mock_dialog.destroy.assert_called_once()
        handler._show_error.assert_called_once()


class TestSigningHandlerProgress:
    """Tests for progress updates."""

    def test_update_progress_with_success(self):
        """Progress update handles success status."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = MagicMock()

        progress = create_mock_progress()
        progress.status = "success"

        handler._update_progress(progress)

        handler._progress_dialog.update_progress.assert_called_once_with(progress)
        window.file_list.update_file_status.assert_called()

    def test_update_progress_with_error(self):
        """Progress update handles error status."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = MagicMock()

        progress = create_mock_progress()
        progress.status = "error"
        progress.message = "Test error"

        handler._update_progress(progress)

        window.file_list.update_file_status.assert_called()

    def test_update_progress_without_dialog(self):
        """Progress update handles missing dialog gracefully."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = None

        progress = create_mock_progress()

        # Should not raise
        handler._update_progress(progress)


class TestSigningHandlerComplete:
    """Tests for signing completion."""

    def test_signing_complete_all_success_shows_result(self):
        """Completion with all files successful calls show_result on dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        handler._progress_dialog = mock_dialog

        # Create results with individual file results
        result1 = MagicMock()
        result1.success = True
        result1.input_path = Path("/test/doc1.pdf")
        result1.output_path = Path("/test/doc1_signed.pdf")

        result2 = MagicMock()
        result2.success = True
        result2.input_path = Path("/test/doc2.pdf")
        result2.output_path = Path("/test/doc2_signed.pdf")

        results = MagicMock()
        results.successful = 2
        results.failed = 0
        results.results = [result1, result2]

        files = [Path("/test/doc1.pdf"), Path("/test/doc2.pdf")]
        handler._signing_complete(results, files, dry_run=False)

        # Dialog shows results instead of being destroyed
        mock_dialog.show_result.assert_called_once_with(results)
        # Dialog is NOT destroyed (user closes it manually)
        mock_dialog.destroy.assert_not_called()

    def test_signing_complete_with_failures_shows_result(self):
        """Completion with some failures still shows result dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        handler._progress_dialog = mock_dialog

        result1 = MagicMock()
        result1.success = True
        result1.input_path = Path("/test/doc1.pdf")
        result1.output_path = Path("/test/doc1_signed.pdf")

        result2 = MagicMock()
        result2.success = False
        result2.input_path = Path("/test/doc2.pdf")
        result2.output_path = None

        results = MagicMock()
        results.successful = 1
        results.failed = 1
        results.results = [result1, result2]

        files = [Path("/test/doc1.pdf"), Path("/test/doc2.pdf")]
        handler._signing_complete(results, files, dry_run=False)

        mock_dialog.show_result.assert_called_once_with(results)
        # File statuses are updated correctly
        assert window.file_list.update_file_status.call_count == 2

    def test_signing_complete_updates_file_statuses(self):
        """File list statuses are updated based on individual results."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = MagicMock()

        result1 = MagicMock()
        result1.success = True
        result1.input_path = Path("/test/doc1.pdf")

        result2 = MagicMock()
        result2.success = False
        result2.input_path = Path("/test/doc2.pdf")

        results = MagicMock()
        results.results = [result1, result2]

        files = [Path("/test/doc1.pdf"), Path("/test/doc2.pdf")]
        handler._signing_complete(results, files, dry_run=False)

        # Check correct statuses are set
        calls = window.file_list.update_file_status.call_args_list
        assert len(calls) == 2
        # First file should be marked as signed
        assert calls[0][0][1] == "signed"
        # Second file should be marked as error
        assert calls[1][0][1] == "error"


class TestSigningHandlerError:
    """Tests for error handling."""

    @patch("pdfsigner.gui.signing_handler.Adw")
    def test_show_error_creates_dialog(self, mock_adw):
        """Error creates message dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        mock_dialog = MagicMock()
        mock_adw.MessageDialog.return_value = mock_dialog

        handler._show_error("Test Title", "Test Message")

        mock_adw.MessageDialog.assert_called_once()
        mock_dialog.add_response.assert_called_once()
        mock_dialog.present.assert_called_once()

    @patch("pdfsigner.gui.signing_handler.Adw")
    def test_show_error_closes_progress_dialog(self, mock_adw):
        """Error closes any open progress dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        handler._progress_dialog = mock_dialog

        mock_adw.MessageDialog.return_value = MagicMock()

        handler._show_error("Error", "Message")

        # Dialog is set to None after destroy, so check the saved reference
        mock_dialog.destroy.assert_called_once()

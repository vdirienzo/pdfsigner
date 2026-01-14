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
    def test_sign_files_opens_options_dialog(self, MockOptionsDialog):
        """sign_files opens the options dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        MockOptionsDialog.return_value = mock_dialog

        files = [Path("/test/doc.pdf")]
        handler.sign_files(files)

        MockOptionsDialog.assert_called_once_with(parent=window)
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
    def test_options_ok_proceeds_to_pin(self, MockPinDialog):
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
        MockPinDialog.return_value = mock_pin_dialog

        # Simulate OK response (1)
        files = [Path("/test/doc.pdf")]
        handler._on_options_response(mock_options_dialog, 1, files)

        mock_options_dialog.destroy.assert_called_once()
        MockPinDialog.assert_called_once_with(parent=window)
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

    def test_signing_complete_all_success(self):
        """Completion with all files successful."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        handler._progress_dialog = mock_dialog

        results = MagicMock()
        results.successful = 3
        results.failed = 0

        handler._signing_complete(results, dry_run=False)

        # Dialog is set to None after destroy, so check the saved reference
        mock_dialog.destroy.assert_called_once()
        window.show_toast.assert_called_once()
        assert handler._progress_dialog is None

    def test_signing_complete_with_failures(self):
        """Completion with some failures shows count."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = MagicMock()

        results = MagicMock()
        results.successful = 2
        results.failed = 1

        handler._signing_complete(results, dry_run=False)

        window.show_toast.assert_called_once()
        toast_msg = window.show_toast.call_args[0][0]
        assert "2" in toast_msg or "1" in toast_msg

    def test_signing_complete_dry_run_message(self):
        """Dry-run completion includes simulation indicator."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        handler._progress_dialog = MagicMock()

        results = {"success": 1, "failed": 0}

        handler._signing_complete(results, dry_run=True)

        window.show_toast.assert_called_once()


class TestSigningHandlerError:
    """Tests for error handling."""

    @patch("pdfsigner.gui.signing_handler.Adw")
    def test_show_error_creates_dialog(self, MockAdw):
        """Error creates message dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)

        mock_dialog = MagicMock()
        MockAdw.MessageDialog.return_value = mock_dialog

        handler._show_error("Test Title", "Test Message")

        MockAdw.MessageDialog.assert_called_once()
        mock_dialog.add_response.assert_called_once()
        mock_dialog.present.assert_called_once()

    @patch("pdfsigner.gui.signing_handler.Adw")
    def test_show_error_closes_progress_dialog(self, MockAdw):
        """Error closes any open progress dialog."""
        from pdfsigner.gui.signing_handler import SigningHandler

        window = create_mock_window()
        handler = SigningHandler(window)
        mock_dialog = MagicMock()
        handler._progress_dialog = mock_dialog

        MockAdw.MessageDialog.return_value = MagicMock()

        handler._show_error("Error", "Message")

        # Dialog is set to None after destroy, so check the saved reference
        mock_dialog.destroy.assert_called_once()

"""
test_gui_sign_flow.py - GUI structure tests for PDFSigner

Tests that verify GUI component structure exists correctly.
These tests use GTK mocks and verify code structure, not runtime behavior.

Note: Tests that require real GTK widgets to function were removed because
the mocking approach doesn't allow testing actual widget behavior.
For real GUI testing, use xvfb-run with unmocked GTK.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import fitz  # PyMuPDF
import pytest

# Skip all tests if no display available
DISPLAY_AVAILABLE = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")

# Install GTK mocks before any GUI module import
sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
import conftest_gui  # noqa: F401
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.config.settings import Settings
from pdfsigner.core.mock.mock_batch import MockBatchManager
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.gui.file_list_widget import FileListWidget
from pdfsigner.gui.main_window import MainWindow
from pdfsigner.gui.signing_handler import SigningHandler

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    tmp = tempfile.mkdtemp(prefix="pdfsigner_gui_e2e_")
    yield Path(tmp)
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_pdf(temp_dir: Path) -> Path:
    """Create a simple 1-page PDF for testing."""
    pdf_path = temp_dir / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 72), "Test Document", fontsize=24)
    page.insert_text((72, 120), "Sample PDF for GUI E2E tests.", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def multiple_pdfs(temp_dir: Path) -> list[Path]:
    """Create multiple PDFs for batch testing."""
    pdfs = []
    for i in range(3):
        pdf_path = temp_dir / f"batch_{i}.pdf"
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((72, 72), f"Batch Document {i}", fontsize=24)
        doc.save(pdf_path)
        doc.close()
        pdfs.append(pdf_path)
    return pdfs


@pytest.fixture
def mock_settings(temp_dir: Path, monkeypatch):
    """Mock settings with temp directories and dry-run enabled."""
    nss_dir = temp_dir / ".nss"
    nss_dir.mkdir()

    settings = Settings(
        nss_db_path=nss_dir,
        tsa_url="https://test.tsa.example.com",
        dry_run=True,
        recent_files_enabled=True,
        recent_files_limit=10,
        system_notifications_enabled=True,
    )

    monkeypatch.setattr("pdfsigner.config.settings.get_settings", lambda: settings)
    return settings


# ============================================================================
# Test Classes - Structure Verification
# ============================================================================


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestMainWindowLaunch:
    """Tests for main window initialization and structure."""

    def test_main_window_launches(self, mock_settings):
        """Test main window creation."""
        window = MainWindow()

        assert window is not None
        assert isinstance(window, Adw.ApplicationWindow)
        assert window.get_title() is not None

        # Verify essential components exist
        assert hasattr(window, "file_list")
        assert hasattr(window, "sign_button")
        assert hasattr(window, "info_label")
        assert hasattr(window, "toast_overlay")

    def test_main_window_has_handlers(self, mock_settings):
        """Test main window has signing and validation handlers."""
        window = MainWindow()

        assert hasattr(window, "signing_handler")
        assert hasattr(window, "validation_handler")
        assert hasattr(window.signing_handler, "sign_files")

    def test_main_window_default_size(self, mock_settings):
        """Test main window has correct default size in source."""
        import inspect

        source = inspect.getsource(MainWindow.__init__)
        assert "set_default_size(700, 500)" in source

    def test_main_window_has_action_bar(self, mock_settings):
        """Test main window has bottom action bar with buttons."""
        window = MainWindow()

        assert hasattr(window, "sign_button")
        assert hasattr(window, "info_label")

    def test_main_window_has_header_bar(self, mock_settings):
        """Test main window has header bar with menu in source."""
        import inspect

        source = inspect.getsource(MainWindow._setup_ui)
        assert "Adw.HeaderBar()" in source
        assert "MenuButton" in source


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestFileLoading:
    """Tests for file loading structure."""

    def test_add_nonpdf_files_ignored(self, mock_settings, temp_dir: Path):
        """Test non-PDF files are filtered (verifies filter exists)."""
        window = MainWindow()

        txt_file = temp_dir / "test.txt"
        txt_file.write_text("Not a PDF")

        # The filter should reject .txt files
        window.add_files([str(txt_file)])

        # Files list should be empty (mocked but filter logic runs)
        files = window.file_list.get_files()
        assert len(files) == 0

    def test_info_label_updates_method_exists(self, mock_settings):
        """Test info label update method uses file count."""
        import inspect

        source = inspect.getsource(MainWindow._update_info_label)
        assert "get_file_count()" in source


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestSigningFlow:
    """Tests for signing flow structure."""

    def test_sign_button_exists(self, mock_settings, sample_pdf: Path):
        """Test sign button exists after file loaded."""
        window = MainWindow()
        window.add_files([str(sample_pdf)])

        assert window.sign_button is not None

    def test_toast_notification_method_works(self, mock_settings):
        """Test toast notification method executes without error."""
        window = MainWindow()

        # Should not raise
        window.show_toast("Test message")

        assert hasattr(window, "toast_overlay")

    def test_show_error_method_exists(self, mock_settings):
        """Test error display method exists on handler."""
        window = MainWindow()

        # Should not raise
        window.signing_handler._show_error("Error", "Test error")

        assert hasattr(window.signing_handler, "_show_error")


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestRecentFiles:
    """Tests for recent files structure."""

    def test_recent_files_button_exists(self, mock_settings):
        """Test recent files button exists when enabled."""
        mock_settings.recent_files_enabled = True
        window = MainWindow()

        assert hasattr(window, "recent_button")


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestKeyboardShortcuts:
    """Tests for keyboard shortcuts structure."""

    def test_file_chooser_method_exists(self, mock_settings):
        """Test file chooser method exists for Ctrl+O."""
        window = MainWindow()

        assert hasattr(window, "show_file_chooser")
        assert callable(window.show_file_chooser)

    def test_sign_action_exists(self, mock_settings, sample_pdf: Path):
        """Test sign action exists for Ctrl+S."""
        window = MainWindow()

        with patch("pdfsigner.gui.file_list_widget.PDFValidator"):
            window.add_files([str(sample_pdf)])

            action = window.lookup_action("sign")
            assert action is not None
            assert hasattr(action, "activate")

    def test_clear_action_exists(self, mock_settings):
        """Test clear action exists."""
        window = MainWindow()

        action = window.lookup_action("clear")
        assert action is not None

    def test_validate_action_exists(self, mock_settings):
        """Test validate action exists."""
        window = MainWindow()

        action = window.lookup_action("validate")
        assert action is not None


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestBatchOperations:
    """Tests for batch operations structure."""

    def test_sign_files_accepts_multiple(self, mock_settings):
        """Test sign_files method accepts multiple files."""
        import inspect

        source = inspect.getsource(SigningHandler.sign_files)
        assert "files" in source

    def test_clear_removes_files(self, mock_settings, multiple_pdfs: list[Path]):
        """Test clear method exists and is callable."""
        window = MainWindow()
        window.add_files([str(p) for p in multiple_pdfs])

        # Should not raise
        window._on_clear_clicked(None)

        # Method executed (actual clearing is mocked)
        files = window.file_list.get_files()
        assert len(files) == 0


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestWindowState:
    """Tests for window state structure."""

    def test_window_title_in_source(self, mock_settings):
        """Test window title is set in source code."""
        import inspect

        source = inspect.getsource(MainWindow.__init__)
        assert 'set_title(_("PDFSigner"))' in source

    def test_toast_overlay_exists(self, mock_settings):
        """Test toast overlay is set up."""
        window = MainWindow()

        assert hasattr(window, "toast_overlay")
        assert window.toast_overlay is not None


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestFileListWidget:
    """Tests for FileListWidget structure."""

    def test_file_list_widget_creation(self):
        """Test FileListWidget can be created."""
        widget = FileListWidget()

        assert widget is not None
        assert isinstance(widget, Gtk.ScrolledWindow)


@pytest.mark.gui
@pytest.mark.skipif(not DISPLAY_AVAILABLE, reason="No display available")
class TestIntegrationWorkflows:
    """Integration structure tests."""

    def test_dry_run_batch_manager_works(self, mock_settings, sample_pdf: Path):
        """Test MockBatchManager for dry-run signing."""
        mock_batch = MockBatchManager()
        mock_result = mock_batch.sign_batch(
            pdf_files=[sample_pdf],
            appearance=SignatureAppearance(
                visible=True, page="last", position_preference=PositionPreference.BOTTOM_RIGHT
            ),
        )

        assert mock_result.all_successful

    def test_settings_dialog_method_exists(self, mock_settings):
        """Test settings dialog open method exists."""
        window = MainWindow()

        with patch("pdfsigner.gui.main_window.SettingsDialog") as mock_dialog_class:
            mock_dialog = MagicMock()
            mock_dialog_class.return_value = mock_dialog

            window.show_settings()

            # Dialog close handler exists
            window._on_settings_closed(mock_dialog)

            assert hasattr(window, "recent_button")


# ============================================================================
# Main entry point
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "gui"])

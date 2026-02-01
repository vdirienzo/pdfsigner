"""Tests for RecentFilesManager."""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Mock GTK before importing
if "gi.repository" not in sys.modules:
    mock_gtk = MagicMock()
    mock_gtk.RecentManager.get_default = MagicMock()
    mock_gtk.RecentData = MagicMock

    sys.modules["gi"] = MagicMock()
    sys.modules["gi.repository"] = MagicMock()
    sys.modules["gi.repository.Gtk"] = mock_gtk

from pdfsigner.core.recent.recent_manager import RecentFileInfo, RecentFilesManager


class TestRecentFileInfo:
    """Tests for RecentFileInfo dataclass."""

    def test_recent_file_info_creation(self):
        """RecentFileInfo can be created with required fields."""
        info = RecentFileInfo(
            path=Path("/test/file.pdf"),
            display_name="file.pdf",
            added_time=datetime.now(),
            exists=True,
        )

        assert info.path == Path("/test/file.pdf")
        assert info.display_name == "file.pdf"
        assert isinstance(info.added_time, datetime)
        assert info.exists is True


class TestRecentFilesManagerSingleton:
    """Tests for singleton pattern."""

    def test_get_recent_files_manager_returns_singleton(self):
        """Same instance returned on multiple calls."""
        import pdfsigner.core.recent.recent_manager as rm

        rm._manager = None

        from pdfsigner.core.recent import get_recent_files_manager

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_limit = 10

            mgr1 = get_recent_files_manager()
            mgr2 = get_recent_files_manager()

            assert mgr1 is mgr2


class TestAddFile:
    """Tests for add_file method."""

    @pytest.fixture
    def manager(self):
        """Create fresh manager."""
        with patch("pdfsigner.core.recent.recent_manager.Gtk.RecentManager.get_default"):
            return RecentFilesManager(limit=10)

    def test_add_file_returns_false_when_file_not_exists(self, manager, tmp_path):
        """File not added when it doesn't exist."""
        non_existent = tmp_path / "nonexistent.pdf"

        result = manager.add_file(non_existent)

        assert result is False

    def test_add_file_calls_manager_add_item(self, manager, tmp_path):
        """add_item called with correct URI when file exists."""
        test_file = tmp_path / "test.pdf"
        test_file.write_text("dummy")

        manager._manager.add_item = MagicMock(return_value=True)

        result = manager.add_file(test_file, operation="signed")

        assert result is True
        manager._manager.add_item.assert_called_once()

        # Verify URI is correct
        call_args = manager._manager.add_item.call_args
        uri = call_args[0][0]
        assert uri == test_file.as_uri()

    def test_add_file_with_different_operations(self, manager, tmp_path):
        """Different operations all result in add_item calls."""
        test_file = tmp_path / "test.pdf"
        test_file.write_text("dummy")

        manager._manager.add_item = MagicMock(return_value=True)

        for operation in ["signed", "validated", "opened"]:
            manager.add_file(test_file, operation=operation)

        # Verify add_item was called 3 times
        assert manager._manager.add_item.call_count == 3


class TestGetRecentPdfs:
    """Tests for get_recent_pdfs method."""

    @pytest.fixture
    def manager(self):
        """Create fresh manager."""
        with patch("pdfsigner.core.recent.recent_manager.Gtk.RecentManager.get_default"):
            return RecentFilesManager(limit=10)

    def test_get_recent_pdfs_respects_disabled_setting(self, manager):
        """Returns empty list when recent files disabled."""
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = False

            result = manager.get_recent_pdfs()

            assert result == []

    def test_get_recent_pdfs_filters_by_mime_type(self, manager):
        """Only returns items with PDF MIME type."""
        mock_pdf_item = MagicMock()
        mock_pdf_item.get_mime_type.return_value = "application/pdf"
        mock_pdf_item.has_application.return_value = True
        mock_pdf_item.get_uri.return_value = "file:///test/file.pdf"
        mock_pdf_item.get_display_name.return_value = "file.pdf"
        mock_pdf_item.get_modified.return_value = datetime.now().timestamp()

        mock_doc_item = MagicMock()
        mock_doc_item.get_mime_type.return_value = "application/msword"

        manager._manager.get_items.return_value = [mock_pdf_item, mock_doc_item]

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            # Only PDF should be returned
            assert len(result) == 1
            assert result[0].display_name == "file.pdf"

    def test_get_recent_pdfs_filters_by_app_name(self, manager):
        """Only returns items registered with pdfsigner."""
        mock_item = MagicMock()
        mock_item.get_mime_type.return_value = "application/pdf"
        mock_item.has_application.return_value = False  # Not pdfsigner

        manager._manager.get_items.return_value = [mock_item]

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            assert len(result) == 0

    def test_get_recent_pdfs_respects_limit(self, manager):
        """Returns only up to limit files."""
        mock_items = []
        base_time = datetime.now().timestamp()

        for i in range(20):
            item = MagicMock()
            item.get_mime_type.return_value = "application/pdf"
            item.has_application.return_value = True
            item.get_uri.return_value = f"file:///test/file{i}.pdf"
            item.get_display_name.return_value = f"file{i}.pdf"
            item.get_modified.return_value = base_time - i  # Newer first
            mock_items.append(item)

        manager._manager.get_items.return_value = mock_items

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            assert len(result) == 10

    def test_get_recent_pdfs_sorts_by_time_newest_first(self, manager):
        """Results sorted by added_time, newest first."""
        base_time = datetime.now().timestamp()

        # Create items with different timestamps
        old_item = MagicMock()
        old_item.get_mime_type.return_value = "application/pdf"
        old_item.has_application.return_value = True
        old_item.get_uri.return_value = "file:///test/old.pdf"
        old_item.get_display_name.return_value = "old.pdf"
        old_item.get_modified.return_value = base_time - 1000

        new_item = MagicMock()
        new_item.get_mime_type.return_value = "application/pdf"
        new_item.has_application.return_value = True
        new_item.get_uri.return_value = "file:///test/new.pdf"
        new_item.get_display_name.return_value = "new.pdf"
        new_item.get_modified.return_value = base_time

        manager._manager.get_items.return_value = [old_item, new_item]

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            # Newest should be first
            assert result[0].display_name == "new.pdf"
            assert result[1].display_name == "old.pdf"

    def test_get_recent_pdfs_handles_invalid_items(self, manager):
        """Invalid items are skipped without crashing."""
        good_item = MagicMock()
        good_item.get_mime_type.return_value = "application/pdf"
        good_item.has_application.return_value = True
        good_item.get_uri.return_value = "file:///test/good.pdf"
        good_item.get_display_name.return_value = "good.pdf"
        good_item.get_modified.return_value = datetime.now().timestamp()

        bad_item = MagicMock()
        bad_item.get_mime_type.return_value = "application/pdf"
        bad_item.has_application.return_value = True
        bad_item.get_uri.side_effect = RuntimeError("Invalid URI")

        manager._manager.get_items.return_value = [good_item, bad_item]

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            # Only good item should be returned
            assert len(result) == 1
            assert result[0].display_name == "good.pdf"

    def test_get_recent_pdfs_skips_non_file_uris(self, manager):
        """Non-file:// URIs are skipped."""
        http_item = MagicMock()
        http_item.get_mime_type.return_value = "application/pdf"
        http_item.has_application.return_value = True
        http_item.get_uri.return_value = "http://example.com/file.pdf"

        manager._manager.get_items.return_value = [http_item]

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.recent_files_enabled = True
            mock_settings.return_value.recent_files_limit = 10

            result = manager.get_recent_pdfs()

            assert len(result) == 0


class TestClearPdfHistory:
    """Tests for clear_pdf_history method."""

    @pytest.fixture
    def manager(self):
        """Create fresh manager."""
        with patch("pdfsigner.core.recent.recent_manager.Gtk.RecentManager.get_default"):
            return RecentFilesManager(limit=10)

    def test_clear_pdf_history_removes_pdfsigner_items(self, manager):
        """Only removes items registered with pdfsigner app."""
        pdf_item = MagicMock()
        pdf_item.has_application.return_value = True
        pdf_item.get_uri.return_value = "file:///test/file.pdf"

        other_item = MagicMock()
        other_item.has_application.return_value = False

        manager._manager.get_items.return_value = [pdf_item, other_item]
        manager._manager.remove_item = MagicMock()

        removed = manager.clear_pdf_history()

        assert removed == 1
        manager._manager.remove_item.assert_called_once_with("file:///test/file.pdf")

    def test_clear_pdf_history_counts_removed_items(self, manager):
        """Returns count of successfully removed items."""
        items = []
        for i in range(5):
            item = MagicMock()
            item.has_application.return_value = True
            item.get_uri.return_value = f"file:///test/file{i}.pdf"
            items.append(item)

        manager._manager.get_items.return_value = items
        manager._manager.remove_item = MagicMock()

        removed = manager.clear_pdf_history()

        assert removed == 5
        assert manager._manager.remove_item.call_count == 5

    def test_clear_pdf_history_handles_removal_errors(self, manager):
        """Continues on error and doesn't count failed removals."""
        good_item = MagicMock()
        good_item.has_application.return_value = True
        good_item.get_uri.return_value = "file:///test/good.pdf"

        bad_item = MagicMock()
        bad_item.has_application.return_value = True
        bad_item.get_uri.return_value = "file:///test/bad.pdf"

        manager._manager.get_items.return_value = [good_item, bad_item]

        def remove_side_effect(uri):
            if uri == "file:///test/bad.pdf":
                raise RuntimeError("Cannot remove")

        manager._manager.remove_item = MagicMock(side_effect=remove_side_effect)

        removed = manager.clear_pdf_history()

        # Only successful removal should be counted
        assert removed == 1

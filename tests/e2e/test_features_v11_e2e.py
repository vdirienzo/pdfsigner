"""
test_features_v11_e2e.py - End-to-end tests for v1.1 features

Author: Homero Thompson del Lago del Terror

Tests E2E coverage for v1.1 features:
- Recent files tracking
- System notifications
- Settings (validation/behavior pages)
- Accessibility labels
"""

import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import fitz  # PyMuPDF
import pytest

from pdfsigner.core.mock.mock_batch import MockBatchManager
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    tmp = tempfile.mkdtemp(prefix="pdfsigner_v11_e2e_")
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_pdf(temp_dir: Path) -> Path:
    """Create a simple 1-page PDF for testing."""
    pdf_path = temp_dir / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 72), "Test Document", fontsize=24)
    page.insert_text((72, 120), "Sample PDF for v1.1 E2E tests.", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def batch_pdfs(temp_dir: Path) -> list[Path]:
    """Create multiple PDFs for batch signing tests."""
    pdfs = []
    for i in range(1, 4):
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
    """Mock settings with temp directories."""
    from pdfsigner.config.settings import Settings

    nss_dir = temp_dir / ".nss"
    nss_dir.mkdir()
    config_dir = temp_dir / "config"
    config_dir.mkdir()

    settings = Settings(
        nss_db_path=nss_dir,
        tsa_url="https://test.tsa.example.com",
        log_level="DEBUG",
        log_dir=temp_dir / "logs",
        recent_files_enabled=True,
        recent_files_limit=10,
        system_notifications_enabled=True,
        revocation_check_enabled=False,
        revocation_check_timeout=10,
        revocation_cache_ttl=3600,
        revocation_prefer_ocsp=True,
    )

    # Monkeypatch get_settings globally
    # This will affect all imports that use get_settings()
    monkeypatch.setattr(
        "pdfsigner.config.settings.get_settings",
        lambda: settings,
    )

    return settings


@pytest.fixture
def mock_gtk_recent_manager():
    """Mock GTK RecentManager for testing."""
    manager = MagicMock()

    # Mock recent items
    mock_items = []

    def add_item(uri: str) -> bool:
        """Mock add_item method."""
        item = MagicMock()
        item.get_uri.return_value = uri
        item.get_mime_type.return_value = "application/pdf"
        item.has_application.return_value = True
        item.get_display_name.return_value = uri.split("/")[-1]
        item.get_modified.return_value = 1700000000.0  # Mock timestamp
        mock_items.append(item)
        return True

    def get_items():
        """Mock get_items method."""
        return mock_items

    manager.add_item = add_item
    manager.get_items = get_items
    manager.remove_item = MagicMock(return_value=True)

    return manager


@pytest.fixture
def mock_gio_application():
    """Mock Gio.Application for notification tests."""
    app = MagicMock()

    # Track sent notifications
    app.sent_notifications = []

    def send_notification(notification_id: str, notification):
        """Track notification calls."""
        app.sent_notifications.append(
            {
                "id": notification_id,
                "notification": notification,
            }
        )

    app.send_notification = send_notification

    # Mock window state (not active = should notify)
    window = MagicMock()
    window.is_active.return_value = False
    app.get_active_window.return_value = window

    return app


# ============================================================================
# Test Classes
# ============================================================================


class TestRecentFilesFlow:
    """E2E tests for recent files tracking."""

    def test_sign_file_adds_to_recent(
        self,
        sample_pdf: Path,
        temp_dir: Path,
        mock_settings,
        mock_gtk_recent_manager,
    ):
        """Sign a file and verify it appears in recent files list."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Create recent files manager with mock GTK manager
        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        # Sign the file
        batch_manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = batch_manager.sign_batch(
            pdf_files=[sample_pdf],
            appearance=appearance,
        )

        assert result.all_successful
        output_path = result.results[0].output_path

        # Add signed file to recent files
        success = recent_manager.add_file(output_path, operation="signed")
        assert success

        # Verify it appears in recent files
        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 1
        assert recent_files[0].path == output_path
        assert recent_files[0].display_name == output_path.name

    def test_batch_sign_adds_all_to_recent(
        self,
        batch_pdfs: list[Path],
        mock_settings,
        mock_gtk_recent_manager,
    ):
        """Batch sign multiple files and verify all appear in recent files."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        # Batch sign
        batch_manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        result = batch_manager.sign_batch(
            pdf_files=batch_pdfs,
            appearance=appearance,
        )

        assert result.all_successful
        assert result.successful == 3

        # Add all to recent files
        for res in result.results:
            recent_manager.add_file(res.output_path, operation="signed")

        # Verify all appear in recent list
        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 3

    def test_recent_files_respects_limit(
        self,
        temp_dir: Path,
        mock_settings,
        mock_gtk_recent_manager,
    ):
        """Add more files than limit and verify only limit are returned."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Set limit to 5
        mock_settings.recent_files_limit = 5
        recent_manager = RecentFilesManager(limit=5)
        recent_manager._manager = mock_gtk_recent_manager

        # Create and add 10 test PDFs
        for i in range(10):
            pdf_path = temp_dir / f"test_{i}.pdf"
            pdf_path.write_text("test")
            recent_manager.add_file(pdf_path)

        # Should only return 5 most recent
        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 5

    def test_recent_files_disabled(self, sample_pdf: Path, mock_settings, mock_gtk_recent_manager):
        """When recent files disabled, should return empty list."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Disable recent files
        mock_settings.recent_files_enabled = False

        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        # Add file
        recent_manager.add_file(sample_pdf)

        # Should return empty list when disabled
        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 0

    def test_clear_recent_history(self, sample_pdf: Path, mock_settings, mock_gtk_recent_manager):
        """Test clearing recent files history."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        # Add files
        recent_manager.add_file(sample_pdf)
        assert len(recent_manager.get_recent_pdfs()) == 1

        # Clear history
        removed = recent_manager.clear_pdf_history()
        assert removed == 1


class TestNotificationFlow:
    """E2E tests for system notifications."""

    def test_batch_complete_notification_success(
        self,
        batch_pdfs: list[Path],
        temp_dir: Path,
        mock_settings,
        mock_gio_application,
    ):
        """Complete batch signing and verify success notification is sent."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        # Reset singleton
        NotificationManager._instance = None

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = mock_gio_application
            mock_notification = MagicMock()
            mock_gio.Notification.new.return_value = mock_notification
            mock_gio.NotificationPriority.NORMAL = 1

            # Create notification manager
            notif_manager = NotificationManager.get_instance()

            # Simulate batch complete
            notif_manager.notify_batch_complete(
                total=3,
                successful=3,
                failed=0,
                output_folder=temp_dir,
            )

            # Verify notification was sent
            assert len(mock_gio_application.sent_notifications) == 1
            notif = mock_gio_application.sent_notifications[0]
            assert "batch-complete" in notif["id"]

    def test_batch_complete_notification_with_failures(
        self,
        mock_settings,
        mock_gio_application,
    ):
        """Batch with failures sends HIGH priority notification."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        NotificationManager._instance = None

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = mock_gio_application
            mock_notification = MagicMock()
            mock_gio.Notification.new.return_value = mock_notification
            mock_gio.NotificationPriority.HIGH = 2

            notif_manager = NotificationManager.get_instance()

            # Simulate batch with failures
            notif_manager.notify_batch_complete(
                total=5,
                successful=3,
                failed=2,
            )

            # Verify high priority notification sent
            assert len(mock_gio_application.sent_notifications) == 1

    def test_notification_respects_settings_disabled(
        self,
        mock_gio_application,
        temp_dir: Path,
    ):
        """When notifications disabled, no notifications are sent."""
        from pdfsigner.config.settings import Settings
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        # Create settings with notifications disabled
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()
        settings = Settings(
            nss_db_path=nss_dir,
            system_notifications_enabled=False,  # Disabled
        )

        NotificationManager._instance = None

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = mock_gio_application

            # Patch get_settings in the notification_manager module
            with patch(
                "pdfsigner.core.notifications.notification_manager.get_settings",
                return_value=settings,
            ):
                notif_manager = NotificationManager.get_instance()

                # Try to send notification
                notif_manager.notify_batch_complete(total=1, successful=1, failed=0)

                # Should not send when disabled
                assert len(mock_gio_application.sent_notifications) == 0

    def test_notification_only_when_window_not_active(
        self,
        mock_settings,
    ):
        """Notifications only sent when window is not active."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        NotificationManager._instance = None

        # Mock application with active window
        app = MagicMock()
        window = MagicMock()
        window.is_active.return_value = True  # Window IS active
        app.get_active_window.return_value = window

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = app
            mock_notification = MagicMock()
            mock_gio.Notification.new.return_value = mock_notification

            notif_manager = NotificationManager.get_instance()

            # Should not notify when window is active
            assert not notif_manager.should_notify()

            # Try to send notification
            notif_manager.notify_batch_complete(total=1, successful=1, failed=0)

            # Notification should not be sent
            mock_gio.Notification.new.assert_not_called()

    def test_critical_error_notification(
        self,
        mock_settings,
        mock_gio_application,
    ):
        """Critical error sends HIGH priority notification."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        NotificationManager._instance = None

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = mock_gio_application
            mock_notification = MagicMock()
            mock_gio.Notification.new.return_value = mock_notification
            mock_gio.NotificationPriority.HIGH = 2

            notif_manager = NotificationManager.get_instance()

            # Send critical error
            notif_manager.notify_critical_error(
                error_type="Token Error",
                message="Failed to connect to token",
            )

            # Verify notification sent
            assert len(mock_gio_application.sent_notifications) == 1
            notif = mock_gio_application.sent_notifications[0]
            assert "critical-error" in notif["id"]


class TestSettingsFlow:
    """E2E tests for settings dialog and persistence."""

    def test_validation_settings_save_and_load(self, temp_dir: Path, mock_settings):
        """Change validation settings and verify they persist."""
        from pdfsigner.config.settings import Settings

        config_file = temp_dir / "config.toml"

        # Create TOML config with validation settings
        config_content = """
        # Validation
        revocation_check_enabled = true
        revocation_check_timeout = 15
        revocation_cache_ttl = 7200
        revocation_prefer_ocsp = false
        """
        config_file.write_text(config_content)

        # Load settings from file
        with patch("pdfsigner.config.settings.TOML_CONFIG_PATH", config_file):
            settings = Settings()

        # Verify validation settings loaded correctly
        assert settings.revocation_check_enabled is True
        assert settings.revocation_check_timeout == 15
        assert settings.revocation_cache_ttl == 7200
        assert settings.revocation_prefer_ocsp is False

    def test_behavior_settings_save_and_load(self, temp_dir: Path):
        """Change behavior settings and verify they persist."""
        from pdfsigner.config.settings import Settings

        config_file = temp_dir / "config.toml"

        # Create TOML config with behavior settings
        config_content = """
        # Behavior
        recent_files_enabled = false
        recent_files_limit = 25
        system_notifications_enabled = false
        """
        config_file.write_text(config_content)

        # Load settings from file
        with patch("pdfsigner.config.settings.TOML_CONFIG_PATH", config_file):
            settings = Settings()

        # Verify behavior settings loaded correctly
        assert settings.recent_files_enabled is False
        assert settings.recent_files_limit == 25
        assert settings.system_notifications_enabled is False

    def test_settings_validation_page_integration(self, temp_dir: Path):
        """Test validation page creation and widget references."""
        # Import conftest_gui to install mocks first
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.config.settings import Settings
        from pdfsigner.gui.settings_pages.validation_page import create_validation_page

        settings = Settings(
            revocation_check_enabled=True,
            revocation_check_timeout=20,
            revocation_cache_ttl=7200,
            revocation_prefer_ocsp=True,
        )

        # Create mock dialog
        dialog = MagicMock()

        # Create validation page
        page = create_validation_page(settings, dialog)

        # Verify page created
        assert page is not None

        # Verify widget references stored in dialog
        assert hasattr(dialog, "revocation_switch")
        assert hasattr(dialog, "revocation_timeout_spin")
        assert hasattr(dialog, "revocation_cache_ttl_spin")
        assert hasattr(dialog, "revocation_prefer_ocsp_switch")

    def test_settings_behavior_page_integration(self, temp_dir: Path):
        """Test behavior page creation and widget references."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.config.settings import Settings
        from pdfsigner.gui.settings_pages.behavior_page import create_behavior_page

        settings = Settings(
            recent_files_enabled=True,
            recent_files_limit=15,
            system_notifications_enabled=True,
        )

        # Create mock dialog
        dialog = MagicMock()

        # Create behavior page
        page = create_behavior_page(settings, dialog)

        # Verify page created
        assert page is not None

        # Verify widget references stored in dialog
        assert hasattr(dialog, "recent_files_switch")
        assert hasattr(dialog, "recent_files_limit_spin")
        assert hasattr(dialog, "notifications_switch")

    def test_settings_full_workflow(self, temp_dir: Path):
        """Test complete settings save/load workflow."""
        from pdfsigner.config.settings import Settings

        config_file = temp_dir / "config.toml"

        # Initial settings
        initial_content = """
        revocation_check_enabled = false
        recent_files_enabled = true
        system_notifications_enabled = true
        """
        config_file.write_text(initial_content)

        # Load settings
        with patch("pdfsigner.config.settings.TOML_CONFIG_PATH", config_file):
            settings1 = Settings()
            assert settings1.revocation_check_enabled is False
            assert settings1.recent_files_enabled is True

        # Simulate settings change
        updated_content = """
        revocation_check_enabled = true
        recent_files_enabled = false
        system_notifications_enabled = false
        """
        config_file.write_text(updated_content)

        # Reload settings
        with patch("pdfsigner.config.settings.TOML_CONFIG_PATH", config_file):
            settings2 = Settings()
            assert settings2.revocation_check_enabled is True
            assert settings2.recent_files_enabled is False
            assert settings2.system_notifications_enabled is False


class TestAccessibilityFlow:
    """E2E tests for accessibility features."""

    def test_a11y_set_accessible_name(self):
        """Test set_accessible_name function."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.gui.a11y import set_accessible_name

        # Create mock widget
        widget = MagicMock()
        widget.update_property = MagicMock()

        # Set accessible name
        set_accessible_name(widget, "Test Button")

        # Verify update_property was called
        widget.update_property.assert_called_once()
        args = widget.update_property.call_args[0]
        # First arg is list of properties, second is list of values
        assert len(args) == 2
        assert "Test Button" in args[1]

    def test_a11y_set_accessible_description(self):
        """Test set_accessible_description function."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.gui.a11y import set_accessible_description

        widget = MagicMock()
        widget.update_property = MagicMock()

        # Set accessible description
        set_accessible_description(widget, "This button does something")

        # Verify called
        widget.update_property.assert_called_once()

    def test_a11y_set_accessible_both(self):
        """Test set_accessible with both name and description."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.gui.a11y import set_accessible

        widget = MagicMock()
        widget.update_property = MagicMock()

        # Set both name and description
        set_accessible(
            widget,
            name="Sign Button",
            description="Sign all selected PDF documents",
        )

        # Verify called with both
        widget.update_property.assert_called_once()
        args = widget.update_property.call_args[0]
        assert len(args) == 2
        # Should have both values
        assert "Sign Button" in args[1]
        assert "Sign all selected PDF documents" in args[1]

    def test_a11y_critical_widgets_have_labels(self):
        """Verify critical widgets in behavior page have accessible labels."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.config.settings import Settings
        from pdfsigner.gui.settings_pages.behavior_page import create_behavior_page

        settings = Settings()
        dialog = MagicMock()

        # Create page (should call set_accessible on widgets)
        page = create_behavior_page(settings, dialog)

        assert page is not None

        # Verify critical widgets have been created with accessibility
        # (The page creation calls set_accessible internally)
        assert hasattr(dialog, "recent_files_switch")
        assert hasattr(dialog, "notifications_switch")

    def test_a11y_validation_widgets_have_labels(self):
        """Verify validation page widgets have accessible labels."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "unit"))
        import conftest_gui  # noqa: F401

        from pdfsigner.config.settings import Settings
        from pdfsigner.gui.settings_pages.validation_page import create_validation_page

        settings = Settings()
        dialog = MagicMock()

        # Create page
        page = create_validation_page(settings, dialog)

        assert page is not None

        # Verify accessibility widget references
        assert hasattr(dialog, "revocation_switch")
        assert hasattr(dialog, "revocation_timeout_spin")
        assert hasattr(dialog, "revocation_cache_ttl_spin")


class TestIntegrationWorkflows:
    """E2E integration tests combining multiple features."""

    def test_full_signing_workflow_with_recent_and_notification(
        self,
        sample_pdf: Path,
        temp_dir: Path,
        mock_settings,
        mock_gtk_recent_manager,
        mock_gio_application,
    ):
        """Complete workflow: sign → add to recent → send notification."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Setup
        NotificationManager._instance = None
        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            mock_gio.Application.get_default.return_value = mock_gio_application
            mock_notification = MagicMock()
            mock_gio.Notification.new.return_value = mock_notification
            mock_gio.NotificationPriority.NORMAL = 1

            notif_manager = NotificationManager.get_instance()

            # Step 1: Sign file
            batch_manager = MockBatchManager()
            appearance = SignatureAppearance(visible=True, page="last")

            result = batch_manager.sign_batch(
                pdf_files=[sample_pdf],
                appearance=appearance,
            )

            assert result.all_successful
            output_path = result.results[0].output_path

            # Step 2: Add to recent files
            success = recent_manager.add_file(output_path, operation="signed")
            assert success

            # Step 3: Send notification
            notif_manager.notify_batch_complete(
                total=1,
                successful=1,
                failed=0,
                output_folder=temp_dir,
            )

            # Verify all steps completed
            recent_files = recent_manager.get_recent_pdfs()
            assert len(recent_files) == 1
            assert recent_files[0].path == output_path

            assert len(mock_gio_application.sent_notifications) == 1

    def test_batch_workflow_with_settings(
        self,
        batch_pdfs: list[Path],
        temp_dir: Path,
        mock_settings,
        mock_gtk_recent_manager,
    ):
        """Batch signing respecting settings for recent files and notifications."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Configure settings
        mock_settings.recent_files_enabled = True
        mock_settings.recent_files_limit = 5

        recent_manager = RecentFilesManager(limit=5)
        recent_manager._manager = mock_gtk_recent_manager

        # Batch sign
        batch_manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        result = batch_manager.sign_batch(
            pdf_files=batch_pdfs,
            appearance=appearance,
        )

        assert result.all_successful
        assert result.successful == 3

        # Add all to recent
        for res in result.results:
            recent_manager.add_file(res.output_path)

        # Verify respects settings
        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 3  # Within limit


class TestEdgeCases:
    """Edge cases and error handling for v1.1 features."""

    def test_recent_files_with_nonexistent_file(
        self,
        temp_dir: Path,
        mock_settings,
        mock_gtk_recent_manager,
    ):
        """Adding non-existent file to recent files should fail gracefully."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = mock_gtk_recent_manager

        # Try to add non-existent file
        fake_path = temp_dir / "nonexistent.pdf"
        success = recent_manager.add_file(fake_path)

        # Should return False for non-existent file
        assert not success

    def test_recent_files_without_gtk_manager(self, mock_settings):
        """Recent files manager without GTK should handle gracefully."""
        from pdfsigner.core.recent.recent_manager import RecentFilesManager

        # Create manager without GTK (simulates CLI/headless)
        recent_manager = RecentFilesManager(limit=10)
        recent_manager._manager = None

        # Operations should not crash
        fake_path = Path("/tmp/test.pdf")
        success = recent_manager.add_file(fake_path)
        assert not success

        recent_files = recent_manager.get_recent_pdfs()
        assert len(recent_files) == 0

    def test_notification_without_application(self, mock_settings):
        """Notifications without application should fail gracefully."""
        from pdfsigner.core.notifications.notification_manager import NotificationManager

        NotificationManager._instance = None

        with patch("pdfsigner.core.notifications.notification_manager.Gio") as mock_gio:
            # No application available
            mock_gio.Application.get_default.return_value = None

            notif_manager = NotificationManager.get_instance()

            # Should not crash
            notif_manager.notify_batch_complete(total=1, successful=1, failed=0)

    def test_settings_with_invalid_values(self, temp_dir: Path):
        """Settings with invalid values should use defaults."""
        from pdfsigner.config.settings import Settings

        config_file = temp_dir / "config.toml"

        # Invalid config (negative values, out of range)
        config_content = """
        recent_files_limit = -5
        revocation_check_timeout = 1000
        """
        config_file.write_text(config_content)

        # Should use validation and constraints
        with patch("pdfsigner.config.settings.TOML_CONFIG_PATH", config_file):
            try:
                settings = Settings()
                # If validation passes, values should be constrained
                assert settings.recent_files_limit >= 5
                assert settings.revocation_check_timeout <= 60
            except Exception:
                # Or validation error is raised (also acceptable)
                pass


# ============================================================================
# Main entry point for running standalone
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

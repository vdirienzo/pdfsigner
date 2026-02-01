"""Tests for NotificationManager."""

from datetime import UTC
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.certificate.health_status import CertificateHealth
from pdfsigner.core.notifications.notification_manager import NotificationManager


class TestNotificationManagerSingleton:
    """Tests for singleton pattern."""

    def test_get_instance_returns_same_instance(self):
        """Same instance returned on multiple calls."""
        # Reset singleton
        NotificationManager._instance = None

        mgr1 = NotificationManager.get_instance()
        mgr2 = NotificationManager.get_instance()

        assert mgr1 is mgr2
        assert isinstance(mgr1, NotificationManager)

    def test_get_notification_manager_function(self):
        """Module-level function returns singleton."""
        from pdfsigner.core.notifications import get_notification_manager

        # Reset singleton
        NotificationManager._instance = None

        mgr1 = get_notification_manager()
        mgr2 = get_notification_manager()

        assert mgr1 is mgr2


class TestShouldNotify:
    """Tests for should_notify logic."""

    @pytest.fixture
    def manager(self):
        """Create fresh manager for each test."""
        NotificationManager._instance = None
        return NotificationManager.get_instance()

    def test_should_not_notify_when_disabled(self, manager):
        """Should return False when notifications disabled."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.return_value.system_notifications_enabled = False

            assert manager.should_notify() is False

    def test_should_notify_when_no_app(self, manager):
        """Should return True when no application instance."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.return_value.system_notifications_enabled = True

            with patch(
                "pdfsigner.core.notifications.notification_manager.Gio.Application.get_default"
            ) as mock_app:
                mock_app.return_value = None

                assert manager.should_notify() is True

    def test_should_notify_when_no_window(self, manager):
        """Should return True when no active window."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.return_value.system_notifications_enabled = True

            with patch(
                "pdfsigner.core.notifications.notification_manager.Gio.Application.get_default"
            ) as mock_app:
                mock_app_instance = MagicMock()
                mock_app_instance.get_active_window.return_value = None
                mock_app.return_value = mock_app_instance

                assert manager.should_notify() is True

    def test_should_not_notify_when_window_active(self, manager):
        """Should return False when window is active."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.return_value.system_notifications_enabled = True

            with patch(
                "pdfsigner.core.notifications.notification_manager.Gio.Application.get_default"
            ) as mock_app:
                mock_window = MagicMock()
                mock_window.is_active.return_value = True

                mock_app_instance = MagicMock()
                mock_app_instance.get_active_window.return_value = mock_window
                mock_app.return_value = mock_app_instance

                assert manager.should_notify() is False

    def test_should_notify_when_window_inactive(self, manager):
        """Should return True when window is not active."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.return_value.system_notifications_enabled = True

            with patch(
                "pdfsigner.core.notifications.notification_manager.Gio.Application.get_default"
            ) as mock_app:
                mock_window = MagicMock()
                mock_window.is_active.return_value = False

                mock_app_instance = MagicMock()
                mock_app_instance.get_active_window.return_value = mock_window
                mock_app.return_value = mock_app_instance

                assert manager.should_notify() is True

    def test_should_notify_returns_false_on_error(self, manager):
        """Should return False if error checking state."""
        with patch(
            "pdfsigner.core.notifications.notification_manager.get_settings"
        ) as mock_settings:
            mock_settings.side_effect = RuntimeError("Test error")

            assert manager.should_notify() is False


class TestBatchComplete:
    """Tests for batch complete notifications."""

    @pytest.fixture
    def manager(self):
        NotificationManager._instance = None
        return NotificationManager.get_instance()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_batch_complete_all_success(self, mock_gio, manager):
        """Notification sent when all files succeed."""
        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification
        mock_gio.NotificationPriority.NORMAL = 0

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_batch_complete(5, 5, 0, None)

        # Verify notification was created and sent
        mock_gio.Notification.new.assert_called_once()
        mock_notification.set_body.assert_called_once()
        mock_notification.set_priority.assert_called_with(mock_gio.NotificationPriority.NORMAL)
        mock_app.send_notification.assert_called_once()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_batch_complete_with_failures(self, mock_gio, manager):
        """Notification includes failure count with HIGH priority."""
        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification
        mock_gio.NotificationPriority.HIGH = 2

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_batch_complete(5, 3, 2, None)

        # Verify HIGH priority for failures
        mock_notification.set_priority.assert_called_with(mock_gio.NotificationPriority.HIGH)
        mock_app.send_notification.assert_called_once()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_batch_complete_not_sent_when_should_not_notify(self, mock_gio, manager):
        """Notification not sent when should_notify returns False."""
        with patch.object(manager, "should_notify", return_value=False):
            manager.notify_batch_complete(5, 5, 0, None)

        mock_gio.Notification.new.assert_not_called()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_batch_complete_increments_counter(self, mock_gio, manager):
        """Each notification gets unique ID."""
        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        initial_count = manager._notification_count

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_batch_complete(3, 3, 0, None)
            manager.notify_batch_complete(2, 2, 0, None)

        assert manager._notification_count == initial_count + 2


class TestCriticalError:
    """Tests for critical error notifications."""

    @pytest.fixture
    def manager(self):
        NotificationManager._instance = None
        return NotificationManager.get_instance()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_critical_error(self, mock_gio, manager):
        """Critical error notification sent with HIGH priority."""
        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification
        mock_gio.NotificationPriority.HIGH = 2

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_critical_error("Token Error", "Token not found")

        mock_gio.Notification.new.assert_called_once()
        mock_notification.set_priority.assert_called_with(mock_gio.NotificationPriority.HIGH)
        mock_app.send_notification.assert_called_once()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_critical_error_not_sent_when_disabled(self, mock_gio, manager):
        """Critical error not sent when should_notify returns False."""
        with patch.object(manager, "should_notify", return_value=False):
            manager.notify_critical_error("Test Error", "Test message")

        mock_gio.Notification.new.assert_not_called()


class TestCertificateHealth:
    """Tests for certificate health notifications."""

    @pytest.fixture
    def manager(self):
        NotificationManager._instance = None
        return NotificationManager.get_instance()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_certificate_health_expired(self, mock_gio, manager):
        """Expired certificate gets URGENT priority."""
        from datetime import datetime

        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test Certificate",
            issuer_cn="Test CA",
            serial_number="ABC123",
            not_before=now,
            not_after=now,  # Expired (not_after == now)
        )

        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification
        mock_gio.NotificationPriority.URGENT = 3

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_certificate_health(health)

        mock_notification.set_priority.assert_called_with(mock_gio.NotificationPriority.URGENT)
        assert "ABC123" in manager._notified_certificates

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_certificate_health_critical(self, mock_gio, manager):
        """Critical health gets HIGH priority."""
        from datetime import datetime, timedelta

        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test Certificate",
            issuer_cn="Test CA",
            serial_number="ABC456",
            not_before=now,
            not_after=now + timedelta(days=3),  # 3 days remaining = CRITICAL
        )

        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification
        mock_gio.NotificationPriority.HIGH = 2

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_certificate_health(health)

        mock_notification.set_priority.assert_called_with(mock_gio.NotificationPriority.HIGH)

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_certificate_health_ok_not_sent(self, mock_gio, manager):
        """OK health level does not send notification."""
        from datetime import datetime, timedelta

        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test Certificate",
            issuer_cn="Test CA",
            serial_number="ABC789",
            not_before=now,
            not_after=now + timedelta(days=365),  # 365 days = OK
        )

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_certificate_health(health)

        mock_gio.Notification.new.assert_not_called()

    @patch("pdfsigner.core.notifications.notification_manager.Gio")
    def test_notify_certificate_health_anti_spam(self, mock_gio, manager):
        """Same certificate only notified once."""
        from datetime import datetime, timedelta

        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test Certificate",
            issuer_cn="Test CA",
            serial_number="DUPLICATE",
            not_before=now,
            not_after=now + timedelta(days=30),  # 30 days = ALERT
        )

        mock_notification = MagicMock()
        mock_gio.Notification.new.return_value = mock_notification

        mock_app = MagicMock()
        mock_gio.Application.get_default.return_value = mock_app

        with patch.object(manager, "should_notify", return_value=True):
            manager.notify_certificate_health(health)
            manager.notify_certificate_health(health)

        # Should only be called once
        mock_gio.Notification.new.assert_called_once()

    def test_reset_certificate_notifications(self, manager):
        """Reset clears notified certificates set."""
        manager._notified_certificates.add("CERT1")
        manager._notified_certificates.add("CERT2")

        assert len(manager._notified_certificates) == 2

        manager.reset_certificate_notifications()

        assert len(manager._notified_certificates) == 0

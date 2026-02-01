"""
notification_manager.py - System notification manager

Author: Homero Thompson del Lago del Terror

Manages system notifications for background events in PDFSigner.
Only shows notifications when the application window is not focused.
"""

import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio  # noqa: E402
from loguru import logger  # noqa: E402

from pdfsigner.config.settings import get_settings  # noqa: E402
from pdfsigner.core.certificate.health_status import CertificateHealth, HealthLevel  # noqa: E402
from pdfsigner.i18n import _  # noqa: E402


class NotificationManager:
    """
    System notification manager for PDFSigner.

    Features:
    - Only notifies when window is not focused
    - Anti-spam for certificate health warnings (one per serial)
    - Priority-based notifications (LOW/NORMAL/HIGH)
    - Thread-safe operation
    """

    _instance: "NotificationManager | None" = None
    _lock = threading.Lock()

    def __init__(self):
        """Initialize notification manager."""
        self._notified_certificates: set[str] = set()
        self._notification_count = 0

    @classmethod
    def get_instance(cls) -> "NotificationManager":
        """
        Get or create singleton instance.

        Thread-safe singleton pattern with double-checked locking.

        Returns:
            NotificationManager singleton instance
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def should_notify(self) -> bool:
        """
        Check if notifications should be shown.

        Only notify when:
        1. System notifications are enabled in settings
        2. Application window is not active/focused

        Returns:
            True if notifications should be sent
        """
        try:
            settings = get_settings()
            if not settings.system_notifications_enabled:
                return False

            # Check if window is active
            app = Gio.Application.get_default()
            if app is None:
                return True

            window = app.get_active_window()
            if window is None:
                return True

            # If window exists and is active, don't notify
            return not window.is_active()

        except Exception as e:
            logger.warning(f"Error checking notification state: {e}")
            return False

    def notify_batch_complete(
        self,
        total: int,
        successful: int,
        failed: int,
        output_folder: Path | None = None,
    ) -> None:
        """
        Notify when batch signing completes.

        Args:
            total: Total number of files
            successful: Number of successfully signed files
            failed: Number of failed files
            output_folder: Output directory (for open-folder action)
        """
        if not self.should_notify():
            return

        try:
            notification = Gio.Notification.new(_("PDFSigner - Signing Complete"))

            # Build body message
            if failed == 0:
                body = _("✓ {successful}/{total} files signed successfully").format(
                    successful=successful, total=total
                )
                notification.set_priority(Gio.NotificationPriority.NORMAL)
            else:
                body = _("⚠ {failed} files failed").format(failed=failed)
                notification.set_priority(Gio.NotificationPriority.HIGH)

            notification.set_body(body)

            # Add action to open output folder if available
            if output_folder and output_folder.exists():
                notification.add_button(
                    _("Open Folder"),
                    f"app.open-folder::{output_folder}",
                )

            self._send_notification("batch-complete", notification)
            logger.debug(f"Sent batch complete notification: {successful}/{total} successful")

        except Exception as e:
            logger.error(f"Failed to send batch complete notification: {e}")

    def notify_critical_error(self, error_type: str, message: str) -> None:
        """
        Notify critical errors.

        Args:
            error_type: Type of error (e.g., "Token Error", "Signature Error")
            message: Error message
        """
        if not self.should_notify():
            return

        try:
            notification = Gio.Notification.new(_("PDFSigner - Error"))
            notification.set_body(f"{error_type}: {message}")
            notification.set_priority(Gio.NotificationPriority.HIGH)

            self._send_notification("critical-error", notification)
            logger.debug(f"Sent critical error notification: {error_type}")

        except Exception as e:
            logger.error(f"Failed to send critical error notification: {e}")

    def notify_certificate_health(self, health: CertificateHealth) -> None:
        """
        Notify certificate health warnings.

        Only notifies once per certificate serial (anti-spam).
        Only notifies for WARNING level or worse.

        Args:
            health: CertificateHealth object with certificate status
        """
        if not self.should_notify():
            return

        # Only notify for warning levels or worse
        if health.health_level == HealthLevel.OK:
            return

        # Anti-spam: only notify once per certificate serial
        if health.serial_number in self._notified_certificates:
            return

        try:
            notification = Gio.Notification.new(_("PDFSigner - Certificate Warning"))

            # Build message based on health level
            if health.is_expired:
                body = _("{cn} has expired").format(cn=health.subject_cn)
                priority = Gio.NotificationPriority.URGENT
            elif health.days_remaining == 1:
                body = _("{cn} expires tomorrow").format(cn=health.subject_cn)
                priority = Gio.NotificationPriority.HIGH
            else:
                body = _("{cn} expires in {days} days").format(
                    cn=health.subject_cn,
                    days=health.days_remaining,
                )
                # Priority based on health level
                if health.health_level == HealthLevel.CRITICAL:
                    priority = Gio.NotificationPriority.HIGH
                elif health.health_level == HealthLevel.ALERT:
                    priority = Gio.NotificationPriority.NORMAL
                else:  # WARNING
                    priority = Gio.NotificationPriority.LOW

            notification.set_body(body)
            notification.set_priority(priority)

            self._send_notification("certificate-health", notification)

            # Mark as notified
            self._notified_certificates.add(health.serial_number)
            logger.debug(
                f"Sent certificate health notification: {health.subject_cn} "
                f"({health.days_remaining} days)"
            )

        except Exception as e:
            logger.error(f"Failed to send certificate health notification: {e}")

    def _send_notification(self, notification_id: str, notification: Gio.Notification) -> None:
        """
        Send notification via application.

        Args:
            notification_id: Unique notification ID
            notification: Gio.Notification object
        """
        try:
            app = Gio.Application.get_default()
            if app is None:
                logger.warning("Cannot send notification: no application instance")
                return

            # Add unique suffix to ID for multiple notifications
            self._notification_count += 1
            unique_id = f"{notification_id}-{self._notification_count}"

            app.send_notification(unique_id, notification)

        except Exception as e:
            logger.error(f"Failed to send notification {notification_id}: {e}")

    def reset_certificate_notifications(self) -> None:
        """
        Reset certificate notification tracking.

        Useful for allowing re-notification after certificate renewal.
        """
        self._notified_certificates.clear()
        logger.debug("Reset certificate notification tracking")


# Module-level convenience function
def get_notification_manager() -> NotificationManager:
    """
    Get the singleton NotificationManager instance.

    Returns:
        NotificationManager singleton
    """
    return NotificationManager.get_instance()

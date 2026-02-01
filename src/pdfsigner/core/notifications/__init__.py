"""Notification system for PDFSigner."""

from pdfsigner.core.notifications.notification_manager import (
    NotificationManager,
    get_notification_manager,
)

__all__ = ["NotificationManager", "get_notification_manager"]

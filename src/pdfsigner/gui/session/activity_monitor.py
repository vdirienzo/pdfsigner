"""
activity_monitor.py - User activity monitoring for auto-logoff

Monitors user inactivity and triggers automatic logout according to HIPAA
compliance requirements (§164.312(a)(2)(iii) - Automatic Logoff).

Features:
- Monitors user inactivity in GUI
- Shows warning 1 minute before timeout
- Automatic logout after configured timeout
- Session extension on any user activity
- Only active when healthcare_mode=True

Author: Homero Thompson del Lago del Terror
"""

import time
from typing import TYPE_CHECKING

from gi.repository import Adw, GLib
from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.session import get_session_manager
from pdfsigner.exceptions import SessionExpiredError

if TYPE_CHECKING:
    pass


class ActivityMonitor:
    """
    Monitor user activity and enforce automatic logoff for HIPAA compliance.

    Only active when healthcare_mode is enabled in settings. Monitors user
    inactivity and triggers a warning dialog 1 minute before timeout, then
    performs automatic logout if no activity is detected.
    """

    def __init__(self, window: Adw.ApplicationWindow, session_id: str | None = None):
        """
        Initialize activity monitor.

        Args:
            window: Main application window
            session_id: Current session ID (required if healthcare_mode is enabled)
        """
        self.window = window
        self.session_id = session_id
        self.last_activity = time.time()
        self._timeout_id: int | None = None
        self._warning_shown = False
        self._warning_dialog: Adw.MessageDialog | None = None
        self._countdown_timeout_id: int | None = None

    def start(self) -> None:
        """
        Start activity monitoring.

        Only starts if healthcare_mode is enabled. Monitors user inactivity
        and triggers warnings/logout based on configured timeout.
        """
        settings = get_settings()
        if not settings.healthcare_mode:
            logger.debug("Healthcare mode disabled - activity monitoring not started")
            return

        if not self.session_id:
            logger.warning("Cannot start activity monitor without session_id")
            return

        if self._timeout_id is not None:
            logger.warning("Activity monitor already running")
            return

        # Reset state
        self.last_activity = time.time()
        self._warning_shown = False

        # Check inactivity every 10 seconds
        self._timeout_id = GLib.timeout_add_seconds(10, self._check_inactivity)

        logger.info(
            f"Activity monitor started for session {self.session_id} "
            f"(timeout: {settings.healthcare_session_timeout_minutes} minutes)"
        )

    def stop(self) -> None:
        """Stop activity monitoring and cleanup."""
        if self._timeout_id is not None:
            GLib.source_remove(self._timeout_id)
            self._timeout_id = None

        if self._countdown_timeout_id is not None:
            GLib.source_remove(self._countdown_timeout_id)
            self._countdown_timeout_id = None

        if self._warning_dialog is not None:
            self._warning_dialog.close()
            self._warning_dialog = None

        logger.info("Activity monitor stopped")

    def record_activity(self) -> None:
        """
        Record user activity and extend session.

        Should be called by event handlers whenever the user interacts with
        the application (clicks, keypresses, etc.).
        """
        settings = get_settings()
        if not settings.healthcare_mode:
            return

        if not self.session_id:
            return

        self.last_activity = time.time()

        # Reset warning state if user becomes active again
        if self._warning_shown:
            self._warning_shown = False
            if self._warning_dialog is not None:
                self._warning_dialog.close()
                self._warning_dialog = None
            if self._countdown_timeout_id is not None:
                GLib.source_remove(self._countdown_timeout_id)
                self._countdown_timeout_id = None

        # Extend session in SessionManager
        try:
            session_manager = get_session_manager()
            session_manager.touch_session(self.session_id)
            logger.debug(f"Session {self.session_id} extended due to user activity")
        except SessionExpiredError:
            logger.error(f"Cannot extend expired session {self.session_id}")
            self._perform_logout()
        except Exception as e:
            logger.error(f"Failed to extend session {self.session_id}: {e}")

    def _check_inactivity(self) -> bool:
        """
        Check for user inactivity and trigger warnings/logout.

        Called periodically by GLib timeout. Returns True to continue monitoring.

        Returns:
            True to continue monitoring, False to stop
        """
        settings = get_settings()
        timeout_seconds = settings.healthcare_session_timeout_minutes * 60
        warning_threshold_seconds = 60  # Show warning 1 minute before timeout

        elapsed = time.time() - self.last_activity

        # Check if session has exceeded timeout
        if elapsed >= timeout_seconds:
            logger.warning(
                f"Session {self.session_id} timeout exceeded "
                f"({elapsed:.0f}s >= {timeout_seconds}s) - performing logout"
            )
            self._perform_logout()
            return False  # Stop monitoring

        # Check if we should show warning (1 minute before timeout)
        if not self._warning_shown and elapsed >= (timeout_seconds - warning_threshold_seconds):
            logger.info(
                f"Session {self.session_id} approaching timeout ({elapsed:.0f}s) - showing warning"
            )
            self._show_timeout_warning()
            self._warning_shown = True

        return True  # Continue monitoring

    def _show_timeout_warning(self) -> None:
        """
        Show warning dialog with countdown timer.

        Displays a message dialog warning the user that they will be logged out
        in 1 minute unless they extend their session.
        """
        settings = get_settings()
        timeout_seconds = settings.healthcare_session_timeout_minutes * 60
        remaining_seconds = int(timeout_seconds - (time.time() - self.last_activity))

        message = (
            f"You will be automatically logged out in {remaining_seconds} seconds "
            "due to inactivity."
        )
        self._warning_dialog = Adw.MessageDialog.new(
            self.window,
            "Session Timeout Warning",
            message,
        )

        self._warning_dialog.add_response("extend", "Extend Session")
        self._warning_dialog.set_response_appearance("extend", Adw.ResponseAppearance.SUGGESTED)
        self._warning_dialog.set_default_response("extend")
        self._warning_dialog.set_close_response("extend")

        self._warning_dialog.connect("response", self._on_warning_response)

        # Update countdown every second
        self._countdown_timeout_id = GLib.timeout_add_seconds(
            1, self._update_warning_countdown, remaining_seconds
        )

        self._warning_dialog.present()

    def _update_warning_countdown(self, initial_remaining: int) -> bool:
        """
        Update countdown in warning dialog.

        Args:
            initial_remaining: Initial remaining seconds when dialog was shown

        Returns:
            True to continue countdown, False to stop
        """
        if self._warning_dialog is None:
            return False

        settings = get_settings()
        timeout_seconds = settings.healthcare_session_timeout_minutes * 60
        remaining = int(timeout_seconds - (time.time() - self.last_activity))

        if remaining <= 0:
            # Timeout reached
            return False

        # Update dialog body with new countdown
        self._warning_dialog.set_body(
            f"You will be automatically logged out in {remaining} seconds due to inactivity."
        )

        return True  # Continue countdown

    def _on_warning_response(self, dialog: Adw.MessageDialog, response: str) -> None:
        """
        Handle warning dialog response.

        Args:
            dialog: Warning dialog
            response: Response ID ("extend")
        """
        if response == "extend":
            logger.info(f"User extended session {self.session_id}")
            self.record_activity()  # This will reset everything

        if self._countdown_timeout_id is not None:
            GLib.source_remove(self._countdown_timeout_id)
            self._countdown_timeout_id = None

        self._warning_dialog = None

    def _perform_logout(self) -> None:
        """
        Perform automatic logout.

        Terminates the session, logs the event, and closes/locks the application
        window. This should trigger the authentication flow to restart.
        """
        if not self.session_id:
            return

        logger.warning(f"Performing automatic logout for session {self.session_id}")

        # Close warning dialog if shown
        if self._warning_dialog is not None:
            self._warning_dialog.close()
            self._warning_dialog = None

        # Stop monitoring
        self.stop()

        # Terminate session in SessionManager
        try:
            session_manager = get_session_manager()
            session_manager.terminate_session(self.session_id)
        except Exception as e:
            logger.error(f"Failed to terminate session {self.session_id}: {e}")

        # Show logout notification
        logout_dialog = Adw.MessageDialog.new(
            self.window,
            "Session Expired",
            "You have been automatically logged out due to inactivity.",
        )
        logout_dialog.add_response("ok", "OK")
        logout_dialog.set_default_response("ok")
        logout_dialog.set_close_response("ok")

        def on_logout_acknowledged(dialog: Adw.MessageDialog, response: str) -> None:
            """Handle logout acknowledgment."""
            # Close the main window or trigger re-authentication
            # This depends on how the application handles authentication
            # For now, we'll just close the window
            if hasattr(self.window, "close"):
                self.window.close()

        logout_dialog.connect("response", on_logout_acknowledged)
        logout_dialog.present()

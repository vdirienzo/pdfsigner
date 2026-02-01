"""
emergency_access_dialog.py - Emergency Access (Break-Glass) Dialog

Author: Homero Thompson del Lago del Terror

Implements HIPAA §164.312(a)(2)(ii) emergency access dialog.
Allows users to request emergency access with justification and view request status.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk
from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.emergency import (
    EmergencyAccessRequest,
    EmergencyAccessStatus,
    get_break_glass_service,
)
from pdfsigner.exceptions import EmergencyAccessError
from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


class EmergencyAccessDialog(Adw.Window):
    """
    Emergency Access (Break-Glass) dialog.

    Allows users to request temporary emergency access with a justification.
    Displays request status (pending/approved/denied) and handles approval workflow.
    """

    def __init__(self, parent: Adw.ApplicationWindow, user_id: str):
        """
        Initialize emergency access dialog.

        Args:
            parent: Parent application window
            user_id: User ID requesting emergency access
        """
        super().__init__()

        self.user_id = user_id
        self.service = get_break_glass_service()
        self.settings = get_settings()
        self.current_request: EmergencyAccessRequest | None = None

        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_title(_("Emergency Access"))
        self.set_default_size(500, 400)

        self._setup_ui()
        self._check_existing_request()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        # Header bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        # Main layout with toolbar
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Content box
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)

        # Info section
        info_group = Adw.PreferencesGroup()
        info_group.set_title(_("Emergency Access Request"))
        info_group.set_description(
            _(
                "Emergency access allows temporary elevated permissions during urgent situations. "
                "All access is logged and requires justification."
            )
        )

        # User info row
        user_row = Adw.ActionRow()
        user_row.set_title(_("User ID"))
        user_row.set_subtitle(self.user_id)
        user_row.add_css_class("property")
        info_group.add(user_row)

        content.append(info_group)

        # Reason input section
        reason_group = Adw.PreferencesGroup()
        reason_group.set_title(_("Justification"))
        reason_group.set_description(_("Provide a clear reason for requesting emergency access"))

        # Text view container (styled like Adwaita)
        reason_frame = Gtk.Frame()
        reason_frame.set_margin_top(8)
        reason_frame.set_margin_bottom(8)
        reason_frame.add_css_class("card")

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(120)

        self.reason_text = Gtk.TextView()
        self.reason_text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.reason_text.set_accepts_tab(False)
        self.reason_text.set_margin_top(8)
        self.reason_text.set_margin_bottom(8)
        self.reason_text.set_margin_start(12)
        self.reason_text.set_margin_end(12)
        set_accessible(
            self.reason_text,
            name=_("Emergency access justification"),
            description=_("Enter the reason for requesting emergency access"),
        )

        scroll.set_child(self.reason_text)
        reason_frame.set_child(scroll)

        reason_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        reason_box.append(reason_frame)
        reason_group.set_child(reason_box)

        content.append(reason_group)

        # Action buttons section
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        button_box.set_halign(Gtk.Align.END)

        self.request_button = Gtk.Button()
        self.request_button.set_label(_("Request Access"))
        self.request_button.add_css_class("suggested-action")
        self.request_button.add_css_class("pill")
        self.request_button.connect("clicked", self._on_request_clicked)
        set_accessible(
            self.request_button,
            name=_("Request emergency access"),
            description=_("Submit emergency access request with the provided justification"),
        )

        button_box.append(self.request_button)
        content.append(button_box)

        # Status section (initially hidden)
        self.status_group = Adw.PreferencesGroup()
        self.status_group.set_title(_("Request Status"))
        self.status_group.set_visible(False)

        self.status_row = Adw.ActionRow()
        self.status_row.set_title(_("Status"))
        self.status_row.add_css_class("property")

        # Spinner for pending status
        self.status_spinner = Gtk.Spinner()
        self.status_spinner.set_visible(False)
        self.status_row.add_suffix(self.status_spinner)

        self.status_group.add(self.status_row)

        # Request ID row
        self.request_id_row = Adw.ActionRow()
        self.request_id_row.set_title(_("Request ID"))
        self.request_id_row.add_css_class("property")
        self.status_group.add(self.request_id_row)

        content.append(self.status_group)

        # Set content
        toolbar.set_content(content)
        self.set_content(toolbar)

    def _check_existing_request(self) -> None:
        """Check if user has an existing request and display its status."""
        try:
            # Check for active request
            requests = self.service.get_user_requests(self.user_id, limit=1)
            if requests:
                latest = requests[0]
                # Show status if it's recent (pending, approved, or just denied)
                if latest.status in (
                    EmergencyAccessStatus.PENDING,
                    EmergencyAccessStatus.APPROVED,
                ):
                    self.current_request = latest
                    self._show_status(latest)
                    # Disable form if already approved
                    if latest.status == EmergencyAccessStatus.APPROVED:
                        self.reason_text.set_editable(False)
                        self.request_button.set_sensitive(False)
        except Exception as e:
            logger.warning(f"Failed to check existing request: {e}")

    def _on_request_clicked(self, button: Gtk.Button) -> None:
        """Handle request access button click."""
        # Get reason text
        buffer = self.reason_text.get_buffer()
        start = buffer.get_start_iter()
        end = buffer.get_end_iter()
        reason = buffer.get_text(start, end, False).strip()

        # Validate reason
        if not reason:
            self._show_error(_("Please provide a justification for emergency access"))
            return

        # Disable button during request
        self.request_button.set_sensitive(False)
        self.request_button.set_label(_("Requesting..."))

        # Request emergency access
        try:
            request = self.service.request_emergency_access(self.user_id, reason)
            self.current_request = request
            logger.info(f"Emergency access requested: {request.id} (status={request.status.value})")

            # Show status
            self._show_status(request)

            # If auto-approved, show success and close after delay
            if request.status == EmergencyAccessStatus.APPROVED:
                GLib.timeout_add_seconds(2, self._close_on_success)
            else:
                # Re-enable button for potential retry
                self.request_button.set_sensitive(True)
                self.request_button.set_label(_("Request Access"))

        except EmergencyAccessError as e:
            logger.error(f"Failed to request emergency access: {e}")
            self._show_error(str(e))
            self.request_button.set_sensitive(True)
            self.request_button.set_label(_("Request Access"))
        except Exception:
            logger.exception("Unexpected error requesting emergency access")
            self._show_error(_("Failed to request emergency access. Check logs for details."))
            self.request_button.set_sensitive(True)
            self.request_button.set_label(_("Request Access"))

    def _show_status(self, request: EmergencyAccessRequest) -> None:
        """
        Display request status.

        Args:
            request: Emergency access request to display
        """
        # Make status section visible
        self.status_group.set_visible(True)

        # Update request ID
        self.request_id_row.set_subtitle(request.id)

        # Update status based on request state
        if request.status == EmergencyAccessStatus.PENDING:
            self.status_row.set_subtitle(_("Pending Approval"))
            self.status_row.remove_css_class("success")
            self.status_row.remove_css_class("error")
            self.status_row.add_css_class("warning")

            # Show spinner
            self.status_spinner.set_visible(True)
            self.status_spinner.start()

            # Disable form
            self.reason_text.set_editable(False)
            self.request_button.set_sensitive(False)

        elif request.status == EmergencyAccessStatus.APPROVED:
            self.status_row.set_subtitle(_("Access Granted"))
            self.status_row.remove_css_class("warning")
            self.status_row.remove_css_class("error")
            self.status_row.add_css_class("success")

            # Hide spinner
            self.status_spinner.stop()
            self.status_spinner.set_visible(False)

            # Show expiration if available
            if request.expires_at:
                expires_str = request.expires_at.strftime("%Y-%m-%d %H:%M:%S")
                expiry_row = Adw.ActionRow()
                expiry_row.set_title(_("Expires At"))
                expiry_row.set_subtitle(expires_str)
                expiry_row.add_css_class("property")
                self.status_group.add(expiry_row)

            # Disable form
            self.reason_text.set_editable(False)
            self.request_button.set_sensitive(False)

        elif request.status == EmergencyAccessStatus.DENIED:
            self.status_row.set_subtitle(_("Access Denied"))
            self.status_row.remove_css_class("warning")
            self.status_row.remove_css_class("success")
            self.status_row.add_css_class("error")

            # Hide spinner
            self.status_spinner.stop()
            self.status_spinner.set_visible(False)

            # Keep form enabled for retry
            self.reason_text.set_editable(True)
            self.request_button.set_sensitive(True)

        elif request.status == EmergencyAccessStatus.EXPIRED:
            self.status_row.set_subtitle(_("Expired"))
            self.status_row.remove_css_class("warning")
            self.status_row.remove_css_class("success")
            self.status_row.add_css_class("error")

            # Hide spinner
            self.status_spinner.stop()
            self.status_spinner.set_visible(False)

            # Keep form enabled for new request
            self.reason_text.set_editable(True)
            self.request_button.set_sensitive(True)

        elif request.status == EmergencyAccessStatus.REVOKED:
            self.status_row.set_subtitle(_("Revoked"))
            self.status_row.remove_css_class("warning")
            self.status_row.remove_css_class("success")
            self.status_row.add_css_class("error")

            # Hide spinner
            self.status_spinner.stop()
            self.status_spinner.set_visible(False)

            # Keep form enabled for new request
            self.reason_text.set_editable(True)
            self.request_button.set_sensitive(True)

    def _show_error(self, message: str) -> None:
        """
        Show error message using toast.

        Args:
            message: Error message to display
        """
        # Try to find the application to show toast
        app = self.get_application()
        if app and hasattr(app, "show_toast"):
            app.show_toast(message)
        else:
            # Fallback: log error
            logger.error(f"Emergency access error: {message}")

        # Show error in status if status section is visible
        if self.status_group.get_visible():
            self.status_row.set_subtitle(message)
            self.status_row.add_css_class("error")
        else:
            # Create temporary error display
            error_label = Gtk.Label(label=message)
            error_label.set_wrap(True)
            error_label.add_css_class("error")
            error_label.add_css_class("caption")
            error_label.set_margin_top(12)

            # Add to content (find the main box)
            content = self.get_content()
            if isinstance(content, Adw.ToolbarView):
                main_content = content.get_content()
                if isinstance(main_content, Gtk.Box):
                    main_content.append(error_label)

    def _close_on_success(self) -> bool:
        """Close dialog after successful approval (GLib timeout callback)."""
        self.close()
        return False  # Don't repeat timeout

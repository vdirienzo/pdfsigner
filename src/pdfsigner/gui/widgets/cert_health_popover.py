"""
cert_health_popover.py - Certificate health status popover widget

Author: Homero Thompson del Lago del Terror

GTK4 popover widget that displays certificate health status with
color-coded expiry warnings. Triggered from header button.
Includes toast notifications for critical states.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from pdfsigner.core.certificate.health_status import CertificateHealth, HealthLevel
from pdfsigner.i18n import _


class CertHealthPopover(Gtk.Popover):
    """
    Certificate health status popover widget.

    Shows certificate details in a popover attached to header button.
    Displays subject, issuer, expiry date, and progress bar.
    Shows toast notifications for warnings/alerts.
    """

    def __init__(self):
        """Initialize the popover widget."""
        super().__init__()

        self._health: CertificateHealth | None = None
        self._toast_shown = False

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the popover UI components."""
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_start(16)
        main_box.set_margin_end(16)
        main_box.set_margin_top(16)
        main_box.set_margin_bottom(16)
        main_box.add_css_class("cert-health-popover")

        # === HEADER: Icon + Status ===
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        self._status_icon = Gtk.Label(label="🔐")
        self._status_icon.add_css_class("status-icon")
        header_box.append(self._status_icon)

        # Subject + status in vertical box
        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        status_box.set_hexpand(True)

        self._subject_label = Gtk.Label(label=_("Certificate Status"))
        self._subject_label.set_xalign(0)
        self._subject_label.set_wrap(True)
        self._subject_label.set_max_width_chars(30)
        status_box.append(self._subject_label)

        self._status_label = Gtk.Label(label="")
        self._status_label.set_xalign(0)
        self._status_label.add_css_class("caption")
        status_box.append(self._status_label)

        header_box.append(status_box)
        main_box.append(header_box)

        # === SEPARATOR ===
        separator1 = Gtk.Separator()
        main_box.append(separator1)

        # === DETAILS SECTION ===
        self._details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        # Issuer
        self._issuer_label = Gtk.Label(label="")
        self._issuer_label.set_xalign(0)
        self._issuer_label.set_wrap(True)
        self._issuer_label.add_css_class("dim-label")
        self._issuer_label.add_css_class("caption")
        self._details_box.append(self._issuer_label)

        # Expiry date
        self._expiry_label = Gtk.Label(label="")
        self._expiry_label.set_xalign(0)
        self._expiry_label.add_css_class("caption")
        self._details_box.append(self._expiry_label)

        main_box.append(self._details_box)

        # === PROGRESS BAR ===
        self._progress_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._progress_box.set_margin_top(4)

        self._progress_bar = Gtk.ProgressBar()
        self._progress_bar.set_hexpand(True)
        self._progress_bar.set_show_text(False)
        self._progress_box.append(self._progress_bar)

        self._progress_label = Gtk.Label(label="")
        self._progress_label.add_css_class("dim-label")
        self._progress_label.add_css_class("caption")
        self._progress_box.append(self._progress_label)

        main_box.append(self._progress_box)

        # === FOOTER SEPARATOR ===
        separator2 = Gtk.Separator()
        separator2.set_margin_top(4)
        main_box.append(separator2)

        # === REFRESH BUTTON ===
        refresh_btn = Gtk.Button()
        refresh_btn.set_halign(Gtk.Align.CENTER)
        refresh_btn.add_css_class("flat")

        refresh_content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        refresh_icon = Gtk.Image(icon_name="view-refresh-symbolic")
        refresh_content.append(refresh_icon)
        refresh_label = Gtk.Label(label=_("Refresh"))
        refresh_content.append(refresh_label)
        refresh_btn.set_child(refresh_content)

        refresh_btn.connect("clicked", self._on_refresh_clicked)
        main_box.append(refresh_btn)

        self.set_child(main_box)

    def set_health(self, health: CertificateHealth | None) -> None:
        """
        Update the popover with certificate health info.

        Args:
            health: Certificate health data or None if no cert available
        """
        self._health = health

        if health is None:
            self._show_no_certificate()
            return

        self._show_certificate(health)

        # Show toast for warnings (only once per session)
        if not self._toast_shown:
            self._show_status_toast(health)
            self._toast_shown = True

    def _show_no_certificate(self) -> None:
        """Show the 'no certificate' state."""
        self._status_icon.set_label("🔐")
        self._subject_label.set_label(_("No certificate loaded"))
        self._status_label.set_label(_("Connect a token to view certificate status"))
        self._details_box.set_visible(False)
        self._progress_box.set_visible(False)

        # Remove all status classes
        self._clear_text_classes()

    def _show_certificate(self, health: CertificateHealth) -> None:
        """Show certificate information."""
        self._details_box.set_visible(True)
        self._progress_box.set_visible(True)

        # Update icon based on health level
        self._status_icon.set_label(health.status_icon)

        # Subject name
        self._subject_label.set_label(health.subject_cn)

        # Status text with color
        self._status_label.set_label(health.status_text)
        self._clear_text_classes()
        self._status_label.add_css_class(f"cert-text-{health.health_level.value}")

        # Issuer
        self._issuer_label.set_label(f"🏢 {_('Issued by')}: {health.issuer_cn}")

        # Format expiry date
        expiry_str = health.not_after.strftime("%Y-%m-%d")
        self._expiry_label.set_label(f"📅 {_('Valid until')}: {expiry_str}")

        # Update progress bar
        self._progress_bar.set_fraction(health.lifetime_progress)
        progress_pct = int(health.lifetime_progress * 100)
        self._progress_label.set_label(f"{progress_pct}% {_('used')}")

        # Progress bar color
        self._clear_progress_classes()
        self._progress_bar.add_css_class(f"cert-progress-{health.health_level.value}")

    def _show_status_toast(self, health: CertificateHealth) -> None:
        """Show toast notification based on health level."""
        window = self.get_root()
        if not hasattr(window, "toast_overlay"):
            return

        # Determine toast message and priority
        toast_msg = None
        timeout = 3

        if health.health_level == HealthLevel.EXPIRED:
            toast_msg = f"⚠️ {_('Certificate has expired!')}"
            timeout = 5
        elif health.health_level == HealthLevel.CRITICAL:
            toast_msg = f"🚨 {_('Certificate expires in')} {health.days_remaining} {_('days!')}"
            timeout = 5
        elif health.health_level == HealthLevel.ALERT:
            toast_msg = f"🔶 {_('Certificate expires in')} {health.days_remaining} {_('days')}"
            timeout = 4
        elif health.health_level == HealthLevel.WARNING:
            toast_msg = f"⚠️ {_('Certificate expires in')} {health.days_remaining} {_('days')}"
            timeout = 3

        if toast_msg:
            # Schedule toast to show after window is ready
            GLib.timeout_add(500, self._add_toast, window, toast_msg, timeout)

    def _add_toast(self, window, message: str, timeout: int) -> bool:
        """Add toast to window's toast overlay."""
        if hasattr(window, "toast_overlay"):
            toast = Adw.Toast(title=message)
            toast.set_timeout(timeout)
            window.toast_overlay.add_toast(toast)
        return False  # Don't repeat

    def _clear_text_classes(self) -> None:
        """Remove all text color classes."""
        for level in HealthLevel:
            self._status_label.remove_css_class(f"cert-text-{level.value}")

    def _clear_progress_classes(self) -> None:
        """Remove all progress bar color classes."""
        for level in HealthLevel:
            self._progress_bar.remove_css_class(f"cert-progress-{level.value}")

    def _on_refresh_clicked(self, button: Gtk.Button) -> None:
        """Handle refresh button click."""
        # Reset toast shown flag to allow new toast
        self._toast_shown = False

        # Get main window and refresh
        window = self.get_root()
        if hasattr(window, "refresh_certificate_status"):
            window.refresh_certificate_status()

        # Close popover after refresh
        self.popdown()

    def get_health(self) -> CertificateHealth | None:
        """Get current health data."""
        return self._health

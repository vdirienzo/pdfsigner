"""
cert_health_banner.py - Certificate health status banner widget

Author: Homero Thompson del Lago del Terror

GTK4 widget that displays certificate health status with
color-coded expiry warnings in the main window header.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.certificate.health_status import CertificateHealth, HealthLevel
from pdfsigner.i18n import _


class CertHealthBanner(Gtk.Box):
    """
    Certificate health status banner widget.

    Displays certificate information with color-coded
    expiry status and progress bar.
    """

    def __init__(self):
        """Initialize the banner widget."""
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        self._health: CertificateHealth | None = None

        self.add_css_class("card")
        self.set_margin_start(12)
        self.set_margin_end(12)
        self.set_margin_top(8)
        self.set_margin_bottom(8)

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the banner UI components."""
        # Main container with padding
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.set_margin_top(10)
        content.set_margin_bottom(10)

        # Header row: icon + title
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        self._status_icon = Gtk.Label(label="🔐")
        header.append(self._status_icon)

        title = Gtk.Label(label=_("Certificate Status"))
        title.add_css_class("heading")
        title.set_hexpand(True)
        title.set_xalign(0)
        header.append(title)

        # Refresh button
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.add_css_class("flat")
        refresh_btn.set_tooltip_text(_("Refresh certificate status"))
        refresh_btn.connect("clicked", self._on_refresh_clicked)
        header.append(refresh_btn)

        content.append(header)

        # Certificate info
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info_box.set_margin_start(28)

        # Subject (certificate owner)
        self._subject_label = Gtk.Label(label="")
        self._subject_label.set_xalign(0)
        self._subject_label.add_css_class("title-4")
        info_box.append(self._subject_label)

        # Issuer
        self._issuer_label = Gtk.Label(label="")
        self._issuer_label.set_xalign(0)
        self._issuer_label.add_css_class("dim-label")
        info_box.append(self._issuer_label)

        # Expiry info row
        expiry_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        self._expiry_label = Gtk.Label(label="")
        self._expiry_label.set_xalign(0)
        expiry_box.append(self._expiry_label)

        self._days_label = Gtk.Label(label="")
        self._days_label.set_xalign(0)
        expiry_box.append(self._days_label)

        info_box.append(expiry_box)

        content.append(info_box)

        # Progress bar
        progress_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        progress_box.set_margin_start(28)
        progress_box.set_margin_top(4)

        self._progress_bar = Gtk.ProgressBar()
        self._progress_bar.set_hexpand(True)
        self._progress_bar.set_show_text(False)
        progress_box.append(self._progress_bar)

        self._progress_label = Gtk.Label(label="")
        self._progress_label.add_css_class("dim-label")
        self._progress_label.add_css_class("caption")
        progress_box.append(self._progress_label)

        content.append(progress_box)

        # No certificate message (shown when no cert available)
        self._no_cert_label = Gtk.Label(
            label=_("No certificate loaded. Connect your token to view status.")
        )
        self._no_cert_label.add_css_class("dim-label")
        self._no_cert_label.set_margin_start(28)
        self._no_cert_label.set_visible(False)

        content.append(self._no_cert_label)

        self.append(content)

        # Store content box for visibility toggling
        self._info_box = info_box
        self._progress_box = progress_box

    def set_health(self, health: CertificateHealth | None) -> None:
        """
        Update the banner with certificate health info.

        Args:
            health: Certificate health data or None if no cert available
        """
        self._health = health

        if health is None:
            self._show_no_certificate()
            return

        self._show_certificate(health)

    def _show_no_certificate(self) -> None:
        """Show the 'no certificate' state."""
        self._status_icon.set_label("🔐")
        self._info_box.set_visible(False)
        self._progress_box.set_visible(False)
        self._no_cert_label.set_visible(True)

        # Remove all status classes
        for level in HealthLevel:
            self.remove_css_class(f"cert-status-{level.value}")

    def _show_certificate(self, health: CertificateHealth) -> None:
        """Show certificate information."""
        self._info_box.set_visible(True)
        self._progress_box.set_visible(True)
        self._no_cert_label.set_visible(False)

        # Update icon based on health level
        self._status_icon.set_label(health.status_icon)

        # Update labels
        self._subject_label.set_label(f"👤 {health.subject_cn}")
        self._issuer_label.set_label(f"🏢 {health.issuer_cn}")

        # Format expiry date
        expiry_str = health.not_after.strftime("%B %d, %Y")
        self._expiry_label.set_label(f"📅 {_('Valid until')}: {expiry_str}")

        # Days remaining with color
        self._days_label.set_label(f"⏳ {health.status_text}")

        # Update days label color based on health level
        for level in HealthLevel:
            self._days_label.remove_css_class(f"cert-{level.value}")
        self._days_label.add_css_class(f"cert-{health.health_level.value}")

        # Update progress bar
        self._progress_bar.set_fraction(health.lifetime_progress)
        progress_pct = int(health.lifetime_progress * 100)
        self._progress_label.set_label(f"{progress_pct}%")

        # Update banner background color class
        for level in HealthLevel:
            self.remove_css_class(f"cert-status-{level.value}")
        self.add_css_class(health.css_class)

    def _on_refresh_clicked(self, button: Gtk.Button) -> None:
        """Handle refresh button click."""
        # Emit a custom signal or callback
        # For now, we'll let the parent handle this
        pass

    def get_health(self) -> CertificateHealth | None:
        """Get current health data."""
        return self._health

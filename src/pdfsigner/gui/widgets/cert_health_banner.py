"""
cert_health_banner.py - Certificate health status banner widget

Author: Homero Thompson del Lago del Terror

GTK4 widget that displays certificate health status with
color-coded expiry warnings. Compact by default, expandable for details.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.certificate.health_status import CertificateHealth, HealthLevel
from pdfsigner.i18n import _


class CertHealthBanner(Gtk.Box):
    """
    Certificate health status banner widget.

    Compact by default showing only icon + name + status.
    Click to expand for full details.
    """

    def __init__(self):
        """Initialize the banner widget."""
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        self._health: CertificateHealth | None = None
        self._expanded = False

        self.add_css_class("card")
        self.set_margin_start(12)
        self.set_margin_end(12)
        self.set_margin_top(8)
        self.set_margin_bottom(4)

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the banner UI components."""
        # === COMPACT VIEW (always visible) ===
        self._compact_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._compact_row.set_margin_start(10)
        self._compact_row.set_margin_end(6)
        self._compact_row.set_margin_top(8)
        self._compact_row.set_margin_bottom(8)

        # Status icon
        self._status_icon = Gtk.Label(label="🔐")
        self._compact_row.append(self._status_icon)

        # Compact info: "John Doe • Expires in 45 days"
        self._compact_label = Gtk.Label(label=_("Certificate Status"))
        self._compact_label.set_hexpand(True)
        self._compact_label.set_xalign(0)
        self._compact_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        self._compact_row.append(self._compact_label)

        # Expand/collapse button
        self._expand_btn = Gtk.Button(icon_name="pan-down-symbolic")
        self._expand_btn.add_css_class("flat")
        self._expand_btn.set_tooltip_text(_("Show details"))
        self._expand_btn.connect("clicked", self._on_expand_clicked)
        self._compact_row.append(self._expand_btn)

        # Refresh button
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.add_css_class("flat")
        refresh_btn.set_tooltip_text(_("Refresh"))
        refresh_btn.connect("clicked", self._on_refresh_clicked)
        self._compact_row.append(refresh_btn)

        self.append(self._compact_row)

        # === EXPANDED VIEW (hidden by default) ===
        self._details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._details_box.set_margin_start(36)
        self._details_box.set_margin_end(12)
        self._details_box.set_margin_bottom(10)
        self._details_box.set_visible(False)

        # Issuer
        self._issuer_label = Gtk.Label(label="")
        self._issuer_label.set_xalign(0)
        self._issuer_label.add_css_class("dim-label")
        self._issuer_label.add_css_class("caption")
        self._details_box.append(self._issuer_label)

        # Expiry date
        self._expiry_label = Gtk.Label(label="")
        self._expiry_label.set_xalign(0)
        self._expiry_label.add_css_class("caption")
        self._details_box.append(self._expiry_label)

        # Progress bar row
        progress_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        progress_box.set_margin_top(4)

        self._progress_bar = Gtk.ProgressBar()
        self._progress_bar.set_hexpand(True)
        self._progress_bar.set_show_text(False)
        progress_box.append(self._progress_bar)

        self._progress_label = Gtk.Label(label="")
        self._progress_label.add_css_class("dim-label")
        self._progress_label.add_css_class("caption")
        progress_box.append(self._progress_label)

        self._details_box.append(progress_box)

        self.append(self._details_box)

        # No certificate message
        self._no_cert_label = Gtk.Label(label=_("No certificate loaded"))
        self._no_cert_label.add_css_class("dim-label")
        self._no_cert_label.set_visible(False)

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
        self._compact_label.set_label(_("No certificate loaded"))
        self._details_box.set_visible(False)
        self._expand_btn.set_visible(False)

        # Remove all status classes
        for level in HealthLevel:
            self.remove_css_class(f"cert-status-{level.value}")

    def _show_certificate(self, health: CertificateHealth) -> None:
        """Show certificate information."""
        self._expand_btn.set_visible(True)

        # Update icon based on health level
        self._status_icon.set_label(health.status_icon)

        # Compact label: "John Doe • Expires in 45 days"
        self._compact_label.set_label(f"{health.subject_cn}  •  {health.status_text}")

        # Details
        self._issuer_label.set_label(f"🏢 {_('Issued by')}: {health.issuer_cn}")

        # Format expiry date
        expiry_str = health.not_after.strftime("%Y-%m-%d")
        self._expiry_label.set_label(f"📅 {_('Valid until')}: {expiry_str}")

        # Update progress bar
        self._progress_bar.set_fraction(health.lifetime_progress)
        progress_pct = int(health.lifetime_progress * 100)
        self._progress_label.set_label(f"{progress_pct}% {_('used')}")

        # Update banner background color class
        for level in HealthLevel:
            self.remove_css_class(f"cert-status-{level.value}")
        self.add_css_class(health.css_class)

    def _on_expand_clicked(self, button: Gtk.Button) -> None:
        """Toggle expanded/collapsed state."""
        self._expanded = not self._expanded
        self._details_box.set_visible(self._expanded)

        if self._expanded:
            button.set_icon_name("pan-up-symbolic")
            button.set_tooltip_text(_("Hide details"))
        else:
            button.set_icon_name("pan-down-symbolic")
            button.set_tooltip_text(_("Show details"))

    def _on_refresh_clicked(self, button: Gtk.Button) -> None:
        """Handle refresh button click."""
        # Get main window and refresh
        window = self.get_root()
        if hasattr(window, "refresh_certificate_status"):
            window.refresh_certificate_status()

    def get_health(self) -> CertificateHealth | None:
        """Get current health data."""
        return self._health

    def is_expanded(self) -> bool:
        """Check if details are expanded."""
        return self._expanded

"""
cert_health_banner.py - Certificate health status banner widget

Author: Homero Thompson del Lago del Terror

GTK4 widget that displays certificate health status with
color-coded expiry warnings. Compact by default, expandable for details.
Includes CSS animations and toast notifications.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from pdfsigner.core.certificate.health_status import CertificateHealth, HealthLevel
from pdfsigner.i18n import _


class CertHealthBanner(Gtk.Box):
    """
    Certificate health status banner widget.

    Compact by default showing only icon + name + status.
    Click to expand for full details.
    Shows toast notifications for warnings/alerts.
    """

    def __init__(self):
        """Initialize the banner widget."""
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        self._health: CertificateHealth | None = None
        self._expanded = False
        self._toast_shown = False

        # Base CSS class
        self.add_css_class("card")
        self.add_css_class("cert-health-banner")
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
        self._status_icon.set_accessible_name(_("Certificate status icon"))
        self._compact_row.append(self._status_icon)

        # Compact info: "John Doe • Expires in 45 days"
        self._compact_label = Gtk.Label(label=_("Certificate Status"))
        self._compact_label.set_hexpand(True)
        self._compact_label.set_xalign(0)
        self._compact_label.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        self._compact_label.set_accessible_name(_("Certificate information"))
        self._compact_row.append(self._compact_label)

        # Expand/collapse button
        self._expand_btn = Gtk.Button(icon_name="pan-down-symbolic")
        self._expand_btn.add_css_class("flat")
        self._expand_btn.set_tooltip_text(_("Show details"))
        self._expand_btn.set_accessible_name(_("Show details"))
        self._expand_btn.set_accessible_description(_("Show certificate details"))
        self._expand_btn.connect("clicked", self._on_expand_clicked)
        self._compact_row.append(self._expand_btn)

        # Refresh button
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.add_css_class("flat")
        refresh_btn.set_tooltip_text(_("Refresh"))
        refresh_btn.set_accessible_name(_("Refresh"))
        refresh_btn.set_accessible_description(_("Refresh certificate status"))
        refresh_btn.connect("clicked", self._on_refresh_clicked)
        self._compact_row.append(refresh_btn)

        self.append(self._compact_row)

        # === EXPANDED VIEW (hidden by default) ===
        self._details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._details_box.add_css_class("cert-details-box")
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
        self._progress_bar.set_accessible_name(_("Certificate lifetime"))
        self._progress_bar.set_accessible_description(_("Certificate validity progress"))
        progress_box.append(self._progress_bar)

        self._progress_label = Gtk.Label(label="")
        self._progress_label.add_css_class("dim-label")
        self._progress_label.add_css_class("caption")
        progress_box.append(self._progress_label)

        self._details_box.append(progress_box)

        self.append(self._details_box)

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

        # Show toast for warnings (only once per session)
        if not self._toast_shown:
            self._show_status_toast(health)
            self._toast_shown = True

    def _show_no_certificate(self) -> None:
        """Show the 'no certificate' state."""
        self._status_icon.set_label("🔐")
        self._compact_label.set_label(_("No certificate loaded"))
        self._details_box.set_visible(False)
        self._expand_btn.set_visible(False)

        # Remove all status classes
        self._clear_status_classes()

    def _show_certificate(self, health: CertificateHealth) -> None:
        """Show certificate information."""
        self._expand_btn.set_visible(True)

        # Add fade-in animation
        self.add_css_class("cert-fade-in")
        GLib.timeout_add(500, self._remove_fade_class)

        # Update icon based on health level
        self._status_icon.set_label(health.status_icon)

        # Add pulse animation for critical states
        if health.health_level in (HealthLevel.CRITICAL, HealthLevel.EXPIRED):
            self._status_icon.add_css_class("cert-icon-pulse")
        else:
            self._status_icon.remove_css_class("cert-icon-pulse")

        # Compact label: "John Doe • Expires in 45 days"
        self._compact_label.set_label(f"{health.subject_cn}  •  {health.status_text}")

        # Add text color class
        self._clear_text_classes()
        self._compact_label.add_css_class(f"cert-text-{health.health_level.value}")

        # Details
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

        # Update banner background color class
        self._clear_status_classes()
        self.add_css_class(health.css_class)

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

    def _clear_status_classes(self) -> None:
        """Remove all status background classes."""
        for level in HealthLevel:
            self.remove_css_class(f"cert-status-{level.value}")

    def _clear_text_classes(self) -> None:
        """Remove all text color classes."""
        for level in HealthLevel:
            self._compact_label.remove_css_class(f"cert-text-{level.value}")

    def _clear_progress_classes(self) -> None:
        """Remove all progress bar color classes."""
        for level in HealthLevel:
            self._progress_bar.remove_css_class(f"cert-progress-{level.value}")

    def _remove_fade_class(self) -> bool:
        """Remove fade-in class after animation."""
        self.remove_css_class("cert-fade-in")
        return False  # Don't repeat

    def _on_expand_clicked(self, button: Gtk.Button) -> None:
        """Toggle expanded/collapsed state."""
        self._expanded = not self._expanded
        self._details_box.set_visible(self._expanded)

        if self._expanded:
            button.set_icon_name("pan-up-symbolic")
            button.set_tooltip_text(_("Hide details"))
            self.add_css_class("expanded")
            self._details_box.add_css_class("expanded")
            self._details_box.remove_css_class("collapsed")
        else:
            button.set_icon_name("pan-down-symbolic")
            button.set_tooltip_text(_("Show details"))
            self.remove_css_class("expanded")
            self._details_box.remove_css_class("expanded")
            self._details_box.add_css_class("collapsed")

    def _on_refresh_clicked(self, button: Gtk.Button) -> None:
        """Handle refresh button click."""
        # Reset toast shown flag to allow new toast
        self._toast_shown = False

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

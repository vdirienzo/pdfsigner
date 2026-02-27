"""
certificate_details_dialog.py - Certificate details viewer dialog

Author: Homero Thompson del Lago del Terror

Displays detailed X.509 certificate information in a professional,
multi-tab interface using libadwaita components.

Tab builders are in certificate_tab_builders.py to keep this file focused
on dialog orchestration.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk
from loguru import logger

from pdfsigner.core.certificate import X509Details, X509Parser
from pdfsigner.gui.dialogs.certificate_tab_builders import (
    create_details_tab,
    create_extensions_tab,
    create_general_tab,
)
from pdfsigner.i18n import _


class CertificateDetailsDialog(Adw.Window):
    """
    Certificate details viewer dialog.

    Displays comprehensive X.509 certificate information organized
    in tabs: General, Details, Extensions, and Thumbprints.
    """

    def __init__(
        self,
        cert_bytes: bytes | None = None,
        cert_details: X509Details | None = None,
        **kwargs,
    ):
        """
        Initialize the certificate details dialog.

        Args:
            cert_bytes: DER-encoded certificate bytes (will be parsed)
            cert_details: Pre-parsed X509Details object
            **kwargs: Additional arguments passed to Adw.Window

        Note: Either cert_bytes or cert_details must be provided.
        """
        super().__init__(**kwargs)

        if cert_details is None and cert_bytes is None:
            raise ValueError("Either cert_bytes or cert_details must be provided")

        if cert_details is None:
            if cert_bytes is None:
                raise RuntimeError("cert_bytes must not be None when cert_details is not provided")
            try:
                self._details = X509Parser.parse(cert_bytes)
            except Exception as e:
                logger.error(f"Failed to parse certificate: {e}")
                raise
        else:
            self._details = cert_details

        self.set_title(_("Certificate Details"))
        self.set_default_size(500, 450)
        self.set_modal(True)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        view_stack = Adw.ViewStack()

        # Tabs: 3 delegated to tab builders, thumbprints stays here (small)
        view_stack.add_titled(create_general_tab(self), "general", _("General"))
        view_stack.add_titled(create_details_tab(self), "details", _("Details"))
        view_stack.add_titled(create_extensions_tab(self), "extensions", _("Extensions"))
        view_stack.add_titled(self._create_thumbprints_tab(), "thumbprints", _("Thumbprints"))

        switcher = Adw.ViewSwitcher()
        switcher.set_stack(view_stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        view_stack.set_vexpand(True)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(view_stack)

        toolbar.set_content(content_box)
        self.set_content(toolbar)

    def _create_thumbprints_tab(self) -> Gtk.Widget:
        """Create the Thumbprints tab."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        thumbprints_group = Adw.PreferencesGroup()
        thumbprints_group.set_title(_("Certificate Thumbprints"))
        thumbprints_group.set_description(
            _("Thumbprints are cryptographic hashes that uniquely identify this certificate")
        )

        sha256_row = self._create_copyable_row(
            "SHA-256", self._format_thumbprint(self._details.thumbprint_sha256)
        )
        thumbprints_group.add(sha256_row)

        sha1_row = self._create_copyable_row(
            "SHA-1", self._format_thumbprint(self._details.thumbprint_sha1)
        )
        thumbprints_group.add(sha1_row)

        content.append(thumbprints_group)

        scroll.set_child(content)
        return scroll

    def _create_copyable_row(self, title: str, value: str) -> Adw.ActionRow:
        """Create a row with a copy button."""
        row = Adw.ActionRow()
        row.set_title(title)
        row.set_subtitle(value)
        row.add_css_class("property")

        copy_btn = Gtk.Button()
        copy_btn.set_icon_name("edit-copy-symbolic")
        copy_btn.add_css_class("flat")
        copy_btn.add_css_class("circular")
        copy_btn.set_valign(Gtk.Align.CENTER)
        copy_btn.set_tooltip_text(_("Copy to clipboard"))
        copy_btn.connect("clicked", lambda _: self._copy_to_clipboard(value))
        row.add_suffix(copy_btn)

        return row

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard."""
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(text)

        logger.debug(f"Copied to clipboard: {text[:50]}...")

    def _format_datetime(self, dt) -> str:
        """Format datetime for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def _format_thumbprint(self, thumbprint: str) -> str:
        """Format thumbprint with colons every 2 characters."""
        return ":".join(thumbprint[i : i + 2] for i in range(0, len(thumbprint), 2))

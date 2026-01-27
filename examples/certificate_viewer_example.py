#!/usr/bin/env python3
"""
certificate_viewer_example.py - Example of using the Certificate Details Dialog

Author: Homero Thompson del Lago del Terror

This example demonstrates how to use the X509Parser and CertificateDetailsDialog
to display detailed certificate information in a GTK4/Adwaita window.
"""

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.core.certificate import X509Parser
from pdfsigner.gui.dialogs import CertificateDetailsDialog


class ExampleWindow(Adw.ApplicationWindow):
    """Example window with certificate viewer."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("Certificate Viewer Example")
        self.set_default_size(400, 300)

        # Header bar
        header = Adw.HeaderBar()

        # Main layout
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Content
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        content.set_margin_top(40)
        content.set_margin_bottom(40)
        content.set_margin_start(40)
        content.set_margin_end(40)
        content.set_valign(Gtk.Align.CENTER)

        label = Gtk.Label(
            label="Select a certificate file (DER or PEM format)\nto view its details"
        )
        label.add_css_class("title-2")
        content.append(label)

        # Button to open file
        open_btn = Gtk.Button(label="Open Certificate")
        open_btn.add_css_class("pill")
        open_btn.add_css_class("suggested-action")
        open_btn.set_halign(Gtk.Align.CENTER)
        open_btn.connect("clicked", self._on_open_clicked)
        content.append(open_btn)

        toolbar.set_content(content)
        self.set_content(toolbar)

    def _on_open_clicked(self, _button):
        """Handle open button click."""
        dialog = Gtk.FileDialog()

        # Create filter for certificate files
        cert_filter = Gtk.FileFilter()
        cert_filter.set_name("Certificate files")
        cert_filter.add_pattern("*.crt")
        cert_filter.add_pattern("*.cer")
        cert_filter.add_pattern("*.der")
        cert_filter.add_pattern("*.pem")

        all_filter = Gtk.FileFilter()
        all_filter.set_name("All files")
        all_filter.add_pattern("*")

        filter_list = Gtk.ListStore.new([Gtk.FileFilter])
        filter_list.append([cert_filter])
        filter_list.append([all_filter])

        dialog.set_default_filter(cert_filter)

        dialog.open(self, None, self._on_file_selected)

    def _on_file_selected(self, dialog, result):
        """Handle file selection."""
        try:
            file = dialog.open_finish(result)
            if file is None:
                return

            # Read certificate file
            path = file.get_path()
            with open(path, "rb") as f:
                cert_bytes = f.read()

            # Try to parse as DER first, then PEM
            try:
                details = X509Parser.parse(cert_bytes)
            except ValueError:
                # Try PEM format
                from cryptography.hazmat.primitives import serialization

                cert = serialization.load_pem_x509_certificate(cert_bytes)
                cert_bytes = cert.public_bytes(serialization.Encoding.DER)
                details = X509Parser.parse(cert_bytes)

            # Show certificate details dialog
            cert_dialog = CertificateDetailsDialog(cert_details=details)
            cert_dialog.set_transient_for(self)
            cert_dialog.present()

        except Exception as e:
            # Show error toast
            toast = Adw.Toast.new(f"Error loading certificate: {e}")
            toast.set_timeout(3)

            # Get toast overlay from content
            content = self.get_content()
            if isinstance(content, Adw.ToastOverlay):
                content.add_toast(toast)


class ExampleApp(Adw.Application):
    """Example application."""

    def __init__(self):
        super().__init__(application_id="com.example.certificateviewer")
        self.connect("activate", self._on_activate)

    def _on_activate(self, _app):
        """Handle app activation."""
        win = ExampleWindow(application=self)
        win.present()


def main():
    """Run the example application."""
    app = ExampleApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())

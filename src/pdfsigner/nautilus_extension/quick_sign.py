"""
quick_sign.py - Quick signing mode for Nautilus integration

Author: Homero Thompson del Lago del Terror

Signs PDFs directly with preconfigured options, only asking for PIN.
Uses settings from ~/.config/pdfsigner/config.toml
"""

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance


class QuickSignApp(Adw.Application):
    """Quick sign application - shows PIN dialog and signs."""

    def __init__(self, pdf_paths: list[str]):
        super().__init__(
            application_id="com.pdfsigner.quicksign",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.pdf_paths = [Path(p) for p in pdf_paths]
        self.settings = get_settings()
        self.window = None

    def do_activate(self) -> None:
        """Show PIN dialog on activation."""
        self.window = Adw.Window(application=self)
        self.window.set_default_size(350, 200)
        self.window.set_title("PDFSigner - Quick Sign")

        # Main container
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        # Header
        header = Gtk.Label(label="Enter PIN to sign")
        header.add_css_class("title-2")
        box.append(header)

        # File count info
        count = len(self.pdf_paths)
        info_text = f"Signing {count} file(s)" if count > 1 else f"Signing: {self.pdf_paths[0].name}"
        info = Gtk.Label(label=info_text)
        info.add_css_class("dim-label")
        box.append(info)

        # PIN entry
        self.pin_entry = Gtk.PasswordEntry()
        self.pin_entry.set_show_peek_icon(True)
        self.pin_entry.set_placeholder_text("Token PIN")
        self.pin_entry.connect("activate", self._on_sign_clicked)
        box.append(self.pin_entry)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        button_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _: self.quit())
        button_box.append(cancel_btn)

        sign_btn = Gtk.Button(label="Sign")
        sign_btn.add_css_class("suggested-action")
        sign_btn.connect("clicked", self._on_sign_clicked)
        button_box.append(sign_btn)

        box.append(button_box)

        self.window.set_content(box)
        self.window.present()

        # Focus PIN entry
        self.pin_entry.grab_focus()

    def _on_sign_clicked(self, _widget) -> None:
        """Handle sign button click."""
        pin = self.pin_entry.get_text()
        if not pin:
            self._show_error("Please enter your PIN")
            return

        # Disable UI during signing
        self.pin_entry.set_sensitive(False)

        # Run signing in background
        GLib.idle_add(self._do_sign, pin)

    def _do_sign(self, pin: str) -> bool:
        """Perform the actual signing."""
        try:
            from loguru import logger

            from pdfsigner.core.signer.batch_manager import BatchManager
            from pdfsigner.core.signer.lta_handler import create_lta_handler_from_settings
            from pdfsigner.core.token.cert_selector import CertificateSelector
            from pdfsigner.core.token.nss_handler import NSSHandler

            # Build appearance from settings
            appearance = self._build_appearance()

            # Connect to token
            nss_handler = NSSHandler()
            nss_handler.initialize()

            tokens = nss_handler.get_available_tokens()
            if not tokens:
                self._show_error("USB token not detected")
                return False

            nss_handler.connect_token()

            # Authenticate
            try:
                nss_handler.authenticate(pin)
            except Exception as e:
                self._show_error(f"Authentication error: {e}")
                nss_handler.close()
                return False

            # Get certificate
            cert_selector = CertificateSelector(nss_handler)
            try:
                cert = cert_selector.get_default_certificate()
                logger.info(f"Using certificate: {cert.display_name}")
            except Exception as e:
                self._show_error(f"No valid certificate: {e}")
                nss_handler.close()
                return False

            # Setup LTA handler
            try:
                lta_handler = create_lta_handler_from_settings()
            except Exception as e:
                logger.warning(f"TSA not available: {e}")
                lta_handler = None

            # Sign files
            batch_manager = BatchManager(nss_handler, lta_handler)
            result = batch_manager.sign_batch(
                pdf_files=self.pdf_paths,
                appearance=appearance,
                cert_id=cert.info.pkcs11_id,
            )

            # Cleanup
            nss_handler.close()

            # Show result
            if result.all_successful:
                self._show_success(f"✓ {result.successful} file(s) signed successfully")
            else:
                self._show_error(f"Signed: {result.successful}, Failed: {result.failed}")

        except Exception as e:
            self._show_error(f"Unexpected error: {e}")

        return False

    def _build_appearance(self) -> SignatureAppearance:
        """Build SignatureAppearance from settings."""
        settings = self.settings

        # Map position string to enum
        position_map = {
            "bottom_right": PositionPreference.BOTTOM_RIGHT,
            "bottom_left": PositionPreference.BOTTOM_LEFT,
            "top_right": PositionPreference.TOP_RIGHT,
            "top_left": PositionPreference.TOP_LEFT,
            "bottom_center": PositionPreference.BOTTOM_CENTER,
            "top_center": PositionPreference.TOP_CENTER,
        }
        position = position_map.get(
            settings.nautilus_stamp_position,
            PositionPreference.BOTTOM_RIGHT,
        )

        return SignatureAppearance(
            visible=settings.nautilus_visible_stamp,
            page=settings.nautilus_stamp_page,
            position_preference=position,
            show_name=settings.nautilus_show_name,
            show_date=settings.nautilus_show_date,
        )

    def _show_error(self, message: str) -> None:
        """Show error dialog."""
        dialog = Adw.MessageDialog(
            transient_for=self.window,
            heading="Signing Error",
            body=message,
        )
        dialog.add_response("ok", "OK")
        dialog.connect("response", lambda d, r: self.quit())
        dialog.present()

    def _show_success(self, message: str) -> None:
        """Show success and quit."""
        dialog = Adw.MessageDialog(
            transient_for=self.window,
            heading="Success",
            body=message,
        )
        dialog.add_response("ok", "OK")
        dialog.connect("response", lambda d, r: self.quit())
        dialog.present()


def run_quick_sign(pdf_paths: list[str]) -> int:
    """Entry point for quick sign mode."""
    if not pdf_paths:
        print("No PDF files specified")
        return 1

    app = QuickSignApp(pdf_paths)
    return app.run([])


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: pdfsigner-quick-sign file1.pdf [file2.pdf ...]")
        return 1

    return run_quick_sign(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())

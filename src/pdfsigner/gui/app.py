"""
app.py - Main GTK4 Application

Author: Homero Thompson del Lago del Terror

Entry point for the standalone GUI application.
"""

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk

from pdfsigner.gui.main_window import MainWindow

# Path to the application icon
ICON_PATH = Path(__file__).parent.parent / "ui" / "icon" / "icon.png"
APP_ID = "com.pdfsigner.app"


class PDFSignerApp(Adw.Application):
    """
    Main PDFSigner application.

    Uses libadwaita for a modern appearance
    consistent with GNOME.
    """

    def __init__(self):
        """Initializes the application."""
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.HANDLES_OPEN,
        )

        self.window = None
        self._nss_configured: bool | None = None  # None = not checked yet

        # Actions
        self.create_actions()

    def create_actions(self) -> None:
        """Creates the application actions."""
        # Action: Open files
        action_open = Gio.SimpleAction.new("open", None)
        action_open.connect("activate", self.on_open_action)
        self.add_action(action_open)

        # Action: Preferences
        action_preferences = Gio.SimpleAction.new("preferences", None)
        action_preferences.connect("activate", self.on_preferences_action)
        self.add_action(action_preferences)

        # Action: About
        action_about = Gio.SimpleAction.new("about", None)
        action_about.connect("activate", self.on_about_action)
        self.add_action(action_about)

        # Action: Quit
        action_quit = Gio.SimpleAction.new("quit", None)
        action_quit.connect("activate", self.on_quit_action)
        self.add_action(action_quit)

        # Keyboard shortcuts
        self.set_accels_for_action("app.open", ["<Control>o"])
        self.set_accels_for_action("app.preferences", ["<Control>comma"])
        self.set_accels_for_action("app.quit", ["<Control>q"])

    def do_startup(self) -> None:
        """Initialization on application startup."""
        Adw.Application.do_startup(self)

    def do_activate(self) -> None:
        """Activates the application."""
        # Check NSS configuration on first activation
        if self._nss_configured is None:
            if not self._check_nss():
                self._show_nss_wizard()
                return

        if not self.window:
            self.window = MainWindow(application=self)
            self.window.set_icon_name(APP_ID)

        self.window.present()

    def _check_nss(self) -> bool:
        """
        Check if NSS database is configured.

        Returns:
            True if NSS is configured, False otherwise
        """
        from loguru import logger

        from pdfsigner.core.setup import NSSChecker

        checker = NSSChecker()
        self._nss_configured = checker.is_configured()

        if self._nss_configured:
            logger.debug("NSS database is configured")
        else:
            logger.info("NSS database not configured, showing setup wizard")

        return self._nss_configured

    def _show_nss_wizard(self) -> None:
        """Show NSS setup wizard for first-time configuration."""
        from pdfsigner.ui.dialogs.nss_wizard import NSSSetupWizard

        wizard = NSSSetupWizard(application=self)
        wizard.present()

    def do_open(self, files: list, n_files: int, hint: str) -> None:
        """Handles files opened from the system."""
        self.do_activate()

        paths = [f.get_path() for f in files if f.get_path()]
        if paths:
            self.window.add_files(paths)

    def on_open_action(self, action, param) -> None:
        """Action: Open files."""
        if self.window:
            self.window.show_file_chooser()

    def on_preferences_action(self, action, param) -> None:
        """Action: Show preferences."""
        if self.window:
            self.window.show_settings()

    def on_about_action(self, action, param) -> None:
        """Action: Show About dialog."""
        about = Adw.AboutWindow(
            transient_for=self.window,
            application_name="PDFSigner",
            application_icon=APP_ID,
            developer_name="Homero Thompson del Lago del Terror",
            version="0.1.0",
            comments="Digital signature of PDFs with SafeNet 5110 USB token",
            website="https://github.com/vdirienzo/pdfsigner",
            license_type=Gtk.License.MIT_X11,
            developers=["Homero Thompson del Lago del Terror"],
        )
        about.present()

    def on_quit_action(self, action, param) -> None:
        """Action: Quit."""
        self.quit()


def run_gui() -> int:
    """Entry point for the GUI."""
    Adw.init()
    app = PDFSignerApp()
    return app.run(sys.argv)

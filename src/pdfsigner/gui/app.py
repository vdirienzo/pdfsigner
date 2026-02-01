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
from gi.repository import Adw, Gdk, Gio, Gtk  # noqa: F401

from pdfsigner.gui.main_window import MainWindow
from pdfsigner.i18n import _

# Path to custom CSS
CSS_PATH = Path(__file__).parent / "styles.css"

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

        # Keyboard shortcuts - Application actions
        self.set_accels_for_action("app.open", ["<Control>o"])
        self.set_accels_for_action("app.preferences", ["<Control>comma"])
        self.set_accels_for_action("app.quit", ["<Control>q"])
        self.set_accels_for_action("app.about", ["F1"])

        # Keyboard shortcuts - Window actions
        self.set_accels_for_action("win.sign", ["<Control>s"])
        self.set_accels_for_action("win.validate", ["<Control><Shift>v"])
        self.set_accels_for_action("win.clear", ["<Control>l", "Delete"])

    def do_startup(self) -> None:
        """Initialization on application startup."""
        Adw.Application.do_startup(self)

        # Load custom CSS
        self._load_css()

        # Load and apply appearance settings
        self._apply_saved_appearance()

    def _load_css(self) -> None:
        """Load custom CSS styles."""
        if not CSS_PATH.exists():
            return

        css_provider = Gtk.CssProvider()
        css_provider.load_from_path(str(CSS_PATH))

        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

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

    def _apply_saved_appearance(self) -> None:
        """Load and apply saved appearance settings on startup."""
        from loguru import logger

        from pdfsigner.config.settings import get_settings
        from pdfsigner.gui.settings_pages import apply_theme
        from pdfsigner.i18n import set_language

        try:
            settings = get_settings()

            # Apply theme
            apply_theme(settings.theme)
            logger.debug(f"Applied theme: {settings.theme}")

            # Apply language (if set)
            if settings.language:
                set_language(settings.language)
                logger.debug(f"Applied language: {settings.language}")

        except Exception as e:
            logger.warning(f"Could not apply appearance settings: {e}")

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
            version="0.6.0",
            comments=_("Digital signature of PDFs with USB cryptographic tokens"),
            website="https://github.com/vdirienzo/pdfsigner",
            license_type=Gtk.License.MIT_X11,
            developers=["Homero Thompson del Lago del Terror"],
        )
        about.present()

    def on_quit_action(self, action, param) -> None:
        """Action: Quit."""
        self.quit()


def setup_logging() -> None:
    """Configure logging for GUI from settings."""
    from loguru import logger

    from pdfsigner.config.settings import get_settings

    settings = get_settings()
    logger.remove()
    logger.add(sys.stderr, level=settings.log_level)


def run_gui() -> int:
    """Entry point for the GUI."""
    setup_logging()
    Adw.init()
    app = PDFSignerApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(run_gui())

"""
nss_wizard.py - NSS Setup Wizard Dialog

Author: Homero Thompson del Lago del Terror

First-run wizard for automatic NSS database configuration.
Shown when NSS is not configured on application startup.
"""

from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk
from loguru import logger

from pdfsigner.core.setup import NSSChecker, NSSSetup, SetupResult
from pdfsigner.i18n import _


class NSSSetupWizard(Adw.Window):
    """
    First-run wizard for NSS configuration.

    Shows a multi-page wizard that:
    1. Welcomes user and explains why NSS is needed
    2. Shows progress while creating NSS database
    3. Shows success or error with appropriate actions

    Attributes:
        app: Parent application instance
        checker: NSS configuration checker
        setup: NSS setup handler
    """

    def __init__(self, application: Adw.Application):
        """
        Initialize NSS setup wizard.

        Args:
            application: Parent Adw.Application instance
        """
        super().__init__(
            application=application,
            title=_("PDFSigner Setup"),
            default_width=500,
            default_height=400,
            modal=True,
        )

        self.app = application
        self.checker = NSSChecker()
        self.setup = NSSSetup()
        self._setup_running = False

        self._build_ui()

        # Connect close request to handle cancel
        self.connect("close-request", self._on_close_request)

        logger.info("NSS Setup Wizard initialized")

    def _build_ui(self) -> None:
        """Build wizard UI with stack for pages."""
        # Main box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(main_box)

        # Header bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        header.set_show_start_title_buttons(False)
        main_box.append(header)

        # Stack for pages
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT)
        self.stack.set_vexpand(True)
        main_box.append(self.stack)

        # Build pages
        self._build_welcome_page()
        self._build_progress_page()
        self._build_success_page()
        self._build_error_page()

        # Start on welcome page
        self.stack.set_visible_child_name("welcome")

    def _build_welcome_page(self) -> None:
        """Build welcome/explanation page."""
        page = Adw.StatusPage()
        page.set_icon_name("dialog-information-symbolic")
        page.set_title(_("Initial Setup Required"))
        page.set_description(
            _(
                "PDFSigner needs to create a security database to communicate "
                "with your USB token.\n\n"
                "This is a one-time setup that takes a few seconds. "
                "Your token will be detected automatically when connected."
            )
        )

        # Buttons
        button_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
        )

        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", self._on_cancel_clicked)
        button_box.append(cancel_btn)

        setup_btn = Gtk.Button(label=_("Set Up"))
        setup_btn.add_css_class("suggested-action")
        setup_btn.connect("clicked", self._on_setup_clicked)
        button_box.append(setup_btn)

        page.set_child(button_box)
        self.stack.add_named(page, "welcome")

    def _build_progress_page(self) -> None:
        """Build progress/spinner page."""
        page = Adw.StatusPage()
        page.set_title(_("Creating Security Database..."))
        page.set_description(_("Please wait while we configure NSS."))

        # Spinner
        spinner = Gtk.Spinner()
        spinner.set_size_request(48, 48)
        spinner.start()
        page.set_child(spinner)

        self.stack.add_named(page, "progress")

    def _build_success_page(self) -> None:
        """Build success page."""
        page = Adw.StatusPage()
        page.set_icon_name("emblem-ok-symbolic")
        page.set_title(_("Setup Complete"))
        page.set_description(
            _(
                "Security database created successfully!\n\n"
                "Connect your USB token and PDFSigner will detect it automatically."
            )
        )

        # Start button
        start_btn = Gtk.Button(label=_("Start PDFSigner"))
        start_btn.add_css_class("suggested-action")
        start_btn.set_halign(Gtk.Align.CENTER)
        start_btn.connect("clicked", self._on_start_clicked)
        page.set_child(start_btn)

        self.stack.add_named(page, "success")

    def _build_error_page(self) -> None:
        """Build error page with retry option."""
        page = Adw.StatusPage()
        page.set_icon_name("dialog-error-symbolic")
        page.set_title(_("Setup Failed"))

        # Error message label (will be updated)
        self.error_label = Gtk.Label()
        self.error_label.set_wrap(True)
        self.error_label.set_max_width_chars(50)
        self.error_label.add_css_class("dim-label")

        # Buttons
        button_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            margin_top=12,
        )

        quit_btn = Gtk.Button(label=_("Quit"))
        quit_btn.connect("clicked", self._on_quit_clicked)
        button_box.append(quit_btn)

        retry_btn = Gtk.Button(label=_("Retry"))
        retry_btn.add_css_class("suggested-action")
        retry_btn.connect("clicked", self._on_retry_clicked)
        button_box.append(retry_btn)

        # Container for label and buttons
        content_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
        )
        content_box.append(self.error_label)
        content_box.append(button_box)

        page.set_child(content_box)
        self.stack.add_named(page, "error")

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handle cancel button click."""
        logger.info("User cancelled NSS setup")
        self.close()
        self.app.quit()

    def _on_setup_clicked(self, button: Gtk.Button) -> None:
        """Handle setup button click - start NSS creation."""
        self._start_setup()

    def _on_start_clicked(self, button: Gtk.Button) -> None:
        """Handle start button click - launch main app."""
        logger.info("NSS setup complete, launching main application")
        self.close()
        # Mark as configured and activate app
        self.app._nss_configured = True
        self.app.activate()

    def _on_quit_clicked(self, button: Gtk.Button) -> None:
        """Handle quit button click."""
        logger.info("User quit after setup failure")
        self.close()
        self.app.quit()

    def _on_retry_clicked(self, button: Gtk.Button) -> None:
        """Handle retry button click."""
        logger.info("User retrying NSS setup")
        self._start_setup()

    def _on_close_request(self, window: Adw.Window) -> bool:
        """Handle window close request."""
        if self._setup_running:
            # Don't allow closing during setup
            return True  # Block close
        return False  # Allow close

    def _start_setup(self) -> None:
        """Start NSS setup in background thread."""
        self._setup_running = True
        self.stack.set_visible_child_name("progress")

        # Run setup in background thread
        Thread(target=self._run_setup, daemon=True).start()

    def _run_setup(self) -> None:
        """Background thread: run certutil to create NSS database."""
        logger.info("Starting NSS database creation")
        result = self.setup.create_database()

        # Update UI on main thread
        GLib.idle_add(self._on_setup_complete, result)

    def _on_setup_complete(self, result: SetupResult) -> None:
        """Handle setup completion on main thread."""
        self._setup_running = False

        if result.success:
            logger.info("NSS setup succeeded")
            self.stack.set_visible_child_name("success")
        else:
            logger.error(f"NSS setup failed: {result.message}")
            self._show_error(result)

        return False  # Remove from idle

    def _show_error(self, result: SetupResult) -> None:
        """Show error page with appropriate message."""
        self.error_label.set_text(result.message)

        # Update page title based on error type
        error_page = self.stack.get_child_by_name("error")
        if result.error_type == "not_found":
            error_page.set_description(_("NSS tools are not installed on your system."))
        elif result.error_type == "permission":
            error_page.set_description(
                _("Could not create the security database due to permissions.")
            )
        elif result.error_type == "timeout":
            error_page.set_description(_("The setup process timed out. Please try again."))
        else:
            error_page.set_description(_("An unexpected error occurred during setup."))

        self.stack.set_visible_child_name("error")

"""
main_window.py - Main PDFSigner Window

Author: Homero Thompson del Lago del Terror

Main window with file list, drag & drop,
and signature/validation actions.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from pdfsigner.gui.file_list_widget import FileListWidget
from pdfsigner.gui.settings_dialog import SettingsDialog
from pdfsigner.gui.signing_handler import SigningHandler
from pdfsigner.i18n import _


class MainWindow(Adw.ApplicationWindow):
    """
    Main PDFSigner window.

    Contains:
    - Drag & drop area for files
    - List of files to process
    - Action buttons (sign, validate, clear)
    - Menu with settings
    """

    def __init__(self, **kwargs):
        """Initializes the window."""
        super().__init__(**kwargs)

        self.set_title(_("PDFSigner"))
        self.set_default_size(700, 500)

        self.signing_handler = SigningHandler(self)
        self.validation_handler = self._create_validation_handler()

        self._setup_ui()
        self._setup_drag_drop()

    def _setup_ui(self) -> None:
        """Configures the user interface."""
        # Header bar
        header = Adw.HeaderBar()

        # Main menu
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(self._create_menu())
        header.pack_end(menu_button)

        # Quick settings button
        settings_button = Gtk.Button(icon_name="emblem-system-symbolic")
        settings_button.set_tooltip_text(_("Settings"))
        settings_button.connect("clicked", lambda b: self.show_settings())
        header.pack_end(settings_button)

        # Add files button
        add_button = Gtk.Button(icon_name="list-add-symbolic")
        add_button.set_tooltip_text(_("Add files"))
        add_button.connect("clicked", lambda b: self.show_file_chooser())
        header.pack_start(add_button)

        # Toolbar box
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Central area
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # File list widget
        self.file_list = FileListWidget()
        self.file_list.set_vexpand(True)
        content_box.append(self.file_list)

        # Bottom action bar
        action_bar = self._create_action_bar()
        content_box.append(action_bar)

        toolbar.set_content(content_box)

        # Wrap in ToastOverlay for notifications
        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(toolbar)
        self.set_content(self.toast_overlay)

    def _create_menu(self) -> Gio.Menu:
        """Creates the main menu."""
        menu = Gio.Menu()

        menu.append(_("Open files..."), "app.open")
        menu.append(_("Preferences"), "app.preferences")

        section = Gio.Menu()
        section.append(_("About"), "app.about")
        section.append(_("Quit"), "app.quit")
        menu.append_section(None, section)

        return menu

    def _create_action_bar(self) -> Gtk.Box:
        """Creates the bottom action bar."""
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        bar.set_margin_top(12)
        bar.set_margin_bottom(12)
        bar.set_margin_start(12)
        bar.set_margin_end(12)

        # File info
        self.info_label = Gtk.Label(label=_("Drag PDF files here"))
        self.info_label.set_hexpand(True)
        self.info_label.set_xalign(0)
        self.info_label.add_css_class("dim-label")
        bar.append(self.info_label)

        # Clear button
        clear_button = Gtk.Button(label=_("Clear"))
        clear_button.connect("clicked", self._on_clear_clicked)
        bar.append(clear_button)

        # Validate button
        validate_button = Gtk.Button(label=_("Validate"))
        validate_button.add_css_class("suggested-action")
        validate_button.connect("clicked", self._on_validate_clicked)
        bar.append(validate_button)

        # Sign button
        self.sign_button = Gtk.Button(label=_("Sign"))
        self.sign_button.add_css_class("suggested-action")
        self.sign_button.connect("clicked", self._on_sign_clicked)
        bar.append(self.sign_button)

        return bar

    def _setup_drag_drop(self) -> None:
        """Configures drag & drop."""
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop_target.connect("drop", self._on_drop)
        self.add_controller(drop_target)

    def _on_drop(self, target, value, x, y) -> bool:
        """Handles dropped files."""
        if isinstance(value, Gdk.FileList):
            files = value.get_files()
            paths = [f.get_path() for f in files if f.get_path()]
            self.add_files(paths)
            return True
        return False

    def add_files(self, paths: list[str]) -> None:
        """
        Adds files to the list.

        Args:
            paths: List of file paths
        """
        added = 0
        for path_str in paths:
            path = Path(path_str)
            if path.is_file() and path.suffix.lower() == ".pdf":
                self.file_list.add_file(path)
                added += 1
            elif path.is_dir():
                for pdf in path.glob("*.pdf"):
                    self.file_list.add_file(pdf)
                    added += 1

        self._update_info_label()

        if added > 0:
            self.show_toast(_("{}file(s) added").format(added))

    def _update_info_label(self) -> None:
        """Updates the info label."""
        count = self.file_list.get_file_count()
        if count == 0:
            self.info_label.set_label(_("Drag PDF files here"))
        else:
            self.info_label.set_label(_("{}file(s) selected").format(count))

    def _on_clear_clicked(self, button: Gtk.Button) -> None:
        """Clears the file list."""
        self.file_list.clear()
        self._update_info_label()

    def _create_validation_handler(self):
        """Creates the validation handler (lazy import to avoid circular)."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        return ValidationHandler(self)

    def _on_validate_clicked(self, button: Gtk.Button) -> None:
        """Validates the selected files."""
        files = self.file_list.get_files()
        if not files:
            self.show_toast(_("No files to validate"))
            return

        self.validation_handler.validate_files(files)

    def _on_sign_clicked(self, button: Gtk.Button) -> None:
        """Signs the selected files."""
        files = self.file_list.get_files()
        if not files:
            self.show_toast(_("No files to sign"))
            return

        self.signing_handler.sign_files(files)

    def show_file_chooser(self) -> None:
        """Shows file selection dialog."""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select PDFs"))

        # PDF filter
        filter_pdf = Gtk.FileFilter()
        filter_pdf.set_name(_("PDF Files"))
        filter_pdf.add_mime_type("application/pdf")

        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_pdf)
        dialog.set_filters(filters)

        dialog.open_multiple(self, None, self._on_files_selected)

    def _on_files_selected(self, dialog, result) -> None:
        """Callback when files are selected."""
        try:
            files = dialog.open_multiple_finish(result)
            if files:
                paths = [f.get_path() for f in files if f.get_path()]
                self.add_files(paths)
        except GLib.Error:
            pass  # User cancelled

    def show_settings(self) -> None:
        """Shows the settings dialog."""
        dialog = SettingsDialog(transient_for=self)
        dialog.present()

    def show_toast(self, message: str) -> None:
        """Shows a toast notification."""
        toast = Adw.Toast(title=message)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

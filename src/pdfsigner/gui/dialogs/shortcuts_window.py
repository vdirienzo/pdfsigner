"""
shortcuts_window.py - Keyboard shortcuts help window

Author: Homero Thompson del Lago del Terror
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.i18n import _


class ShortcutsWindow(Gtk.ShortcutsWindow):
    """Window showing all keyboard shortcuts."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_modal(True)
        self._build_ui()

    def _build_ui(self):
        # Section: Application
        section = Gtk.ShortcutsSection(visible=True)
        section.set_property("section-name", "shortcuts")
        section.set_property("title", _("All Shortcuts"))

        # Group: Files
        files_group = Gtk.ShortcutsGroup(visible=True)
        files_group.set_property("title", _("Files"))

        shortcuts_files = [
            ("<Control>o", _("Open files")),
            ("<Control>s", _("Sign selected files")),
            ("<Control><Shift>v", _("Validate signatures")),
            ("<Control>l", _("Clear file list")),
            ("Delete", _("Clear file list")),
        ]

        for accel, title in shortcuts_files:
            shortcut = Gtk.ShortcutsShortcut(
                visible=True,
                accelerator=accel,
                title=title,
            )
            files_group.append(shortcut)

        section.append(files_group)

        # Group: Application
        app_group = Gtk.ShortcutsGroup(visible=True)
        app_group.set_property("title", _("Application"))

        shortcuts_app = [
            ("<Control>comma", _("Preferences")),
            ("<Control>question", _("Keyboard shortcuts")),
            ("F1", _("About")),
            ("<Control>q", _("Quit")),
        ]

        for accel, title in shortcuts_app:
            shortcut = Gtk.ShortcutsShortcut(
                visible=True,
                accelerator=accel,
                title=title,
            )
            app_group.append(shortcut)

        section.append(app_group)
        self.add(section)

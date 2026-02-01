"""
recent_files_popover.py - Recent files popover widget

Author: Homero Thompson del Lago del Terror

GTK4 popover that displays recent PDF files with click-to-open functionality.
"""

from datetime import datetime
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject, Gtk

from pdfsigner.core.recent import get_recent_files_manager
from pdfsigner.i18n import _


class RecentFilesPopover(Gtk.Popover):
    """
    Popover widget showing recent PDF files.

    Displays a list of recently opened/signed files with:
    - File name as title
    - Path and relative time as subtitle
    - Click to add file to list
    - Clear history button
    """

    __gsignals__ = {
        "file-selected": (GObject.SignalFlags.RUN_FIRST, None, (object,)),
    }

    def __init__(self):
        """Initialize the popover widget."""
        super().__init__()

        self.set_autohide(True)
        self.set_has_arrow(True)

        # Set size constraints
        self.set_size_request(350, -1)

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the popover UI."""
        # Main box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Scrolled window for file list
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_max_content_height(400)
        scrolled.set_propagate_natural_height(True)

        # Preferences group for recent files
        self._files_group = Adw.PreferencesGroup()
        self._files_group.set_title(_("Recent PDF Files"))
        self._files_group.set_margin_start(6)
        self._files_group.set_margin_end(6)
        self._files_group.set_margin_top(6)
        self._files_group.set_margin_bottom(6)

        scrolled.set_child(self._files_group)
        main_box.append(scrolled)

        # Bottom toolbar with clear button
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.set_margin_start(12)
        toolbar.set_margin_end(12)
        toolbar.set_margin_top(6)
        toolbar.set_margin_bottom(12)

        # Clear button
        clear_button = Gtk.Button(label=_("Clear History"))
        clear_button.add_css_class("destructive-action")
        clear_button.set_hexpand(True)
        clear_button.connect("clicked", self._on_clear_clicked)
        toolbar.append(clear_button)

        main_box.append(toolbar)

        self.set_child(main_box)

        # Connect to show signal to refresh list
        self.connect("show", self._on_popover_shown)

    def _on_popover_shown(self, popover) -> None:
        """Refresh file list when popover is shown."""
        self._refresh_file_list()

    def _refresh_file_list(self) -> None:
        """Refresh the list of recent files."""
        # Remove all existing rows
        child = self._files_group.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self._files_group.remove(child)
            child = next_child

        # Get recent files
        manager = get_recent_files_manager()
        recent_files = manager.get_recent_pdfs()

        if not recent_files:
            self._show_empty_state()
            return

        # Add file rows
        for file_info in recent_files:
            row = self._create_file_row(file_info)
            self._files_group.add(row)

    def _show_empty_state(self) -> None:
        """Show empty state when no recent files."""
        status_page = Adw.StatusPage()
        status_page.set_icon_name("document-open-recent-symbolic")
        status_page.set_title(_("No recent files"))
        status_page.set_description(_("Files you open or sign will appear here"))
        status_page.set_vexpand(True)

        # Wrap in box to control sizing
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        empty_box.set_size_request(350, 200)
        empty_box.append(status_page)

        self._files_group.add(empty_box)

    def _create_file_row(self, file_info) -> Adw.ActionRow:
        """Create a row for a recent file.

        Args:
            file_info: RecentFileInfo with file data

        Returns:
            Configured ActionRow
        """
        row = Adw.ActionRow()
        row.set_activatable(True)

        # Title: file name
        row.set_title(file_info.display_name)

        # Subtitle: path + relative time
        relative_time = self._format_relative_time(file_info.added_time)
        subtitle = f"{file_info.path.parent}\n{relative_time}"
        row.set_subtitle(subtitle)

        # Add icon based on file existence
        icon = Gtk.Image()
        if file_info.exists:
            icon.set_from_icon_name("document-open-symbolic")
        else:
            icon.set_from_icon_name("dialog-warning-symbolic")
            row.add_css_class("dim-label")
            row.set_subtitle(f"{subtitle}\n{_('File no longer exists')}")

        row.add_prefix(icon)

        # Add arrow suffix
        arrow = Gtk.Image.new_from_icon_name("go-next-symbolic")
        arrow.add_css_class("dim-label")
        row.add_suffix(arrow)

        # Connect click handler
        row.connect("activated", self._on_file_row_activated, file_info.path)

        return row

    def _format_relative_time(self, dt: datetime) -> str:
        """Format datetime as relative time string.

        Args:
            dt: Datetime to format

        Returns:
            Relative time string (e.g., "2 hours ago")
        """
        now = datetime.now()
        diff = now - dt

        if diff.days > 0:
            if diff.days == 1:
                return _("Yesterday")
            elif diff.days < 7:
                return _("{} days ago").format(diff.days)
            elif diff.days < 30:
                weeks = diff.days // 7
                return _("{} weeks ago").format(weeks)
            elif diff.days < 365:
                months = diff.days // 30
                return _("{} months ago").format(months)
            else:
                years = diff.days // 365
                return _("{} years ago").format(years)
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return _("{} hours ago").format(hours)
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return _("{} minutes ago").format(minutes)
        else:
            return _("Just now")

    def _on_file_row_activated(self, row: Adw.ActionRow, path: Path) -> None:
        """Handle file row activation."""
        self.emit("file-selected", path)
        self.popdown()

    def _on_clear_clicked(self, button: Gtk.Button) -> None:
        """Handle clear history button click."""
        manager = get_recent_files_manager()
        removed = manager.clear_pdf_history()

        # Refresh the list
        self._refresh_file_list()

        # Show toast if in a window with toast overlay
        window = self.get_root()
        if window and hasattr(window, "show_toast"):
            window.show_toast(_("{} files removed from history").format(removed))

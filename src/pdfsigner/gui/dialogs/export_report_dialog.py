"""
export_report_dialog.py - Export validation report dialog

Author: Homero Thompson del Lago del Terror

Dialog for exporting validation reports in multiple formats (PDF, CSV, JSON).
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk

from pdfsigner.core.reports.report_generator import ReportFormat, ReportOptions


class ExportReportDialog(Adw.Window):
    """
    Dialog for exporting validation reports.

    Allows user to select:
    - Export format (PDF, CSV, JSON)
    - Report options (summary, details, certificate info)
    - Output file location
    """

    def __init__(self, parent: Gtk.Window, **kwargs):
        """
        Initialize export report dialog.

        Args:
            parent: Parent window
        """
        super().__init__(**kwargs)

        self.set_title("Export Validation Report")
        self.set_default_size(500, 450)
        self.set_modal(True)
        self.set_transient_for(parent)

        self._parent = parent
        self._output_path: str | None = None
        self._cancelled = False

        # Build UI
        self._build_ui()

    def _build_ui(self) -> None:
        """Build dialog UI."""
        # Main box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_content(main_box)

        # Header bar
        header = Adw.HeaderBar()
        main_box.append(header)

        # Cancel button
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", self._on_cancel_clicked)
        header.pack_start(cancel_btn)

        # Export button
        self._export_btn = Gtk.Button(label="Export")
        self._export_btn.add_css_class("suggested-action")
        self._export_btn.connect("clicked", self._on_export_clicked)
        header.pack_end(self._export_btn)

        # Content area with preferences
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        main_box.append(content)

        # Preferences page
        prefs = Adw.PreferencesPage()
        content.append(prefs)

        # Format group
        format_group = Adw.PreferencesGroup()
        format_group.set_title("Export Format")
        format_group.set_description("Choose output file format")
        prefs.add(format_group)

        # Format selector
        self._format_row = Adw.ComboRow()
        self._format_row.set_title("Format")
        format_model = Gtk.StringList.new(["PDF Report", "CSV Spreadsheet", "JSON Data"])
        self._format_row.set_model(format_model)
        self._format_row.set_selected(0)  # Default to PDF
        format_group.add(self._format_row)

        # Options group
        options_group = Adw.PreferencesGroup()
        options_group.set_title("Report Options")
        options_group.set_description("Select information to include in report")
        prefs.add(options_group)

        # Include summary switch
        self._summary_row = Adw.SwitchRow()
        self._summary_row.set_title("Include Summary")
        self._summary_row.set_subtitle("Overall statistics and counts")
        self._summary_row.set_active(True)
        options_group.add(self._summary_row)

        # Include details switch
        self._details_row = Adw.SwitchRow()
        self._details_row.set_title("Include File Details")
        self._details_row.set_subtitle("Per-file validation results")
        self._details_row.set_active(True)
        options_group.add(self._details_row)

        # Include certificate info switch
        self._cert_info_row = Adw.SwitchRow()
        self._cert_info_row.set_title("Include Certificate Information")
        self._cert_info_row.set_subtitle("Detailed certificate data for each signature")
        self._cert_info_row.set_active(True)
        options_group.add(self._cert_info_row)

        # Output group
        output_group = Adw.PreferencesGroup()
        output_group.set_title("Output Location")
        prefs.add(output_group)

        # File chooser button
        file_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        file_box.set_margin_top(12)
        file_box.set_margin_bottom(12)

        self._file_label = Gtk.Label()
        self._file_label.set_text("No file selected")
        self._file_label.set_xalign(0)
        self._file_label.set_ellipsize(3)  # ELLIPSIZE_END
        self._file_label.set_hexpand(True)
        file_box.append(self._file_label)

        choose_btn = Gtk.Button(label="Choose...")
        choose_btn.connect("clicked", self._on_choose_file_clicked)
        file_box.append(choose_btn)

        output_group.add(file_box)

    def _on_choose_file_clicked(self, button: Gtk.Button) -> None:
        """Handle file chooser button click."""
        # Get file extension based on format
        format_idx = self._format_row.get_selected()
        extensions = {
            0: ("pdf", "PDF Report"),
            1: ("csv", "CSV File"),
            2: ("json", "JSON File"),
        }
        ext, desc = extensions.get(format_idx, ("pdf", "PDF Report"))

        # Create file chooser dialog
        dialog = Gtk.FileDialog()
        dialog.set_title("Save Report As")
        dialog.set_modal(True)

        # Set default filename
        default_name = f"validation_report.{ext}"
        dialog.set_initial_name(default_name)

        # Create file filter
        filter_list = Gio.ListStore.new(Gtk.FileFilter)
        file_filter = Gtk.FileFilter()
        file_filter.set_name(desc)
        file_filter.add_pattern(f"*.{ext}")
        filter_list.append(file_filter)
        dialog.set_filters(filter_list)
        dialog.set_default_filter(file_filter)

        # Show dialog
        dialog.save(self, None, self._on_file_dialog_response)

    def _on_file_dialog_response(self, dialog: Gtk.FileDialog, result) -> None:
        """Handle file chooser dialog response."""
        try:
            file = dialog.save_finish(result)
            if file:
                self._output_path = file.get_path()
                self._file_label.set_text(Path(self._output_path).name)
        except Exception:
            # User cancelled
            pass

    def _on_export_clicked(self, button: Gtk.Button) -> None:
        """Handle export button click."""
        if not self._output_path:
            # Show error toast
            toast = Adw.Toast.new("Please select output file location")
            toast.set_timeout(3)
            if hasattr(self, "_toast_overlay"):
                self._toast_overlay.add_toast(toast)
            return

        # Close dialog with success
        self._cancelled = False
        self.close()

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handle cancel button click."""
        self._cancelled = True
        self.close()

    def get_options(self) -> ReportOptions:
        """
        Get selected report options.

        Returns:
            ReportOptions instance with user selections
        """
        return ReportOptions(
            include_summary=self._summary_row.get_active(),
            include_details=self._details_row.get_active(),
            include_certificate_info=self._cert_info_row.get_active(),
            title="PDF Validation Report",
        )

    def get_format(self) -> ReportFormat:
        """
        Get selected report format.

        Returns:
            ReportFormat enum value
        """
        format_idx = self._format_row.get_selected()
        format_map = {
            0: ReportFormat.PDF,
            1: ReportFormat.CSV,
            2: ReportFormat.JSON,
        }
        return format_map.get(format_idx, ReportFormat.PDF)

    def get_output_path(self) -> str | None:
        """
        Get selected output file path.

        Returns:
            Output file path or None if not selected
        """
        return self._output_path

    def was_cancelled(self) -> bool:
        """
        Check if dialog was cancelled.

        Returns:
            True if user cancelled, False if exported
        """
        return self._cancelled

"""
export_report_dialog.py - Export validation report dialog

Dialog for exporting validation reports in multiple formats (PDF, CSV, JSON).
Shows export result with options to open file or close.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk
from loguru import logger

from pdfsigner.core.reports.report_generator import ReportFormat, ReportOptions
from pdfsigner.i18n import _

if TYPE_CHECKING:
    from pdfsigner.core.validator.pdf_validator import ValidationResult


class ExportReportDialog(Adw.Window):
    """
    Dialog for exporting validation reports.

    Allows user to select format, options, and location.
    Shows result status after export with action buttons.
    """

    def __init__(
        self,
        parent: Gtk.Window,
        validation_result: ValidationResult | None = None,
        **kwargs,
    ):
        """
        Initialize export report dialog.

        Args:
            parent: Parent window
            validation_result: The validation result to export
        """
        super().__init__(**kwargs)

        self.set_title(_("Export Validation Report"))
        self.set_default_size(450, 400)
        self.set_modal(True)
        self.set_transient_for(parent)

        self._parent = parent
        self._validation_result = validation_result
        self._output_path: str | None = None
        self._cancelled = False
        self._export_success = False

        self._build_ui()

    def _build_ui(self) -> None:
        """Build dialog UI."""
        # Toast overlay for notifications
        self._toast_overlay = Adw.ToastOverlay()
        self.set_content(self._toast_overlay)

        # Main box
        self._main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._toast_overlay.set_child(self._main_box)

        # Header bar
        self._header = Adw.HeaderBar()
        self._main_box.append(self._header)

        # Cancel button
        self._cancel_btn = Gtk.Button(label=_("Cancel"))
        self._cancel_btn.connect("clicked", self._on_cancel_clicked)
        self._header.pack_start(self._cancel_btn)

        # Export button
        self._export_btn = Gtk.Button(label=_("Export"))
        self._export_btn.add_css_class("suggested-action")
        self._export_btn.connect("clicked", self._on_export_clicked)
        self._header.pack_end(self._export_btn)

        # Content stack (form vs result)
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT)
        self._stack.set_vexpand(True)
        self._main_box.append(self._stack)

        # Build form page
        self._build_form_page()

        # Build result page (initially hidden)
        self._build_result_page()

        self._stack.set_visible_child_name("form")

    def _build_form_page(self) -> None:
        """Build the export options form."""
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.set_vexpand(True)

        prefs = Adw.PreferencesPage()
        prefs.set_vexpand(True)
        content.append(prefs)

        # Format group
        format_group = Adw.PreferencesGroup()
        format_group.set_title(_("Export Format"))
        prefs.add(format_group)

        # Format selector
        self._format_row = Adw.ComboRow()
        self._format_row.set_title(_("Format"))
        format_model = Gtk.StringList.new(
            [
                _("PDF Report"),
                _("CSV Spreadsheet"),
                _("JSON Data"),
            ]
        )
        self._format_row.set_model(format_model)
        self._format_row.set_selected(0)
        format_group.add(self._format_row)

        # File chooser
        self._file_row = Adw.ActionRow()
        self._file_row.set_title(_("Save to"))
        self._file_row.set_subtitle(_("No file selected"))

        choose_btn = Gtk.Button(label=_("Choose..."))
        choose_btn.set_valign(Gtk.Align.CENTER)
        choose_btn.connect("clicked", self._on_choose_file_clicked)
        self._file_row.add_suffix(choose_btn)
        self._file_row.set_activatable_widget(choose_btn)
        format_group.add(self._file_row)

        # Options group
        options_group = Adw.PreferencesGroup()
        options_group.set_title(_("Report Options"))
        prefs.add(options_group)

        self._summary_row = Adw.SwitchRow()
        self._summary_row.set_title(_("Include Summary"))
        self._summary_row.set_subtitle(_("Overall statistics and counts"))
        self._summary_row.set_active(True)
        options_group.add(self._summary_row)

        self._details_row = Adw.SwitchRow()
        self._details_row.set_title(_("Include File Details"))
        self._details_row.set_subtitle(_("Per-file validation results"))
        self._details_row.set_active(True)
        options_group.add(self._details_row)

        self._cert_info_row = Adw.SwitchRow()
        self._cert_info_row.set_title(_("Include Certificate Information"))
        self._cert_info_row.set_subtitle(_("Detailed certificate data"))
        self._cert_info_row.set_active(True)
        options_group.add(self._cert_info_row)

        self._stack.add_named(content, "form")

    def _build_result_page(self) -> None:
        """Build the export result page."""
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        content.set_margin_top(48)
        content.set_margin_bottom(48)
        content.set_margin_start(24)
        content.set_margin_end(24)
        content.set_valign(Gtk.Align.CENTER)
        content.set_vexpand(True)

        # Status icon
        self._result_icon = Gtk.Image()
        self._result_icon.set_pixel_size(64)
        content.append(self._result_icon)

        # Status title
        self._result_title = Gtk.Label()
        self._result_title.add_css_class("title-1")
        content.append(self._result_title)

        # Status message
        self._result_message = Gtk.Label()
        self._result_message.set_wrap(True)
        self._result_message.set_justify(Gtk.Justification.CENTER)
        self._result_message.add_css_class("dim-label")
        content.append(self._result_message)

        # Action buttons box
        buttons_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        buttons_box.set_halign(Gtk.Align.CENTER)
        buttons_box.set_margin_top(12)
        content.append(buttons_box)

        # Open file button
        self._open_file_btn = Gtk.Button(label=_("Open File"))
        self._open_file_btn.add_css_class("suggested-action")
        self._open_file_btn.add_css_class("pill")
        self._open_file_btn.connect("clicked", self._on_open_file_clicked)
        buttons_box.append(self._open_file_btn)

        # Show in folder button
        self._show_folder_btn = Gtk.Button(label=_("Show in Folder"))
        self._show_folder_btn.add_css_class("pill")
        self._show_folder_btn.connect("clicked", self._on_show_folder_clicked)
        buttons_box.append(self._show_folder_btn)

        # Close button
        close_btn = Gtk.Button(label=_("Close"))
        close_btn.add_css_class("pill")
        close_btn.connect("clicked", self._on_cancel_clicked)
        buttons_box.append(close_btn)

        self._stack.add_named(content, "result")

    def _on_choose_file_clicked(self, button: Gtk.Button) -> None:
        """Handle file chooser button click."""
        format_idx = self._format_row.get_selected()
        extensions = {
            0: ("pdf", _("PDF Report")),
            1: ("csv", _("CSV File")),
            2: ("json", _("JSON File")),
        }
        ext, desc = extensions.get(format_idx, ("pdf", _("PDF Report")))

        dialog = Gtk.FileDialog()
        dialog.set_title(_("Save Report As"))
        dialog.set_modal(True)
        dialog.set_initial_name(f"validation_report.{ext}")

        filter_list = Gio.ListStore.new(Gtk.FileFilter)
        file_filter = Gtk.FileFilter()
        file_filter.set_name(desc)
        file_filter.add_pattern(f"*.{ext}")
        filter_list.append(file_filter)
        dialog.set_filters(filter_list)
        dialog.set_default_filter(file_filter)

        dialog.save(self, None, self._on_file_dialog_response)

    def _on_file_dialog_response(self, dialog: Gtk.FileDialog, result) -> None:
        """Handle file chooser dialog response."""
        try:
            file = dialog.save_finish(result)
            if file:
                self._output_path = file.get_path()
                self._file_row.set_subtitle(Path(self._output_path).name)
        except Exception:
            pass

    def _on_export_clicked(self, button: Gtk.Button) -> None:
        """Handle export button click."""
        if not self._output_path:
            toast = Adw.Toast.new(_("Please select output file location"))
            toast.set_timeout(3)
            self._toast_overlay.add_toast(toast)
            return

        # Perform export
        success, message = self._do_export()
        self._show_result(success, message)

    def _do_export(self) -> tuple[bool, str]:
        """Perform the actual export."""
        if not self._validation_result:
            return False, _("No validation result to export")

        try:
            from pdfsigner.core.reports.report_generator import (
                ValidationReportGenerator,
            )

            options = ReportOptions(
                include_summary=self._summary_row.get_active(),
                include_details=self._details_row.get_active(),
                include_certificate_info=self._cert_info_row.get_active(),
                title=_("PDF Validation Report"),
            )

            report_format = self.get_format()
            generator = ValidationReportGenerator(options=options)
            report_data = generator.generate(
                results=[self._validation_result],
                format=report_format,
            )

            # Write to file
            if isinstance(report_data, bytes):
                with open(self._output_path, "wb") as f:
                    f.write(report_data)
            else:
                with open(self._output_path, "w", encoding="utf-8") as f:
                    f.write(report_data)

            logger.info(f"Report exported to: {self._output_path}")
            return True, str(self._output_path)

        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False, str(e)

    def _show_result(self, success: bool, message: str) -> None:
        """Show export result page."""
        self._export_success = success

        # Update header
        self._cancel_btn.set_visible(False)
        self._export_btn.set_visible(False)

        if success:
            self._result_icon.set_from_icon_name("emblem-ok-symbolic")
            self._result_icon.add_css_class("success")
            self._result_title.set_text(_("Export Successful"))
            self._result_message.set_text(Path(message).name)
            self._open_file_btn.set_visible(True)
            self._show_folder_btn.set_visible(True)
        else:
            self._result_icon.set_from_icon_name("dialog-error-symbolic")
            self._result_icon.add_css_class("error")
            self._result_title.set_text(_("Export Failed"))
            self._result_message.set_text(message)
            self._open_file_btn.set_visible(False)
            self._show_folder_btn.set_visible(False)

        self._stack.set_visible_child_name("result")

    def _on_open_file_clicked(self, button: Gtk.Button) -> None:
        """Open the exported file."""
        if self._output_path:
            try:
                Gio.AppInfo.launch_default_for_uri(f"file://{self._output_path}", None)
            except Exception as e:
                logger.error(f"Failed to open file: {e}")
                # Fallback to xdg-open
                subprocess.Popen(["xdg-open", self._output_path])

    def _on_show_folder_clicked(self, button: Gtk.Button) -> None:
        """Show the file in file manager."""
        if self._output_path:
            try:
                folder = str(Path(self._output_path).parent)
                Gio.AppInfo.launch_default_for_uri(f"file://{folder}", None)
            except Exception as e:
                logger.error(f"Failed to open folder: {e}")
                subprocess.Popen(["xdg-open", folder])

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handle cancel/close button click."""
        self._cancelled = not self._export_success
        self.close()

    def get_format(self) -> ReportFormat:
        """Get selected report format."""
        format_idx = self._format_row.get_selected()
        format_map = {
            0: ReportFormat.PDF,
            1: ReportFormat.CSV,
            2: ReportFormat.JSON,
        }
        return format_map.get(format_idx, ReportFormat.PDF)

    def get_output_path(self) -> str | None:
        """Get selected output file path."""
        return self._output_path

    def was_cancelled(self) -> bool:
        """Check if dialog was cancelled."""
        return self._cancelled

    def was_successful(self) -> bool:
        """Check if export was successful."""
        return self._export_success

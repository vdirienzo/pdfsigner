"""
validation_dialog.py - Diálogo de validación de firmas

Author: Homero Thompson del Lago del Terror

GTK4 dialog that shows validation result
of existing signatures in a PDF.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.core.reports.report_generator import ValidationReportGenerator
from pdfsigner.core.validator.pdf_validator import (
    SignatureStatus,
    ValidationResult,
)
from pdfsigner.gui.dialogs.certificate_details_dialog import CertificateDetailsDialog
from pdfsigner.gui.dialogs.export_report_dialog import ExportReportDialog
from pdfsigner.i18n import _


class ValidationResultDialog(Gtk.Dialog):
    """
    Dialog that shows signature validation results.

    Presents detailed information of each signature found
    in the PDF document.
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        result: ValidationResult | None = None,
    ):
        """
        Initializes the dialog.

        Args:
            parent: Parent window
            result: Validation result
        """
        super().__init__(
            title=_("Signature Validation"),
            transient_for=parent,
            modal=True,
        )

        self.result = result
        self._parent = parent

        self.set_default_size(600, 450)

        # Add Export Report button (only if we have valid data to export)
        if result and result.is_signed and not result.error:
            self._export_button = self.add_button(_("Export Report"), Gtk.ResponseType.NONE)
            self._export_button.add_css_class("suggested-action")
            self._export_button.connect("clicked", self._on_export_clicked)

        self.add_button(_("Close"), Gtk.ResponseType.CLOSE)

        # Contenido
        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        if result is None or result.error:
            self._show_error(content, result)
            return

        if not result.is_signed:
            self._show_not_signed(content)
            return

        self._show_signatures(content, result)

    def _show_error(self, content: Gtk.Box, result: ValidationResult | None) -> None:
        """Shows error message."""
        icon = Gtk.Label(label="❌")
        icon.add_css_class("title-1")
        content.append(icon)

        error_msg = result.error if result else _("Unknown error")
        label = Gtk.Label(label=_("Error validating document:\n{}").format(error_msg))
        label.set_wrap(True)
        content.append(label)

    def _show_not_signed(self, content: Gtk.Box) -> None:
        """Shows unsigned document message."""
        icon = Gtk.Label(label="📄")
        icon.add_css_class("title-1")
        content.append(icon)

        label = Gtk.Label(label=_("This document has no digital signatures."))
        label.add_css_class("title-2")
        content.append(label)

    def _show_signatures(self, content: Gtk.Box, result: ValidationResult) -> None:
        """Shows signature information."""
        # Header con resumen
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        if result.all_valid:
            icon = Gtk.Label(label="✅")
            status_text = _("All signatures are valid ({})").format(result.signature_count)
            status_class = "success"
        else:
            icon = Gtk.Label(label="⚠️")
            valid_count = sum(1 for s in result.signatures if s.status == SignatureStatus.VALID)
            status_text = _("{}/{} valid signatures").format(valid_count, result.signature_count)
            status_class = "warning"

        icon.add_css_class("title-1")
        header_box.append(icon)

        status_label = Gtk.Label(label=status_text)
        status_label.add_css_class("title-3")
        status_label.add_css_class(status_class)
        header_box.append(status_label)

        content.append(header_box)

        # Lista de firmas
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        listbox.add_css_class("boxed-list")

        for sig in result.signatures:
            row = self._create_signature_row(sig)
            listbox.append(row)

        scrolled.set_child(listbox)
        content.append(scrolled)

        # Info del archivo
        file_label = Gtk.Label(label=_("File: {}").format(result.file_path.name))
        file_label.set_xalign(0)
        file_label.set_wrap(True)
        file_label.set_wrap_mode(2)  # WORD_CHAR
        file_label.add_css_class("dim-label")
        content.append(file_label)

    def _create_signature_row(self, sig) -> Gtk.ListBoxRow:
        """Creates row for a signature."""
        row = Gtk.ListBoxRow()

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(12)
        main_box.set_margin_end(12)

        # Header de firma
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        # Icono de estado
        if sig.status == SignatureStatus.VALID:
            icon = Gtk.Label(label="✓")
            icon.add_css_class("success")
        elif sig.status == SignatureStatus.INVALID:
            icon = Gtk.Label(label="✗")
            icon.add_css_class("error")
        else:
            icon = Gtk.Label(label="?")
            icon.add_css_class("warning")

        icon.set_size_request(20, -1)
        header.append(icon)

        # Nombre del firmante
        name_label = Gtk.Label(label=sig.signer_name)
        name_label.set_hexpand(True)
        name_label.set_xalign(0)
        name_label.set_wrap(True)
        name_label.set_wrap_mode(2)  # WORD_CHAR
        name_label.add_css_class("heading")
        header.append(name_label)

        # Timestamp
        if sig.is_timestamp_valid and sig.signing_time:
            time_str = sig.signing_time.strftime("%d/%m/%Y %H:%M")
            time_label = Gtk.Label(label=time_str)
            time_label.add_css_class("dim-label")
            header.append(time_label)

        main_box.append(header)

        # Detalles
        details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        details_box.set_margin_start(28)

        # Estado
        status_label = Gtk.Label(label=sig.status_message)
        status_label.set_xalign(0)
        status_label.set_wrap(True)
        status_label.set_wrap_mode(2)  # WORD_CHAR
        if sig.status != SignatureStatus.VALID:
            status_label.add_css_class("warning")
        details_box.append(status_label)

        # Emisor
        issuer_label = Gtk.Label(label=_("Issuer: {}").format(sig.certificate_issuer))
        issuer_label.set_xalign(0)
        issuer_label.set_wrap(True)
        issuer_label.set_wrap_mode(2)  # WORD_CHAR
        issuer_label.add_css_class("dim-label")
        details_box.append(issuer_label)

        # Cobertura
        if sig.covers_whole_document:
            coverage = _("Covers entire document")
        else:
            coverage = _("Covers partial revision")
        coverage_label = Gtk.Label(label=coverage)
        coverage_label.set_xalign(0)
        coverage_label.set_wrap(True)
        coverage_label.set_wrap_mode(2)  # WORD_CHAR
        coverage_label.add_css_class("dim-label")
        details_box.append(coverage_label)

        # Revocation status (if available)
        if sig.revocation_status:
            status_icons = {
                "valid": "✓",
                "revoked": "⚠",
                "unknown": "?",
                "error": "⚠",
            }
            icon = status_icons.get(sig.revocation_status, "?")
            revocation_text = f"{icon} {sig.revocation_message or sig.revocation_status}"
            revocation_label = Gtk.Label(label=_("Revocation Status: {}").format(revocation_text))
            revocation_label.set_xalign(0)
            revocation_label.set_wrap(True)
            revocation_label.set_wrap_mode(2)  # WORD_CHAR
            revocation_label.add_css_class("dim-label")
            if sig.revocation_status == "revoked":
                revocation_label.add_css_class("error")
            elif sig.revocation_status == "error":
                revocation_label.add_css_class("warning")
            details_box.append(revocation_label)

        main_box.append(details_box)

        # View Certificate button (only if certificate bytes are available)
        if sig.certificate_bytes:
            button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            button_box.set_margin_top(6)
            button_box.set_margin_start(28)

            view_cert_btn = Gtk.Button(label=_("View Certificate"))
            view_cert_btn.add_css_class("flat")
            view_cert_btn.connect("clicked", lambda b: self._show_certificate_details(sig))
            button_box.append(view_cert_btn)

            main_box.append(button_box)

        row.set_child(main_box)

        return row

    def _show_certificate_details(self, sig_info) -> None:
        """Show certificate details dialog."""
        if not sig_info.certificate_bytes:
            return

        dialog = CertificateDetailsDialog(cert_bytes=sig_info.certificate_bytes)
        dialog.set_transient_for(self)
        dialog.present()

    def _on_export_clicked(self, button: Gtk.Button) -> None:
        """Handle export button click."""
        # Open export dialog
        export_dialog = ExportReportDialog(parent=self._parent or self)
        export_dialog.connect("close-request", self._on_export_dialog_close)
        export_dialog.present()

    def _on_export_dialog_close(self, dialog: ExportReportDialog) -> bool:
        """Handle export dialog close."""
        if dialog.was_cancelled():
            return False

        # Get export parameters
        output_path = dialog.get_output_path()
        if not output_path:
            return False

        # Ensure we have a valid result to export
        if not self.result:
            return False

        report_format = dialog.get_format()
        report_options = dialog.get_options()

        try:
            # Generate report
            generator = ValidationReportGenerator(options=report_options)
            report_data = generator.generate(
                results=[self.result],  # ValidationReportGenerator expects a list
                format=report_format,
            )

            # Write to file
            if isinstance(report_data, bytes):
                # PDF format
                with open(output_path, "wb") as f:
                    f.write(report_data)
            else:
                # CSV or JSON format
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(report_data)

            # Show success toast if we have a parent window that supports toasts
            if self._parent and hasattr(self._parent, "add_toast"):
                toast = Adw.Toast.new(_("Report exported successfully"))
                toast.set_timeout(3)
                self._parent.add_toast(toast)

        except Exception as e:
            # Show error toast
            if self._parent and hasattr(self._parent, "add_toast"):
                toast = Adw.Toast.new(_("Error exporting report: {}").format(str(e)))
                toast.set_timeout(5)
                self._parent.add_toast(toast)

        return False


def show_validation_result(
    parent: Gtk.Window | None = None,
    result: ValidationResult | None = None,
) -> None:
    """
    Shows validation dialog.

    Args:
        parent: Parent window
        result: Validation result
    """
    dialog = ValidationResultDialog(parent=parent, result=result)
    dialog.connect("response", lambda d, r: d.destroy())
    dialog.present()

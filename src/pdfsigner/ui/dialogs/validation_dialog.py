"""
validation_dialog.py - Diálogo de validación de firmas

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 que muestra el resultado de validación
de firmas existentes en un PDF.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.validator.pdf_validator import (
    SignatureStatus,
    ValidationResult,
)


class ValidationResultDialog(Gtk.Dialog):
    """
    Diálogo que muestra resultados de validación de firmas.

    Presenta información detallada de cada firma encontrada
    en el documento PDF.
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        result: ValidationResult | None = None,
    ):
        """
        Inicializa el diálogo.

        Args:
            parent: Ventana padre
            result: Resultado de validación
        """
        super().__init__(
            title="Validación de Firmas",
            transient_for=parent,
            modal=True,
        )

        self.result = result

        self.set_default_size(600, 450)
        self.add_button("Cerrar", Gtk.ResponseType.CLOSE)

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
        """Muestra mensaje de error."""
        icon = Gtk.Label(label="❌")
        icon.add_css_class("title-1")
        content.append(icon)

        error_msg = result.error if result else "Error desconocido"
        label = Gtk.Label(label=f"Error al validar el documento:\n{error_msg}")
        label.set_wrap(True)
        content.append(label)

    def _show_not_signed(self, content: Gtk.Box) -> None:
        """Muestra mensaje de documento no firmado."""
        icon = Gtk.Label(label="📄")
        icon.add_css_class("title-1")
        content.append(icon)

        label = Gtk.Label(label="Este documento no tiene firmas digitales.")
        label.add_css_class("title-2")
        content.append(label)

    def _show_signatures(self, content: Gtk.Box, result: ValidationResult) -> None:
        """Muestra información de firmas."""
        # Header con resumen
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        if result.all_valid:
            icon = Gtk.Label(label="✅")
            status_text = f"Todas las firmas son válidas ({result.signature_count})"
            status_class = "success"
        else:
            icon = Gtk.Label(label="⚠️")
            valid_count = sum(1 for s in result.signatures if s.status == SignatureStatus.VALID)
            status_text = f"{valid_count}/{result.signature_count} firmas válidas"
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
        file_label = Gtk.Label(label=f"Archivo: {result.file_path.name}")
        file_label.set_xalign(0)
        file_label.add_css_class("dim-label")
        content.append(file_label)

    def _create_signature_row(self, sig) -> Gtk.ListBoxRow:
        """Crea fila para una firma."""
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
        if sig.status != SignatureStatus.VALID:
            status_label.add_css_class("warning")
        details_box.append(status_label)

        # Emisor
        issuer_label = Gtk.Label(label=f"Emisor: {sig.certificate_issuer}")
        issuer_label.set_xalign(0)
        issuer_label.add_css_class("dim-label")
        details_box.append(issuer_label)

        # Cobertura
        if sig.covers_whole_document:
            coverage = "Cubre todo el documento"
        else:
            coverage = "Cubre revisión parcial"
        coverage_label = Gtk.Label(label=coverage)
        coverage_label.set_xalign(0)
        coverage_label.add_css_class("dim-label")
        details_box.append(coverage_label)

        main_box.append(details_box)
        row.set_child(main_box)

        return row


def show_validation_result(
    parent: Gtk.Window | None = None,
    result: ValidationResult | None = None,
) -> None:
    """
    Muestra diálogo de validación.

    Args:
        parent: Ventana padre
        result: Resultado de validación
    """
    dialog = ValidationResultDialog(parent=parent, result=result)
    dialog.run()
    dialog.destroy()

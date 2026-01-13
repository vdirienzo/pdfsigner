"""
cert_selector_dialog.py - Diálogo de selección de certificado

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 para seleccionar entre múltiples certificados
disponibles en el token USB.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.token.cert_selector import ValidCertificate


class CertificateSelectorDialog(Gtk.Dialog):
    """
    Diálogo para seleccionar certificado de firma.

    Muestra lista de certificados válidos con información
    relevante para que el usuario elija cuál usar.
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        certificates: list[ValidCertificate] | None = None,
    ):
        """
        Inicializa el diálogo.

        Args:
            parent: Ventana padre
            certificates: Lista de certificados disponibles
        """
        super().__init__(
            title="Seleccionar Certificado",
            transient_for=parent,
            modal=True,
        )

        self.certificates = certificates or []
        self._selected_cert: ValidCertificate | None = None

        self.set_default_size(550, 400)

        # Botones
        self.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        self._ok_button = self.add_button("Usar Certificado", Gtk.ResponseType.OK)
        self._ok_button.add_css_class("suggested-action")
        self._ok_button.set_sensitive(False)

        # Contenido
        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        # Mensaje
        msg_label = Gtk.Label(label="Seleccione el certificado para firmar:")
        msg_label.set_xalign(0)
        content.append(msg_label)

        # Lista de certificados
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.connect("row-selected", self._on_row_selected)

        # Agregar certificados
        for cert in self.certificates:
            row = self._create_cert_row(cert)
            self.listbox.append(row)

        scrolled.set_child(self.listbox)
        content.append(scrolled)

        # Info del certificado seleccionado
        self.info_frame = Gtk.Frame()
        self.info_frame.set_label("Detalles del Certificado")
        self.info_label = Gtk.Label()
        self.info_label.set_wrap(True)
        self.info_label.set_xalign(0)
        self.info_label.set_margin_top(8)
        self.info_label.set_margin_bottom(8)
        self.info_label.set_margin_start(8)
        self.info_label.set_margin_end(8)
        self.info_frame.set_child(self.info_label)
        content.append(self.info_frame)

        # Seleccionar el primero por defecto
        if self.certificates:
            first_row = self.listbox.get_row_at_index(0)
            if first_row:
                self.listbox.select_row(first_row)

    def _create_cert_row(self, cert: ValidCertificate) -> Gtk.ListBoxRow:
        """Crea una fila para un certificado."""
        row = Gtk.ListBoxRow()
        row.cert = cert  # Guardar referencia

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # Icono de estado
        if cert.is_expiring_soon:
            icon = Gtk.Label(label="⚠️")
            icon.set_tooltip_text(f"Expira en {cert.days_until_expiry} días")
        else:
            icon = Gtk.Label(label="🔐")
        icon.set_size_request(24, -1)
        box.append(icon)

        # Info del certificado
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        info_box.set_hexpand(True)

        name_label = Gtk.Label(label=cert.display_name)
        name_label.set_xalign(0)
        name_label.add_css_class("heading")
        info_box.append(name_label)

        # Emisor (extraer CN)
        issuer = cert.info.issuer
        issuer_cn = issuer.split(",")[0].replace("CN=", "") if "CN=" in issuer else issuer
        issuer_label = Gtk.Label(label=f"Emisor: {issuer_cn}")
        issuer_label.set_xalign(0)
        issuer_label.add_css_class("dim-label")
        info_box.append(issuer_label)

        box.append(info_box)

        # Días restantes
        days_label = Gtk.Label(label=f"{cert.days_until_expiry} días")
        if cert.is_expiring_soon:
            days_label.add_css_class("warning")
        else:
            days_label.add_css_class("dim-label")
        box.append(days_label)

        row.set_child(box)
        return row

    def _on_row_selected(self, listbox: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        """Maneja selección de certificado."""
        if row is None:
            self._selected_cert = None
            self._ok_button.set_sensitive(False)
            self.info_label.set_label("")
            return

        self._selected_cert = row.cert
        self._ok_button.set_sensitive(True)

        # Mostrar detalles
        cert = self._selected_cert
        info_text = (
            f"Nombre: {cert.display_name}\n"
            f"Serial: {cert.info.serial_number}\n"
            f"Válido desde: {cert.info.not_before}\n"
            f"Válido hasta: {cert.info.not_after}\n"
            f"Días restantes: {cert.days_until_expiry}"
        )
        self.info_label.set_label(info_text)

    def get_selected_certificate(self) -> ValidCertificate | None:
        """Obtiene el certificado seleccionado."""
        return self._selected_cert


def ask_certificate(
    parent: Gtk.Window | None = None,
    certificates: list[ValidCertificate] | None = None,
) -> ValidCertificate | None:
    """
    Función de conveniencia para seleccionar certificado.

    Args:
        parent: Ventana padre
        certificates: Lista de certificados

    Returns:
        Certificado seleccionado o None si cancela
    """
    if not certificates:
        return None

    # Si solo hay uno, retornarlo directamente
    if len(certificates) == 1:
        return certificates[0]

    dialog = CertificateSelectorDialog(
        parent=parent,
        certificates=certificates,
    )

    response = dialog.run()
    cert = dialog.get_selected_certificate() if response == Gtk.ResponseType.OK else None
    dialog.destroy()

    return cert

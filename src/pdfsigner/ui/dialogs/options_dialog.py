"""
options_dialog.py - Diálogo de opciones de firma

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 para configurar opciones de firma:
- Firma visible/invisible
- Selección de página
- Preferencia de posición
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance


class SignatureOptionsDialog(Gtk.Dialog):
    """
    Diálogo de opciones de firma.

    Permite configurar:
    - Firma visible o invisible
    - Página donde colocar la firma
    - Posición preferida
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        total_pages: int = 1,
        default_appearance: SignatureAppearance | None = None,
    ):
        """
        Inicializa el diálogo de opciones.

        Args:
            parent: Ventana padre
            total_pages: Número total de páginas del PDF
            default_appearance: Configuración por defecto
        """
        super().__init__(
            title="Opciones de Firma",
            transient_for=parent,
            modal=True,
        )

        self.total_pages = total_pages
        self.default_appearance = default_appearance or SignatureAppearance()

        self.set_default_size(450, 350)

        # Botones
        self.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        ok_button = self.add_button("Firmar", Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        # Contenido
        content = self.get_content_area()
        content.set_spacing(18)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        # === Sección: Tipo de firma ===
        type_frame = self._create_section("Tipo de Firma")
        type_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        # Radio: Invisible
        self.radio_invisible = Gtk.CheckButton(label="Firma invisible (solo metadatos)")
        self.radio_invisible.set_active(not self.default_appearance.visible)

        # Radio: Visible
        self.radio_visible = Gtk.CheckButton(label="Firma visible (sello en el documento)")
        self.radio_visible.set_group(self.radio_invisible)
        self.radio_visible.set_active(self.default_appearance.visible)
        self.radio_visible.connect("toggled", self._on_visible_toggled)

        type_box.append(self.radio_invisible)
        type_box.append(self.radio_visible)
        type_frame.set_child(type_box)
        content.append(type_frame)

        # === Sección: Opciones de firma visible ===
        self.visible_frame = self._create_section("Opciones de Firma Visible")
        visible_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        # Selector de página
        page_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        page_label = Gtk.Label(label="Página:")
        page_label.set_xalign(0)
        page_label.set_size_request(100, -1)

        self.page_combo = Gtk.ComboBoxText()
        self.page_combo.append("last", "Última página")
        self.page_combo.append("first", "Primera página")
        for i in range(1, min(total_pages + 1, 100)):
            self.page_combo.append(str(i - 1), f"Página {i}")
        self.page_combo.set_active_id(
            str(self.default_appearance.page)
            if isinstance(self.default_appearance.page, int)
            else self.default_appearance.page
        )

        page_box.append(page_label)
        page_box.append(self.page_combo)
        visible_box.append(page_box)

        # Selector de posición
        pos_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        pos_label = Gtk.Label(label="Posición:")
        pos_label.set_xalign(0)
        pos_label.set_size_request(100, -1)

        self.position_combo = Gtk.ComboBoxText()
        self.position_combo.append("auto", "Automática (buscar espacio libre)")
        self.position_combo.append("bottom_right", "Inferior derecha")
        self.position_combo.append("bottom_left", "Inferior izquierda")
        self.position_combo.append("bottom_center", "Inferior centro")
        self.position_combo.append("top_right", "Superior derecha")
        self.position_combo.append("top_left", "Superior izquierda")
        self.position_combo.set_active_id(self.default_appearance.position_preference.value)

        pos_box.append(pos_label)
        pos_box.append(self.position_combo)
        visible_box.append(pos_box)

        self.visible_frame.set_child(visible_box)
        content.append(self.visible_frame)

        # Estado inicial
        self._on_visible_toggled(self.radio_visible)

    def _create_section(self, title: str) -> Gtk.Frame:
        """Crea un frame de sección."""
        frame = Gtk.Frame()
        frame.set_label(title)
        return frame

    def _on_visible_toggled(self, button: Gtk.CheckButton) -> None:
        """Muestra/oculta opciones de firma visible."""
        self.visible_frame.set_sensitive(button.get_active())

    def get_appearance(self) -> SignatureAppearance:
        """Obtiene la configuración seleccionada."""
        visible = self.radio_visible.get_active()

        # Página
        page_id = self.page_combo.get_active_id()
        if page_id in ("last", "first"):
            page = page_id
        else:
            page = int(page_id)

        # Posición
        pos_id = self.position_combo.get_active_id()
        position = PositionPreference(pos_id)

        return SignatureAppearance(
            visible=visible,
            page=page,
            width_mm=self.default_appearance.width_mm,
            height_mm=self.default_appearance.height_mm,
            position_preference=position,
            image_path=self.default_appearance.image_path,
        )


def ask_signature_options(
    parent: Gtk.Window | None = None,
    total_pages: int = 1,
    default_appearance: SignatureAppearance | None = None,
) -> SignatureAppearance | None:
    """
    Función de conveniencia para solicitar opciones de firma.

    Args:
        parent: Ventana padre
        total_pages: Número de páginas del PDF
        default_appearance: Configuración por defecto

    Returns:
        SignatureAppearance configurada o None si se cancela
    """
    dialog = SignatureOptionsDialog(
        parent=parent,
        total_pages=total_pages,
        default_appearance=default_appearance,
    )

    response = dialog.run()
    appearance = dialog.get_appearance() if response == Gtk.ResponseType.OK else None
    dialog.destroy()

    return appearance

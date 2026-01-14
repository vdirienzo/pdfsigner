"""
options_dialog.py - Diálogo de opciones de firma

Author: Homero Thompson del Lago del Terror

GTK4 dialog to configure signature options:
- Firma visible/invisible
- Selección de página
- Position preference
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance


class SignatureOptionsDialog(Gtk.Dialog):
    """
    Signature options dialog.

    Allows configuring:
    - Visible or invisible signature
    - Page where to place the signature
    - Preferred position
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        total_pages: int = 1,
        default_appearance: SignatureAppearance | None = None,
    ):
        """
        Initializes the options dialog.

        Args:
            parent: Parent window
            total_pages: Total number of PDF pages
            default_appearance: Default configuration
        """
        super().__init__(
            title="Signature Options",
            transient_for=parent,
            modal=True,
        )

        self.total_pages = total_pages
        self.default_appearance = default_appearance or SignatureAppearance()

        self.set_default_size(450, 350)

        # Botones
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_button = self.add_button("Sign", Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        # Contenido
        content = self.get_content_area()
        content.set_spacing(18)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        # === Sección: Tipo de firma ===
        type_frame = self._create_section("Signature Type")
        type_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        # Radio: Invisible
        self.radio_invisible = Gtk.CheckButton(label="Invisible signature (metadata only)")
        self.radio_invisible.set_active(not self.default_appearance.visible)

        # Radio: Visible
        self.radio_visible = Gtk.CheckButton(label="Visible signature (stamp on document)")
        self.radio_visible.set_group(self.radio_invisible)
        self.radio_visible.set_active(self.default_appearance.visible)
        self.radio_visible.connect("toggled", self._on_visible_toggled)

        type_box.append(self.radio_invisible)
        type_box.append(self.radio_visible)
        type_frame.set_child(type_box)
        content.append(type_frame)

        # === Sección: Opciones de firma visible ===
        self.visible_frame = self._create_section("Visible Signature Options")
        visible_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        # Selector de página
        page_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        page_label = Gtk.Label(label="Page:")
        page_label.set_xalign(0)
        page_label.set_size_request(100, -1)

        self.page_combo = Gtk.ComboBoxText()
        self.page_combo.append("last", "Last page")
        self.page_combo.append("first", "First page")
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
        pos_label = Gtk.Label(label="Position:")
        pos_label.set_xalign(0)
        pos_label.set_size_request(100, -1)

        self.position_combo = Gtk.ComboBoxText()
        self.position_combo.append("auto", "Automatic (find free space)")
        self.position_combo.append("bottom_right", "Bottom right")
        self.position_combo.append("bottom_left", "Bottom left")
        self.position_combo.append("bottom_center", "Bottom center")
        self.position_combo.append("top_right", "Top right")
        self.position_combo.append("top_left", "Top left")
        self.position_combo.set_active_id(self.default_appearance.position_preference.value)

        pos_box.append(pos_label)
        pos_box.append(self.position_combo)
        visible_box.append(pos_box)

        self.visible_frame.set_child(visible_box)
        content.append(self.visible_frame)

        # Estado inicial
        self._on_visible_toggled(self.radio_visible)

    def _create_section(self, title: str) -> Gtk.Frame:
        """Creates a section frame."""
        frame = Gtk.Frame()
        frame.set_label(title)
        return frame

    def _on_visible_toggled(self, button: Gtk.CheckButton) -> None:
        """Shows/hides visible signature options."""
        self.visible_frame.set_sensitive(button.get_active())

    def get_appearance(self) -> SignatureAppearance:
        """Gets the selected configuration."""
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
    Convenience function to request signature options.

    Args:
        parent: Parent window
        total_pages: Número de páginas del PDF
        default_appearance: Default configuration

    Returns:
        Configured SignatureAppearance or None if cancelled
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

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
from pdfsigner.i18n import _


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
            title=_("Signature Options"),
            transient_for=parent,
            modal=True,
        )

        self.total_pages = total_pages
        self.default_appearance = default_appearance or SignatureAppearance()

        self.set_default_size(450, 350)

        # Botones
        self.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        ok_button = self.add_button(_("Sign"), Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        # Contenido
        content = self.get_content_area()
        content.set_spacing(18)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        # === Sección: Tipo de firma ===
        type_frame = self._create_section(_("Signature Type"))
        type_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        # Radio: Invisible
        self.radio_invisible = Gtk.CheckButton(label=_("Invisible signature (metadata only)"))
        self.radio_invisible.set_active(not self.default_appearance.visible)

        # Radio: Visible
        self.radio_visible = Gtk.CheckButton(label=_("Visible signature (stamp on document)"))
        self.radio_visible.set_group(self.radio_invisible)
        self.radio_visible.set_active(self.default_appearance.visible)
        self.radio_visible.connect("toggled", self._on_visible_toggled)

        type_box.append(self.radio_invisible)
        type_box.append(self.radio_visible)
        type_frame.set_child(type_box)
        content.append(type_frame)

        # === Sección: Opciones de firma visible ===
        self.visible_frame = self._create_section(_("Visible Signature Options"))
        visible_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        # Selector de página
        page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        page_combo_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        page_label = Gtk.Label(label=_("Page:"))
        page_label.set_xalign(0)
        page_label.set_size_request(100, -1)

        self.page_combo = Gtk.ComboBoxText()
        self.page_combo.append("last", _("Last page"))
        self.page_combo.append("first", _("First page"))
        self.page_combo.append("all", _("All pages"))
        self.page_combo.append("custom", _("Custom..."))
        self.page_combo.connect("changed", self._on_page_combo_changed)

        page_combo_box.append(page_label)
        page_combo_box.append(self.page_combo)
        page_box.append(page_combo_box)

        # Custom page entry (initially hidden)
        self.custom_page_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        custom_label = Gtk.Label(label=_("Pages:"))
        custom_label.set_xalign(0)
        custom_label.set_size_request(100, -1)

        self.custom_page_entry = Gtk.Entry()
        self.custom_page_entry.set_placeholder_text(_("e.g., 1,3,5 or 1-3 or 1-3,5,7"))
        self.custom_page_entry.set_hexpand(True)

        self.custom_page_box.append(custom_label)
        self.custom_page_box.append(self.custom_page_entry)
        self.custom_page_box.set_visible(False)
        page_box.append(self.custom_page_box)

        # Set default selection
        default_page = self.default_appearance.page
        if default_page in ("last", "first", "all"):
            self.page_combo.set_active_id(default_page)
        elif isinstance(default_page, str) and any(c in default_page for c in ",-"):
            # Custom range
            self.page_combo.set_active_id("custom")
            self.custom_page_entry.set_text(default_page)
            self.custom_page_box.set_visible(True)
        else:
            self.page_combo.set_active_id("last")

        visible_box.append(page_box)

        # Selector de posición
        pos_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        pos_label = Gtk.Label(label=_("Position:"))
        pos_label.set_xalign(0)
        pos_label.set_size_request(100, -1)

        self.position_combo = Gtk.ComboBoxText()
        self.position_combo.append("auto", _("Automatic (find free space)"))
        self.position_combo.append("bottom_right", _("Bottom right"))
        self.position_combo.append("bottom_left", _("Bottom left"))
        self.position_combo.append("bottom_center", _("Bottom center"))
        self.position_combo.append("top_right", _("Top right"))
        self.position_combo.append("top_left", _("Top left"))
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

    def _on_page_combo_changed(self, combo: Gtk.ComboBoxText) -> None:
        """Shows/hides custom page entry based on selection."""
        is_custom = combo.get_active_id() == "custom"
        self.custom_page_box.set_visible(is_custom)
        if is_custom:
            self.custom_page_entry.grab_focus()

    def get_appearance(self) -> SignatureAppearance:
        """Gets the selected configuration."""
        visible = self.radio_visible.get_active()

        # Page selection: "last", "first", "all", or custom range
        page_id = self.page_combo.get_active_id() or "last"
        if page_id == "custom":
            # Get custom page range from entry
            page = self.custom_page_entry.get_text().strip() or "last"
        else:
            page = page_id

        # Position preference
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

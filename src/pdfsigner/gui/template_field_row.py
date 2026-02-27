"""
template_field_row.py - Template field data and row widget

Provides FieldData dataclass and FieldRow GTK widget for
template editor's dynamic text field list.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk

from pdfsigner.i18n import _


@dataclass
class FieldData:
    """Data for a text field in the template."""

    text: str
    font_size: int
    color: str
    is_variable: bool = False  # True for {signer_name}, {org}, {date}


# Predefined field options
PREDEFINED_FIELDS = {
    "{signer_name}": _("Signer name"),
    "{org}": _("Organization"),
    "{date}": _("Date"),
}


class FieldRow(Gtk.ListBoxRow):
    """A row representing a text field in the template."""

    def __init__(
        self,
        field_data: FieldData,
        on_changed: Callable[[], None],
        on_delete: Callable[[Gtk.ListBoxRow], None],
        on_move_up: Callable[[Gtk.ListBoxRow], None],
        on_move_down: Callable[[Gtk.ListBoxRow], None],
    ):
        super().__init__()
        self._field_data = field_data
        self._on_changed = on_changed
        self._on_delete = on_delete
        self._on_move_up = on_move_up
        self._on_move_down = on_move_down
        self._updating = False

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the row UI."""
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        main_box.set_margin_top(6)
        main_box.set_margin_bottom(6)
        main_box.set_margin_start(8)
        main_box.set_margin_end(8)

        main_box.append(self._build_move_buttons())
        main_box.append(self._build_text_section())
        main_box.append(self._build_font_size_section())
        main_box.append(self._build_color_section())
        main_box.append(self._build_delete_button())

        self.set_child(main_box)

    def _build_move_buttons(self) -> Gtk.Box:
        """Build up/down move buttons."""
        move_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        move_box.set_valign(Gtk.Align.CENTER)

        self._up_btn = Gtk.Button()
        self._up_btn.set_icon_name("go-up-symbolic")
        self._up_btn.add_css_class("flat")
        self._up_btn.add_css_class("circular")
        self._up_btn.set_tooltip_text(_("Move up"))
        self._up_btn.connect("clicked", lambda _: self._on_move_up(self))
        move_box.append(self._up_btn)

        self._down_btn = Gtk.Button()
        self._down_btn.set_icon_name("go-down-symbolic")
        self._down_btn.add_css_class("flat")
        self._down_btn.add_css_class("circular")
        self._down_btn.set_tooltip_text(_("Move down"))
        self._down_btn.connect("clicked", lambda _: self._on_move_down(self))
        move_box.append(self._down_btn)

        return move_box

    def _build_text_section(self) -> Gtk.Box:
        """Build text entry or variable label section."""
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)
        text_box.set_valign(Gtk.Align.CENTER)

        if self._field_data.is_variable:
            label_text = PREDEFINED_FIELDS.get(self._field_data.text, self._field_data.text)
            self._text_label = Gtk.Label(label=label_text)
            self._text_label.set_halign(Gtk.Align.START)
            self._text_label.add_css_class("heading")
            text_box.append(self._text_label)

            var_label = Gtk.Label(label=self._field_data.text)
            var_label.set_halign(Gtk.Align.START)
            var_label.add_css_class("dim-label")
            var_label.add_css_class("caption")
            text_box.append(var_label)

            self._text_entry = None
        else:
            self._text_entry = Gtk.Entry()
            self._text_entry.set_text(self._field_data.text)
            self._text_entry.set_placeholder_text(_("Enter custom text..."))
            self._text_entry.set_hexpand(True)
            self._text_entry.connect("changed", self._on_text_changed)
            text_box.append(self._text_entry)

            self._text_label = None

        return text_box

    def _build_font_size_section(self) -> Gtk.Box:
        """Build font size spinner section."""
        size_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        size_box.set_valign(Gtk.Align.CENTER)

        size_label = Gtk.Label(label=_("Size"))
        size_label.add_css_class("dim-label")
        size_label.add_css_class("caption")
        size_box.append(size_label)

        self._font_spin = Gtk.SpinButton.new_with_range(6, 24, 1)
        self._font_spin.set_value(self._field_data.font_size)
        self._font_spin.set_tooltip_text(_("Font size"))
        self._font_spin.connect("value-changed", self._on_spin_changed)
        size_box.append(self._font_spin)

        return size_box

    def _build_color_section(self) -> Gtk.Box:
        """Build color picker section."""
        color_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        color_box.set_valign(Gtk.Align.CENTER)

        color_label = Gtk.Label(label=_("Color"))
        color_label.add_css_class("dim-label")
        color_label.add_css_class("caption")
        color_box.append(color_label)

        self._color_btn = Gtk.ColorButton()
        self._color_btn.set_rgba(self._hex_to_rgba(self._field_data.color))
        self._color_btn.connect("color-set", self._on_color_changed)
        color_box.append(self._color_btn)

        return color_box

    def _build_delete_button(self) -> Gtk.Button:
        """Build delete field button."""
        delete_btn = Gtk.Button()
        delete_btn.set_icon_name("user-trash-symbolic")
        delete_btn.add_css_class("flat")
        delete_btn.add_css_class("circular")
        delete_btn.add_css_class("destructive-action")
        delete_btn.set_tooltip_text(_("Remove field"))
        delete_btn.set_valign(Gtk.Align.CENTER)
        delete_btn.connect("clicked", lambda _: self._on_delete(self))
        return delete_btn

    def _hex_to_rgba(self, hex_color: str) -> Gdk.RGBA:
        """Convert hex color string to Gdk.RGBA."""
        rgba = Gdk.RGBA()
        if hex_color.startswith("#"):
            hex_color = hex_color[1:]
        if len(hex_color) == 3:
            hex_color = "".join(c * 2 for c in hex_color)
        if len(hex_color) == 6:
            r = int(hex_color[0:2], 16) / 255.0
            g = int(hex_color[2:4], 16) / 255.0
            b = int(hex_color[4:6], 16) / 255.0
            rgba.red, rgba.green, rgba.blue, rgba.alpha = r, g, b, 1.0
        return rgba

    def _rgba_to_hex(self, rgba: Gdk.RGBA) -> str:
        """Convert Gdk.RGBA to hex color string."""
        r = int(rgba.red * 255)
        g = int(rgba.green * 255)
        b = int(rgba.blue * 255)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _on_text_changed(self, entry: Gtk.Entry) -> None:
        """Handle text change."""
        if not self._updating:
            self._field_data.text = entry.get_text()
            self._on_changed()

    def _on_spin_changed(self, spin: Gtk.SpinButton) -> None:
        """Handle font size change."""
        if not self._updating:
            self._field_data.font_size = int(spin.get_value())
            self._on_changed()

    def _on_color_changed(self, btn: Gtk.ColorButton) -> None:
        """Handle color change."""
        if not self._updating:
            self._field_data.color = self._rgba_to_hex(btn.get_rgba())
            self._on_changed()

    def get_field_data(self) -> FieldData:
        """Get the current field data."""
        return self._field_data

    def update_move_buttons(self, can_move_up: bool, can_move_down: bool) -> None:
        """Update move button sensitivity."""
        self._up_btn.set_sensitive(can_move_up)
        self._down_btn.set_sensitive(can_move_down)

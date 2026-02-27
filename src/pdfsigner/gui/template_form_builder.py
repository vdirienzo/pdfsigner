"""
template_form_builder.py - Form building and template construction helpers

Provides UI group builders and template construction logic
extracted from TemplateEditorDialog.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk

from pdfsigner.core.signature import Layer, Template
from pdfsigner.gui.template_field_row import PREDEFINED_FIELDS, FieldData
from pdfsigner.i18n import _

if TYPE_CHECKING:
    from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog


def create_basic_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the basic info group (name, description)."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Basic Info"))

    dialog._name_row = Adw.EntryRow()
    dialog._name_row.set_title(_("Name"))
    dialog._name_row.set_text("my_template")
    dialog._name_row.connect("changed", dialog._on_field_changed)
    group.add(dialog._name_row)

    dialog._desc_row = Adw.EntryRow()
    dialog._desc_row.set_title(_("Description"))
    dialog._desc_row.set_text(_("Custom signature template"))
    dialog._desc_row.connect("changed", dialog._on_field_changed)
    group.add(dialog._desc_row)

    return group


def create_dimensions_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the dimensions group (width, height)."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Dimensions"))

    dialog._width_row = Adw.SpinRow.new_with_range(20, 150, 5)
    dialog._width_row.set_title(_("Width (mm)"))
    dialog._width_row.set_value(60)
    dialog._width_row.connect("notify::value", dialog._on_field_changed)
    group.add(dialog._width_row)

    dialog._height_row = Adw.SpinRow.new_with_range(10, 80, 5)
    dialog._height_row.set_title(_("Height (mm)"))
    dialog._height_row.set_value(25)
    dialog._height_row.connect("notify::value", dialog._on_field_changed)
    group.add(dialog._height_row)

    return group


def create_appearance_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the appearance group (colors, border)."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Appearance"))

    bg_row = Adw.ActionRow()
    bg_row.set_title(_("Background color"))
    dialog._bg_color_btn = Gtk.ColorButton()
    dialog._bg_color_btn.set_rgba(Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=1.0))
    dialog._bg_color_btn.set_valign(Gtk.Align.CENTER)
    dialog._bg_color_btn.connect("color-set", dialog._on_field_changed)
    bg_row.add_suffix(dialog._bg_color_btn)
    group.add(bg_row)

    border_row = Adw.ActionRow()
    border_row.set_title(_("Show border"))
    dialog._border_check = Gtk.CheckButton()
    dialog._border_check.set_active(True)
    dialog._border_check.set_valign(Gtk.Align.CENTER)
    dialog._border_check.connect("toggled", dialog._on_field_changed)
    border_row.add_suffix(dialog._border_check)

    dialog._border_color_btn = Gtk.ColorButton()
    dialog._border_color_btn.set_rgba(Gdk.RGBA(red=0.2, green=0.2, blue=0.2, alpha=1.0))
    dialog._border_color_btn.set_valign(Gtk.Align.CENTER)
    dialog._border_color_btn.connect("color-set", dialog._on_field_changed)
    border_row.add_suffix(dialog._border_color_btn)
    group.add(border_row)

    return group


def create_fields_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the dynamic text fields group."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Text Fields"))
    group.set_description(_("Add, remove and reorder text fields"))

    dialog._fields_listbox = Gtk.ListBox()
    dialog._fields_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
    dialog._fields_listbox.add_css_class("boxed-list")

    frame = Gtk.Frame()
    frame.set_child(dialog._fields_listbox)
    group.add(frame)

    add_btn = Gtk.Button()
    add_btn.set_label(_("Add custom text"))
    add_btn.set_icon_name("list-add-symbolic")
    add_btn.add_css_class("pill")
    add_btn.set_tooltip_text(_("Add a custom text line"))
    add_btn.set_margin_top(8)
    add_btn.set_halign(Gtk.Align.CENTER)
    add_btn.connect("clicked", dialog._on_add_field_clicked)
    group.add(add_btn)

    return group


def create_qr_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the QR code group."""
    group = Adw.PreferencesGroup()
    group.set_title(_("QR Code"))
    group.set_description(_("Add a verification QR code to the signature"))

    qr_row = Adw.ActionRow()
    qr_row.set_title(_("Include QR code"))
    qr_row.set_subtitle(_("QR contains document hash for verification"))
    dialog._show_qr_check = Gtk.CheckButton()
    dialog._show_qr_check.set_active(False)
    dialog._show_qr_check.set_valign(Gtk.Align.CENTER)
    dialog._show_qr_check.connect("toggled", dialog._on_qr_toggled)
    qr_row.add_suffix(dialog._show_qr_check)
    group.add(qr_row)

    pos_row = Adw.ActionRow()
    pos_row.set_title(_("QR position"))
    dialog._qr_position_combo = Gtk.ComboBoxText()
    dialog._qr_position_combo.append("left", _("Left side"))
    dialog._qr_position_combo.append("right", _("Right side"))
    dialog._qr_position_combo.set_active_id("left")
    dialog._qr_position_combo.set_valign(Gtk.Align.CENTER)
    dialog._qr_position_combo.connect("changed", dialog._on_field_changed)
    dialog._qr_position_combo.set_sensitive(False)
    pos_row.add_suffix(dialog._qr_position_combo)
    group.add(pos_row)

    return group


def create_preview_group(dialog: TemplateEditorDialog) -> Adw.PreferencesGroup:
    """Create the preview group."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Preview"))

    dialog._preview_frame = Gtk.Frame()
    dialog._preview_frame.add_css_class("view")
    dialog._preview_frame.set_halign(Gtk.Align.CENTER)
    dialog._preview_frame.set_margin_top(8)
    dialog._preview_frame.set_margin_bottom(8)

    placeholder = Gtk.Label(label=_("Loading preview..."))
    placeholder.add_css_class("dim-label")
    placeholder.set_margin_top(20)
    placeholder.set_margin_bottom(20)
    placeholder.set_margin_start(40)
    placeholder.set_margin_end(40)
    dialog._preview_frame.set_child(placeholder)

    group.add(dialog._preview_frame)
    return group


def build_template_from_form(dialog: TemplateEditorDialog) -> Template:
    """Construct a Template object from current form values."""
    layers: list[Layer] = []

    has_qr = dialog._show_qr_check.get_active()
    qr_position = dialog._qr_position_combo.get_active_id() or "left"

    # Background layer
    bg_color = dialog._rgba_to_hex(dialog._bg_color_btn.get_rgba())
    layers.append(Layer(type="background", color=bg_color))

    # Border layer (if enabled)
    if dialog._border_check.get_active():
        border_color = dialog._rgba_to_hex(dialog._border_color_btn.get_rgba())
        layers.append(Layer(type="border", color=border_color, border_width=1))

    # QR layer
    if has_qr:
        if qr_position == "left":
            layers.append(Layer(type="qr", x=3, y=10, width=25, height=80))
        else:
            layers.append(Layer(type="qr", x=72, y=10, width=25, height=80))

    # Calculate text X position based on QR
    if has_qr and qr_position == "left":
        text_x = 32
    elif has_qr and qr_position == "right":
        text_x = 5
    else:
        text_x = 5

    # Text fields from dynamic list
    text_items = [row.get_field_data() for row in dialog._fields]
    text_items = [f for f in text_items if f.is_variable or f.text.strip()]

    if text_items:
        y_positions = _calc_text_positions(len(text_items))
        for i, field_data in enumerate(text_items):
            layers.append(
                Layer(
                    type="text",
                    x=text_x,
                    y=y_positions[i],
                    text=field_data.text,
                    font_size=field_data.font_size,
                    color=field_data.color,
                )
            )

    return Template(
        name=dialog._name_row.get_text().strip(),
        description=dialog._desc_row.get_text().strip(),
        width_mm=dialog._width_row.get_value(),
        height_mm=dialog._height_row.get_value(),
        layers=layers,
    )


def _calc_text_positions(num_items: int) -> list[float]:
    """Calculate evenly distributed Y positions for text items."""
    margin_pct = 10
    available_pct = 100 - (2 * margin_pct)

    if num_items == 1:
        return [margin_pct + available_pct * 0.3]

    spacing = available_pct / (num_items + 0.5)
    return [margin_pct + spacing * (i + 0.5) for i in range(num_items)]


def load_template_values(dialog: TemplateEditorDialog) -> None:
    """Load values from existing template into form fields."""
    template = dialog._edit_template
    if not template:
        return

    dialog._name_row.set_text(template.name)
    dialog._name_row.set_editable(False)
    dialog._desc_row.set_text(template.description or "")

    dialog._width_row.set_value(template.width_mm)
    dialog._height_row.set_value(template.height_mm)

    for layer in template.layers:
        if layer.type == "background" and layer.color:
            dialog._bg_color_btn.set_rgba(dialog._hex_to_rgba(layer.color))
        elif layer.type == "border":
            dialog._border_check.set_active(True)
            if layer.color:
                dialog._border_color_btn.set_rgba(dialog._hex_to_rgba(layer.color))
        elif layer.type == "text":
            text = layer.text or ""
            font_size = layer.font_size or 10
            color = layer.color or "#000000"
            is_variable = text in PREDEFINED_FIELDS
            dialog._add_field(
                FieldData(text=text, font_size=font_size, color=color, is_variable=is_variable)
            )
        elif layer.type == "qr":
            dialog._show_qr_check.set_active(True)
            dialog._qr_position_combo.set_sensitive(True)
            if layer.x and layer.x > 50:
                dialog._qr_position_combo.set_active_id("right")
            else:
                dialog._qr_position_combo.set_active_id("left")

    has_border = any(layer.type == "border" for layer in template.layers)
    if not has_border:
        dialog._border_check.set_active(False)

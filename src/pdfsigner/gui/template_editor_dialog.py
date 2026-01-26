"""
template_editor_dialog.py - Dialog for creating custom signature templates

Author: Homero Thompson del Lago del Terror

Provides a form-based interface for creating custom signature templates
with dynamic field ordering via drag-and-drop style controls.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import dataclass

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk
from loguru import logger

from pdfsigner.core.signature import (
    Layer,
    Template,
    get_builtin_templates_dir,
    render_preview,
    save_user_template,
)
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
        # Main horizontal box
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        main_box.set_margin_top(6)
        main_box.set_margin_bottom(6)
        main_box.set_margin_start(8)
        main_box.set_margin_end(8)

        # Move buttons (up/down)
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

        main_box.append(move_box)

        # Text entry or label
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)
        text_box.set_valign(Gtk.Align.CENTER)

        if self._field_data.is_variable:
            # Show friendly label for variables
            label_text = PREDEFINED_FIELDS.get(self._field_data.text, self._field_data.text)
            self._text_label = Gtk.Label(label=label_text)
            self._text_label.set_halign(Gtk.Align.START)
            self._text_label.add_css_class("heading")
            text_box.append(self._text_label)

            # Show variable name as subtitle
            var_label = Gtk.Label(label=self._field_data.text)
            var_label.set_halign(Gtk.Align.START)
            var_label.add_css_class("dim-label")
            var_label.add_css_class("caption")
            text_box.append(var_label)

            self._text_entry = None
        else:
            # Editable entry for custom text
            self._text_entry = Gtk.Entry()
            self._text_entry.set_text(self._field_data.text)
            self._text_entry.set_placeholder_text(_("Enter custom text..."))
            self._text_entry.set_hexpand(True)
            self._text_entry.connect("changed", self._on_text_changed)
            text_box.append(self._text_entry)

            self._text_label = None

        main_box.append(text_box)

        # Font size spinner
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

        main_box.append(size_box)

        # Color button
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

        main_box.append(color_box)

        # Delete button
        delete_btn = Gtk.Button()
        delete_btn.set_icon_name("user-trash-symbolic")
        delete_btn.add_css_class("flat")
        delete_btn.add_css_class("circular")
        delete_btn.add_css_class("destructive-action")
        delete_btn.set_tooltip_text(_("Remove field"))
        delete_btn.set_valign(Gtk.Align.CENTER)
        delete_btn.connect("clicked", lambda _: self._on_delete(self))
        main_box.append(delete_btn)

        self.set_child(main_box)

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


class TemplateEditorDialog(Adw.Window):
    """
    Dialog for creating custom signature templates.

    Provides a form interface with dynamic field list and live preview.
    """

    def __init__(
        self,
        on_template_created: Callable[[str], None] | None = None,
        edit_template: Template | None = None,
        **kwargs,
    ):
        """
        Initialize the template editor dialog.

        Args:
            on_template_created: Callback when template is saved (receives template name)
            edit_template: Existing template to edit (None for new template)
            **kwargs: Additional arguments passed to Adw.Window
        """
        super().__init__(**kwargs)

        self._on_template_created = on_template_created
        self._edit_template = edit_template
        self._edit_mode = edit_template is not None
        self._debounce_id: int | None = None
        self._fields: list[FieldRow] = []

        title = _("Edit Template") if self._edit_mode else _("Create Custom Template")
        self.set_title(title)
        self.set_default_size(550, 700)
        self.set_modal(True)

        self._setup_ui()

        # Load existing template values if editing
        if self._edit_mode:
            self._load_template_values()
        else:
            # Add default fields for new template
            self._add_default_fields()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        # Header bar with cancel/create buttons
        header = Adw.HeaderBar()

        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda _: self.close())
        header.pack_start(cancel_btn)

        btn_label = _("Save") if self._edit_mode else _("Create")
        self._create_btn = Gtk.Button(label=btn_label)
        self._create_btn.add_css_class("suggested-action")
        self._create_btn.connect("clicked", self._on_create_clicked)
        header.pack_end(self._create_btn)

        # Main layout
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Scrollable content
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        # Main content box
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Add form sections
        content.append(self._create_basic_group())
        content.append(self._create_dimensions_group())
        content.append(self._create_appearance_group())
        content.append(self._create_fields_group())
        content.append(self._create_qr_group())
        content.append(self._create_preview_group())

        scroll.set_child(content)
        toolbar.set_content(scroll)
        self.set_content(toolbar)

        # Initial preview
        GLib.idle_add(self._update_preview)

    def _add_default_fields(self) -> None:
        """Add default fields for a new template."""
        defaults = [
            FieldData(text="{signer_name}", font_size=11, color="#000000", is_variable=True),
            FieldData(text="{date}", font_size=8, color="#888888", is_variable=True),
        ]
        for field_data in defaults:
            self._add_field(field_data)

    def _load_template_values(self) -> None:
        """Load values from existing template into form fields."""
        if not self._edit_template:
            return

        template = self._edit_template

        # Basic info
        self._name_row.set_text(template.name)
        self._name_row.set_editable(False)  # Name is read-only in edit mode
        self._desc_row.set_text(template.description or "")

        # Dimensions
        self._width_row.set_value(template.width_mm)
        self._height_row.set_value(template.height_mm)

        # Parse layers to extract settings
        for layer in template.layers:
            if layer.type == "background" and layer.color:
                self._bg_color_btn.set_rgba(self._hex_to_rgba(layer.color))

            elif layer.type == "border":
                self._border_check.set_active(True)
                if layer.color:
                    self._border_color_btn.set_rgba(self._hex_to_rgba(layer.color))

            elif layer.type == "text":
                text = layer.text or ""
                font_size = layer.font_size or 10
                color = layer.color or "#000000"
                is_variable = text in PREDEFINED_FIELDS

                self._add_field(
                    FieldData(
                        text=text,
                        font_size=font_size,
                        color=color,
                        is_variable=is_variable,
                    )
                )

            elif layer.type == "qr":
                self._show_qr_check.set_active(True)
                self._qr_position_combo.set_sensitive(True)
                if layer.x and layer.x > 50:
                    self._qr_position_combo.set_active_id("right")
                else:
                    self._qr_position_combo.set_active_id("left")

        # If no border layer found, uncheck border
        has_border = any(layer.type == "border" for layer in template.layers)
        if not has_border:
            self._border_check.set_active(False)

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

    def _create_basic_group(self) -> Adw.PreferencesGroup:
        """Create the basic info group (name, description)."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Basic Info"))

        # Name entry
        self._name_row = Adw.EntryRow()
        self._name_row.set_title(_("Name"))
        self._name_row.set_text("my_template")
        self._name_row.connect("changed", self._on_field_changed)
        group.add(self._name_row)

        # Description entry
        self._desc_row = Adw.EntryRow()
        self._desc_row.set_title(_("Description"))
        self._desc_row.set_text(_("Custom signature template"))
        self._desc_row.connect("changed", self._on_field_changed)
        group.add(self._desc_row)

        return group

    def _create_dimensions_group(self) -> Adw.PreferencesGroup:
        """Create the dimensions group (width, height)."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Dimensions"))

        # Width spinner
        self._width_row = Adw.SpinRow.new_with_range(20, 150, 5)
        self._width_row.set_title(_("Width (mm)"))
        self._width_row.set_value(60)
        self._width_row.connect("notify::value", self._on_field_changed)
        group.add(self._width_row)

        # Height spinner
        self._height_row = Adw.SpinRow.new_with_range(10, 80, 5)
        self._height_row.set_title(_("Height (mm)"))
        self._height_row.set_value(25)
        self._height_row.connect("notify::value", self._on_field_changed)
        group.add(self._height_row)

        return group

    def _create_appearance_group(self) -> Adw.PreferencesGroup:
        """Create the appearance group (colors, border)."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Appearance"))

        # Background color
        bg_row = Adw.ActionRow()
        bg_row.set_title(_("Background color"))

        self._bg_color_btn = Gtk.ColorButton()
        self._bg_color_btn.set_rgba(Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=1.0))
        self._bg_color_btn.set_valign(Gtk.Align.CENTER)
        self._bg_color_btn.connect("color-set", self._on_field_changed)
        bg_row.add_suffix(self._bg_color_btn)
        group.add(bg_row)

        # Border toggle and color
        border_row = Adw.ActionRow()
        border_row.set_title(_("Show border"))

        self._border_check = Gtk.CheckButton()
        self._border_check.set_active(True)
        self._border_check.set_valign(Gtk.Align.CENTER)
        self._border_check.connect("toggled", self._on_field_changed)
        border_row.add_suffix(self._border_check)

        self._border_color_btn = Gtk.ColorButton()
        self._border_color_btn.set_rgba(Gdk.RGBA(red=0.2, green=0.2, blue=0.2, alpha=1.0))
        self._border_color_btn.set_valign(Gtk.Align.CENTER)
        self._border_color_btn.connect("color-set", self._on_field_changed)
        border_row.add_suffix(self._border_color_btn)
        group.add(border_row)

        return group

    def _create_fields_group(self) -> Adw.PreferencesGroup:
        """Create the dynamic text fields group."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Text Fields"))
        group.set_description(_("Add, remove and reorder text fields"))

        # ListBox for fields
        self._fields_listbox = Gtk.ListBox()
        self._fields_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self._fields_listbox.add_css_class("boxed-list")

        # Frame for listbox
        frame = Gtk.Frame()
        frame.set_child(self._fields_listbox)
        group.add(frame)

        # Add custom text button
        add_btn = Gtk.Button()
        add_btn.set_label(_("Add custom text"))
        add_btn.set_icon_name("list-add-symbolic")
        add_btn.add_css_class("pill")
        add_btn.set_tooltip_text(_("Add a custom text line"))
        add_btn.set_margin_top(8)
        add_btn.set_halign(Gtk.Align.CENTER)
        add_btn.connect("clicked", self._on_add_field_clicked)
        group.add(add_btn)

        return group

    def _add_field(self, field_data: FieldData) -> None:
        """Add a field to the list."""
        row = FieldRow(
            field_data=field_data,
            on_changed=self._on_field_changed,
            on_delete=self._on_delete_field,
            on_move_up=self._on_move_field_up,
            on_move_down=self._on_move_field_down,
        )
        self._fields.append(row)
        self._fields_listbox.append(row)
        self._update_move_buttons()
        self._on_field_changed()

    def _on_add_field_clicked(self, _button: Gtk.Button) -> None:
        """Handle add field button click - adds a custom text field."""
        field_data = FieldData(
            text="",
            font_size=10,
            color="#333333",
            is_variable=False,
        )
        self._add_field(field_data)

    def _on_delete_field(self, row: FieldRow) -> None:
        """Handle field deletion."""
        if row in self._fields:
            self._fields.remove(row)
            self._fields_listbox.remove(row)
            self._update_move_buttons()
            self._on_field_changed()

    def _on_move_field_up(self, row: FieldRow) -> None:
        """Move field up in the list."""
        if row not in self._fields:
            return

        idx = self._fields.index(row)
        if idx > 0:
            # Swap in our list
            self._fields[idx], self._fields[idx - 1] = self._fields[idx - 1], self._fields[idx]
            # Rebuild listbox
            self._rebuild_listbox()
            self._on_field_changed()

    def _on_move_field_down(self, row: FieldRow) -> None:
        """Move field down in the list."""
        if row not in self._fields:
            return

        idx = self._fields.index(row)
        if idx < len(self._fields) - 1:
            # Swap in our list
            self._fields[idx], self._fields[idx + 1] = self._fields[idx + 1], self._fields[idx]
            # Rebuild listbox
            self._rebuild_listbox()
            self._on_field_changed()

    def _rebuild_listbox(self) -> None:
        """Rebuild the listbox from fields list."""
        # Remove all children
        while True:
            child = self._fields_listbox.get_first_child()
            if child is None:
                break
            self._fields_listbox.remove(child)

        # Re-add in order
        for row in self._fields:
            self._fields_listbox.append(row)

        self._update_move_buttons()

    def _update_move_buttons(self) -> None:
        """Update move button sensitivity for all rows."""
        num_fields = len(self._fields)
        for i, row in enumerate(self._fields):
            row.update_move_buttons(
                can_move_up=(i > 0),
                can_move_down=(i < num_fields - 1),
            )

    def _create_qr_group(self) -> Adw.PreferencesGroup:
        """Create the QR code group."""
        group = Adw.PreferencesGroup()
        group.set_title(_("QR Code"))
        group.set_description(_("Add a verification QR code to the signature"))

        # QR enable row
        qr_row = Adw.ActionRow()
        qr_row.set_title(_("Include QR code"))
        qr_row.set_subtitle(_("QR contains document hash for verification"))

        self._show_qr_check = Gtk.CheckButton()
        self._show_qr_check.set_active(False)
        self._show_qr_check.set_valign(Gtk.Align.CENTER)
        self._show_qr_check.connect("toggled", self._on_qr_toggled)
        qr_row.add_suffix(self._show_qr_check)
        group.add(qr_row)

        # QR position row
        pos_row = Adw.ActionRow()
        pos_row.set_title(_("QR position"))

        self._qr_position_combo = Gtk.ComboBoxText()
        self._qr_position_combo.append("left", _("Left side"))
        self._qr_position_combo.append("right", _("Right side"))
        self._qr_position_combo.set_active_id("left")
        self._qr_position_combo.set_valign(Gtk.Align.CENTER)
        self._qr_position_combo.connect("changed", self._on_field_changed)
        self._qr_position_combo.set_sensitive(False)  # Disabled until QR enabled
        pos_row.add_suffix(self._qr_position_combo)
        group.add(pos_row)

        return group

    def _on_qr_toggled(self, check: Gtk.CheckButton) -> None:
        """Handle QR checkbox toggle."""
        is_active = check.get_active()
        self._qr_position_combo.set_sensitive(is_active)

        # Adjust dimensions for QR (needs more width)
        if is_active:
            current_width = self._width_row.get_value()
            if current_width < 70:
                self._width_row.set_value(70)

        self._on_field_changed()

    def _create_preview_group(self) -> Adw.PreferencesGroup:
        """Create the preview group."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Preview"))

        # Preview frame
        self._preview_frame = Gtk.Frame()
        self._preview_frame.add_css_class("view")
        self._preview_frame.set_halign(Gtk.Align.CENTER)
        self._preview_frame.set_margin_top(8)
        self._preview_frame.set_margin_bottom(8)

        # Placeholder
        placeholder = Gtk.Label(label=_("Loading preview..."))
        placeholder.add_css_class("dim-label")
        placeholder.set_margin_top(20)
        placeholder.set_margin_bottom(20)
        placeholder.set_margin_start(40)
        placeholder.set_margin_end(40)
        self._preview_frame.set_child(placeholder)

        group.add(self._preview_frame)

        return group

    def _on_field_changed(self, *_args) -> None:
        """Handle any form field change with debounce."""
        # Cancel previous scheduled update
        if self._debounce_id is not None:
            GLib.source_remove(self._debounce_id)

        # Schedule preview update after 300ms
        self._debounce_id = GLib.timeout_add(300, self._update_preview)

    def _update_preview(self) -> bool:
        """Update the preview image from current form values."""
        self._debounce_id = None

        try:
            template = self._build_template_from_form()
            templates_dir = get_builtin_templates_dir()
            preview_img = render_preview(template, width_px=300, templates_dir=templates_dir)

            # Convert PIL Image to Gtk.Picture
            buffer = io.BytesIO()
            preview_img.save(buffer, format="PNG")
            png_data = buffer.getvalue()

            gbytes = GLib.Bytes.new(png_data)
            texture = Gdk.Texture.new_from_bytes(gbytes)

            picture = Gtk.Picture.new_for_paintable(texture)
            picture.set_content_fit(Gtk.ContentFit.CONTAIN)
            picture.set_size_request(300, texture.get_height())
            picture.set_can_shrink(False)

            self._preview_frame.set_child(picture)

        except Exception as e:
            logger.error(f"Failed to update preview: {e}")
            error_label = Gtk.Label(label=_("Preview error"))
            error_label.add_css_class("dim-label")
            self._preview_frame.set_child(error_label)

        return False  # Don't repeat

    def _rgba_to_hex(self, rgba: Gdk.RGBA) -> str:
        """Convert Gdk.RGBA to hex color string."""
        r = int(rgba.red * 255)
        g = int(rgba.green * 255)
        b = int(rgba.blue * 255)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _build_template_from_form(self) -> Template:
        """Construct a Template object from current form values."""
        layers: list[Layer] = []

        # Check if QR is enabled and its position
        has_qr = self._show_qr_check.get_active()
        qr_position = self._qr_position_combo.get_active_id() or "left"

        # Background layer
        bg_color = self._rgba_to_hex(self._bg_color_btn.get_rgba())
        layers.append(Layer(type="background", color=bg_color))

        # Border layer (if enabled)
        if self._border_check.get_active():
            border_color = self._rgba_to_hex(self._border_color_btn.get_rgba())
            layers.append(Layer(type="border", color=border_color, border_width=1))

        # Add QR layer if enabled
        if has_qr:
            if qr_position == "left":
                layers.append(Layer(type="qr", x=3, y=10, width=25, height=80))
            else:  # right
                layers.append(Layer(type="qr", x=72, y=10, width=25, height=80))

        # Calculate text X position based on QR
        if has_qr and qr_position == "left":
            text_x = 32  # After QR on left
        elif has_qr and qr_position == "right":
            text_x = 5  # Before QR on right
        else:
            text_x = 5  # No QR, start from left

        # Get text fields from dynamic list
        text_items = [row.get_field_data() for row in self._fields]

        # Filter out empty custom texts
        text_items = [f for f in text_items if f.is_variable or f.text.strip()]

        # Calculate dynamic Y positions based on content
        if text_items:
            num_items = len(text_items)

            # Available space (leave margins top/bottom)
            margin_pct = 10  # 10% margin top and bottom
            available_pct = 100 - (2 * margin_pct)

            # Calculate spacing between lines
            if num_items == 1:
                # Single item: center vertically
                y_positions = [margin_pct + available_pct * 0.3]
            else:
                # Multiple items: distribute evenly
                spacing = available_pct / (num_items + 0.5)
                y_positions = [margin_pct + spacing * (i + 0.5) for i in range(num_items)]

            # Add text layers with calculated positions
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
            name=self._name_row.get_text().strip(),
            description=self._desc_row.get_text().strip(),
            width_mm=self._width_row.get_value(),
            height_mm=self._height_row.get_value(),
            layers=layers,
        )

    def _on_create_clicked(self, _button: Gtk.Button) -> None:
        """Handle create button click."""
        template = self._build_template_from_form()

        # Validate template
        errors = template.validate()
        if errors:
            self._show_error_toast(errors[0])
            return

        # Validate name format (no spaces, special chars)
        name = template.name
        if not name:
            self._show_error_toast(_("Template name is required"))
            return

        if " " in name or not name.replace("_", "").replace("-", "").isalnum():
            self._show_error_toast(
                _("Name must contain only letters, numbers, underscores or hyphens")
            )
            return

        # Save template
        try:
            save_user_template(template)
            logger.info(f"Saved template: {template.name}")

            if self._on_template_created:
                self._on_template_created(template.name)

            self.close()

        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            self._show_error_toast(_("Failed to save template"))

    def _show_error_toast(self, message: str) -> None:
        """Show an error message to the user."""
        toast = Adw.Toast.new(message)
        toast.set_timeout(3)

        # Try to find toast overlay in parent hierarchy
        parent = self.get_transient_for()
        if parent and hasattr(parent, "get_content"):
            content = parent.get_content()
            if isinstance(content, Adw.ToastOverlay):
                content.add_toast(toast)
                return

        # Fallback: show in dialog title temporarily
        original_title = self.get_title()
        self.set_title(f"Error: {message}")
        GLib.timeout_add(3000, lambda: self.set_title(original_title) or False)

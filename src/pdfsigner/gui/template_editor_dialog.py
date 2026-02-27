"""
template_editor_dialog.py - Dialog for creating custom signature templates

Provides a form-based interface for creating custom signature templates
with dynamic field ordering via drag-and-drop style controls.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk
from loguru import logger

from pdfsigner.core.signature import (
    Template,
    get_builtin_templates_dir,
    render_preview,
    save_user_template,
)
from pdfsigner.gui.template_field_row import (  # noqa: F401 - re-exported for backward compat
    PREDEFINED_FIELDS,
    FieldData,
    FieldRow,
)
from pdfsigner.gui.template_form_builder import (
    build_template_from_form,
    create_appearance_group,
    create_basic_group,
    create_dimensions_group,
    create_fields_group,
    create_preview_group,
    create_qr_group,
    load_template_values,
)
from pdfsigner.i18n import _


class TemplateEditorDialog(Adw.Window):
    """Dialog for creating custom signature templates with live preview."""

    def __init__(
        self,
        on_template_created: Callable[[str], None] | None = None,
        edit_template: Template | None = None,
        **kwargs,
    ):
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

        if self._edit_mode:
            load_template_values(self)
        else:
            self._add_default_fields()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        header = Adw.HeaderBar()

        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda _: self.close())
        header.pack_start(cancel_btn)

        btn_label = _("Save") if self._edit_mode else _("Create")
        self._create_btn = Gtk.Button(label=btn_label)
        self._create_btn.add_css_class("suggested-action")
        self._create_btn.connect("clicked", self._on_create_clicked)
        header.pack_end(self._create_btn)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Form sections built by template_form_builder
        content.append(create_basic_group(self))
        content.append(create_dimensions_group(self))
        content.append(create_appearance_group(self))
        content.append(create_fields_group(self))
        content.append(create_qr_group(self))
        content.append(create_preview_group(self))

        scroll.set_child(content)
        toolbar.set_content(scroll)
        self.set_content(toolbar)

        GLib.idle_add(self._update_preview)

    def _add_default_fields(self) -> None:
        """Add default fields for a new template."""
        defaults = [
            FieldData(text="{signer_name}", font_size=11, color="#000000", is_variable=True),
            FieldData(text="{date}", font_size=8, color="#888888", is_variable=True),
        ]
        for field_data in defaults:
            self._add_field(field_data)

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
        """Handle add field button click."""
        self._add_field(FieldData(text="", font_size=10, color="#333333", is_variable=False))

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
            self._fields[idx], self._fields[idx - 1] = self._fields[idx - 1], self._fields[idx]
            self._rebuild_listbox()
            self._on_field_changed()

    def _on_move_field_down(self, row: FieldRow) -> None:
        """Move field down in the list."""
        if row not in self._fields:
            return
        idx = self._fields.index(row)
        if idx < len(self._fields) - 1:
            self._fields[idx], self._fields[idx + 1] = self._fields[idx + 1], self._fields[idx]
            self._rebuild_listbox()
            self._on_field_changed()

    def _rebuild_listbox(self) -> None:
        """Rebuild the listbox from fields list."""
        while True:
            child = self._fields_listbox.get_first_child()
            if child is None:
                break
            self._fields_listbox.remove(child)
        for row in self._fields:
            self._fields_listbox.append(row)
        self._update_move_buttons()

    def _update_move_buttons(self) -> None:
        """Update move button sensitivity for all rows."""
        num_fields = len(self._fields)
        for i, row in enumerate(self._fields):
            row.update_move_buttons(can_move_up=(i > 0), can_move_down=(i < num_fields - 1))

    def _on_qr_toggled(self, check: Gtk.CheckButton) -> None:
        """Handle QR checkbox toggle."""
        is_active = check.get_active()
        self._qr_position_combo.set_sensitive(is_active)
        if is_active and self._width_row.get_value() < 70:
            self._width_row.set_value(70)
        self._on_field_changed()

    def _on_field_changed(self, *_args) -> None:
        """Handle any form field change with debounce."""
        if self._debounce_id is not None:
            GLib.source_remove(self._debounce_id)
        self._debounce_id = GLib.timeout_add(300, self._update_preview)

    def _update_preview(self) -> bool:
        """Update the preview image from current form values."""
        self._debounce_id = None
        try:
            template = build_template_from_form(self)
            templates_dir = get_builtin_templates_dir()
            preview_img = render_preview(template, width_px=300, templates_dir=templates_dir)

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

        return False

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

    def _on_create_clicked(self, _button: Gtk.Button) -> None:
        """Handle create button click."""
        template = build_template_from_form(self)

        errors = template.validate()
        if errors:
            self._show_error_toast(errors[0])
            return

        name = template.name
        if not name:
            self._show_error_toast(_("Template name is required"))
            return

        if " " in name or not name.replace("_", "").replace("-", "").isalnum():
            self._show_error_toast(
                _("Name must contain only letters, numbers, underscores or hyphens")
            )
            return

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

        parent = self.get_transient_for()
        if parent and hasattr(parent, "get_content"):
            content = parent.get_content()
            if isinstance(content, Adw.ToastOverlay):
                content.add_toast(toast)
                return

        original_title = self.get_title()
        self.set_title(f"Error: {message}")
        GLib.timeout_add(3000, lambda: self.set_title(original_title) or False)

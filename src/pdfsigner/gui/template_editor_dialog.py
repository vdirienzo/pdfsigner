"""
template_editor_dialog.py - Dialog for creating custom signature templates

Author: Homero Thompson del Lago del Terror

Provides a form-based interface for creating custom signature templates
without manual JSON editing.
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
    Layer,
    Template,
    get_builtin_templates_dir,
    render_preview,
    save_user_template,
)
from pdfsigner.i18n import _


class TemplateEditorDialog(Adw.Window):
    """
    Dialog for creating custom signature templates.

    Provides a simplified form interface with live preview
    instead of requiring users to edit JSON manually.
    """

    def __init__(
        self,
        on_template_created: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """
        Initialize the template editor dialog.

        Args:
            on_template_created: Callback when template is saved (receives template name)
            **kwargs: Additional arguments passed to Adw.Window
        """
        super().__init__(**kwargs)

        self._on_template_created = on_template_created
        self._debounce_id: int | None = None

        self.set_title(_("Create Custom Template"))
        self.set_default_size(500, 650)
        self.set_modal(True)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        # Header bar with cancel/create buttons
        header = Adw.HeaderBar()

        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda _: self.close())
        header.pack_start(cancel_btn)

        self._create_btn = Gtk.Button(label=_("Create"))
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
        content.append(self._create_content_group())
        content.append(self._create_preview_group())

        scroll.set_child(content)
        toolbar.set_content(scroll)
        self.set_content(toolbar)

        # Initial preview
        GLib.idle_add(self._update_preview)

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

    def _create_content_group(self) -> Adw.PreferencesGroup:
        """Create the content group (name, org, date visibility)."""
        group = Adw.PreferencesGroup()
        group.set_title(_("Content"))
        group.set_description(_("Select what information to show"))

        # Signer name row
        name_row = Adw.ActionRow()
        name_row.set_title(_("Signer name"))

        self._show_name_check = Gtk.CheckButton()
        self._show_name_check.set_active(True)
        self._show_name_check.set_valign(Gtk.Align.CENTER)
        self._show_name_check.connect("toggled", self._on_field_changed)
        name_row.add_suffix(self._show_name_check)

        self._name_font_spin = Gtk.SpinButton.new_with_range(8, 18, 1)
        self._name_font_spin.set_value(11)
        self._name_font_spin.set_valign(Gtk.Align.CENTER)
        self._name_font_spin.set_tooltip_text(_("Font size"))
        self._name_font_spin.connect("value-changed", self._on_field_changed)
        name_row.add_suffix(self._name_font_spin)

        self._name_color_btn = Gtk.ColorButton()
        self._name_color_btn.set_rgba(Gdk.RGBA(red=0.0, green=0.0, blue=0.0, alpha=1.0))
        self._name_color_btn.set_valign(Gtk.Align.CENTER)
        self._name_color_btn.connect("color-set", self._on_field_changed)
        name_row.add_suffix(self._name_color_btn)
        group.add(name_row)

        # Organization row
        org_row = Adw.ActionRow()
        org_row.set_title(_("Organization"))

        self._show_org_check = Gtk.CheckButton()
        self._show_org_check.set_active(True)
        self._show_org_check.set_valign(Gtk.Align.CENTER)
        self._show_org_check.connect("toggled", self._on_field_changed)
        org_row.add_suffix(self._show_org_check)

        self._org_font_spin = Gtk.SpinButton.new_with_range(8, 18, 1)
        self._org_font_spin.set_value(9)
        self._org_font_spin.set_valign(Gtk.Align.CENTER)
        self._org_font_spin.set_tooltip_text(_("Font size"))
        self._org_font_spin.connect("value-changed", self._on_field_changed)
        org_row.add_suffix(self._org_font_spin)

        self._org_color_btn = Gtk.ColorButton()
        self._org_color_btn.set_rgba(Gdk.RGBA(red=0.4, green=0.4, blue=0.4, alpha=1.0))
        self._org_color_btn.set_valign(Gtk.Align.CENTER)
        self._org_color_btn.connect("color-set", self._on_field_changed)
        org_row.add_suffix(self._org_color_btn)
        group.add(org_row)

        # Date row
        date_row = Adw.ActionRow()
        date_row.set_title(_("Date"))

        self._show_date_check = Gtk.CheckButton()
        self._show_date_check.set_active(True)
        self._show_date_check.set_valign(Gtk.Align.CENTER)
        self._show_date_check.connect("toggled", self._on_field_changed)
        date_row.add_suffix(self._show_date_check)

        self._date_font_spin = Gtk.SpinButton.new_with_range(8, 18, 1)
        self._date_font_spin.set_value(8)
        self._date_font_spin.set_valign(Gtk.Align.CENTER)
        self._date_font_spin.set_tooltip_text(_("Font size"))
        self._date_font_spin.connect("value-changed", self._on_field_changed)
        date_row.add_suffix(self._date_font_spin)

        self._date_color_btn = Gtk.ColorButton()
        self._date_color_btn.set_rgba(Gdk.RGBA(red=0.5, green=0.5, blue=0.5, alpha=1.0))
        self._date_color_btn.set_valign(Gtk.Align.CENTER)
        self._date_color_btn.connect("color-set", self._on_field_changed)
        date_row.add_suffix(self._date_color_btn)
        group.add(date_row)

        # Custom text row
        custom_row = Adw.ActionRow()
        custom_row.set_title(_("Custom text"))
        custom_row.set_subtitle(_("Additional text (e.g., 'Approved', 'Reviewed')"))

        self._show_custom_check = Gtk.CheckButton()
        self._show_custom_check.set_active(False)
        self._show_custom_check.set_valign(Gtk.Align.CENTER)
        self._show_custom_check.connect("toggled", self._on_field_changed)
        custom_row.add_suffix(self._show_custom_check)

        self._custom_font_spin = Gtk.SpinButton.new_with_range(8, 18, 1)
        self._custom_font_spin.set_value(9)
        self._custom_font_spin.set_valign(Gtk.Align.CENTER)
        self._custom_font_spin.set_tooltip_text(_("Font size"))
        self._custom_font_spin.connect("value-changed", self._on_field_changed)
        custom_row.add_suffix(self._custom_font_spin)

        self._custom_color_btn = Gtk.ColorButton()
        self._custom_color_btn.set_rgba(Gdk.RGBA(red=0.3, green=0.3, blue=0.3, alpha=1.0))
        self._custom_color_btn.set_valign(Gtk.Align.CENTER)
        self._custom_color_btn.connect("color-set", self._on_field_changed)
        custom_row.add_suffix(self._custom_color_btn)
        group.add(custom_row)

        # Custom text entry
        self._custom_text_row = Adw.EntryRow()
        self._custom_text_row.set_title(_("Text"))
        self._custom_text_row.set_text("")
        self._custom_text_row.connect("changed", self._on_field_changed)
        group.add(self._custom_text_row)

        return group

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

        # Background layer
        bg_color = self._rgba_to_hex(self._bg_color_btn.get_rgba())
        layers.append(Layer(type="background", color=bg_color))

        # Border layer (if enabled)
        if self._border_check.get_active():
            border_color = self._rgba_to_hex(self._border_color_btn.get_rgba())
            layers.append(Layer(type="border", color=border_color, border_width=1))

        # Collect text items with their font sizes
        text_items: list[tuple[str, int, str]] = []  # (text, font_size, color)

        if self._show_name_check.get_active():
            text_items.append(
                (
                    "{signer_name}",
                    int(self._name_font_spin.get_value()),
                    self._rgba_to_hex(self._name_color_btn.get_rgba()),
                )
            )

        if self._show_org_check.get_active():
            text_items.append(
                (
                    "{org}",
                    int(self._org_font_spin.get_value()),
                    self._rgba_to_hex(self._org_color_btn.get_rgba()),
                )
            )

        if self._show_date_check.get_active():
            text_items.append(
                (
                    "{date}",
                    int(self._date_font_spin.get_value()),
                    self._rgba_to_hex(self._date_color_btn.get_rgba()),
                )
            )

        if self._show_custom_check.get_active():
            custom_text = self._custom_text_row.get_text().strip()
            if custom_text:
                text_items.append(
                    (
                        custom_text,
                        int(self._custom_font_spin.get_value()),
                        self._rgba_to_hex(self._custom_color_btn.get_rgba()),
                    )
                )

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
            for i, (text, font_size, color) in enumerate(text_items):
                layers.append(
                    Layer(
                        type="text",
                        x=5,
                        y=y_positions[i],
                        text=text,
                        font_size=font_size,
                        color=color,
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
            logger.info(f"Created custom template: {template.name}")

            if self._on_template_created:
                self._on_template_created(template.name)

            self.close()

        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            self._show_error_toast(_("Failed to save template"))

    def _show_error_toast(self, message: str) -> None:
        """Show an error message to the user."""
        # Find the parent window's toast overlay or create inline error
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

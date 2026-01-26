"""
signature_page.py - Visible signature settings page

Author: Homero Thompson del Lago del Terror

Creates the visible signature appearance settings page with template selection.
"""

import io

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk

from pdfsigner.i18n import _


def _get_template_choices() -> list[tuple[str, str]]:
    """
    Get available template choices for dropdown.

    Template selection determines visibility:
    - "" (empty) = Invisible signature
    - Any template = Visible signature with that template

    Returns:
        List of (value, display_name) tuples
    """
    try:
        from pdfsigner.core.signature import list_all_templates

        templates = list_all_templates()
    except ImportError:
        templates = []

    # Start with "invisible" option (no stamp)
    choices = [("", _("Invisible (metadata only)"))]

    # Add builtin templates with friendly names
    template_labels = {
        "default": _("Default (simple text)"),
        "corporate": _("Corporate"),
        "minimal": _("Minimal"),
        "with_qr": _("With QR Code"),
    }

    for name, source in templates:
        label = template_labels.get(name, name.replace("_", " ").title())
        if source == "user":
            label = f"{label} ({_('custom')})"
        choices.append((name, label))

    return choices


def _create_preview_image(template_name: str, width: int = 300) -> Gtk.Picture | None:
    """
    Create a preview image widget for a template.

    Args:
        template_name: Name of template to preview
        width: Preview width in pixels

    Returns:
        Gtk.Picture widget or None if preview fails
    """
    from loguru import logger

    if not template_name:
        logger.debug("No template name provided for preview")
        return None

    try:
        from pdfsigner.core.signature import (
            get_builtin_templates_dir,
            load_template,
            render_preview,
        )

        template = load_template(template_name)
        if not template:
            logger.warning(f"Template not found: {template_name}")
            return None

        templates_dir = get_builtin_templates_dir()
        logger.debug(f"Rendering preview for template: {template_name}")
        preview_img = render_preview(template, width_px=width, templates_dir=templates_dir)

        # Convert PIL Image to Gdk.Texture (native GTK4 approach)
        buffer = io.BytesIO()
        preview_img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        # Create texture from PNG bytes
        gbytes = GLib.Bytes.new(png_data)
        texture = Gdk.Texture.new_from_bytes(gbytes)

        # Calculate height from texture dimensions
        height = texture.get_height()

        picture = Gtk.Picture.new_for_paintable(texture)
        picture.set_content_fit(Gtk.ContentFit.CONTAIN)
        picture.set_size_request(width, height)
        picture.set_can_shrink(False)

        logger.debug(f"Preview created successfully: {width}x{height}")
        return picture

    except Exception as e:
        logger.error(f"Failed to create preview for '{template_name}': {e}")
        import traceback

        logger.debug(traceback.format_exc())
        return None


def create_signature_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the visible signature settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for storing widget references

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Visible Signature"))
    page.set_icon_name("edit-symbolic")

    # --- Template Group ---
    template_group = Adw.PreferencesGroup()
    template_group.set_title(_("Signature Template"))
    template_group.set_description(_("Choose a visual style for the signature stamp"))

    # Template dropdown with create button
    template_combo = Adw.ComboRow()
    template_combo.set_title(_("Template"))

    choices = _get_template_choices()
    template_model = Gtk.StringList.new([c[1] for c in choices])
    template_combo.set_model(template_model)

    # Find current selection
    current_template = settings.signature_template or ""
    selected_idx = 0
    for i, (value, label) in enumerate(choices):
        if value == current_template:
            selected_idx = i
            break
    template_combo.set_selected(selected_idx)

    # Store choices values for saving
    dialog._template_choices = [c[0] for c in choices]

    # Create custom template button
    create_btn = Gtk.Button()
    create_btn.set_icon_name("list-add-symbolic")
    create_btn.set_tooltip_text(_("Create custom template"))
    create_btn.set_valign(Gtk.Align.CENTER)
    create_btn.add_css_class("flat")

    def _on_create_template_clicked(_button):
        """Open template editor dialog."""
        from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog

        def _on_template_created(name: str):
            """Refresh dropdown when new template is created."""
            # Rebuild choices
            new_choices = _get_template_choices()
            new_model = Gtk.StringList.new([c[1] for c in new_choices])
            template_combo.set_model(new_model)
            dialog._template_choices = [c[0] for c in new_choices]

            # Select the newly created template
            for i, (value, _label) in enumerate(new_choices):
                if value == name:
                    template_combo.set_selected(i)
                    break

            # Update preview
            preview = _create_preview_image(name)
            if preview:
                preview_frame.set_child(preview)

        editor = TemplateEditorDialog(on_template_created=_on_template_created)
        editor.set_transient_for(dialog)
        editor.present()

    create_btn.connect("clicked", _on_create_template_clicked)
    template_combo.add_suffix(create_btn)

    template_group.add(template_combo)

    # Preview container
    preview_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    preview_box.set_margin_top(12)
    preview_box.set_margin_bottom(12)
    preview_box.set_margin_start(12)
    preview_box.set_margin_end(12)
    preview_box.set_halign(Gtk.Align.CENTER)

    preview_label = Gtk.Label(label=_("Preview"))
    preview_label.add_css_class("dim-label")
    preview_box.append(preview_label)

    # Preview image frame
    preview_frame = Gtk.Frame()
    preview_frame.add_css_class("view")
    preview_frame.set_halign(Gtk.Align.CENTER)
    preview_frame.set_size_request(300, -1)  # Minimum width

    # Initial preview
    preview_picture = _create_preview_image(current_template)
    if preview_picture:
        preview_frame.set_child(preview_picture)
        preview_box.append(preview_frame)
    else:
        # Show placeholder for default
        placeholder = Gtk.Label(label=_("Text-only signature stamp"))
        placeholder.add_css_class("dim-label")
        placeholder.set_margin_top(20)
        placeholder.set_margin_bottom(20)
        placeholder.set_margin_start(40)
        placeholder.set_margin_end(40)
        preview_frame.set_child(placeholder)
        preview_box.append(preview_frame)

    template_group.add(preview_box)

    # Connect preview update
    def on_template_changed(combo, _pspec):
        idx = combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        preview = _create_preview_image(template_name)
        if preview:
            preview_frame.set_child(preview)
        else:
            placeholder = Gtk.Label(label=_("Text-only signature stamp"))
            placeholder.add_css_class("dim-label")
            placeholder.set_margin_top(20)
            placeholder.set_margin_bottom(20)
            placeholder.set_margin_start(40)
            placeholder.set_margin_end(40)
            preview_frame.set_child(placeholder)

    template_combo.connect("notify::selected", on_template_changed)

    # Default page for visible signatures
    page_combo = Adw.ComboRow()
    page_combo.set_title(_("Default page"))
    page_combo.set_subtitle(_("Page where visible signature appears"))
    pages = Gtk.StringList.new([_("Last page"), _("First page")])
    page_combo.set_model(pages)
    page_combo.set_selected(0 if settings.default_page == "last" else 1)
    template_group.add(page_combo)

    page.add(template_group)

    # --- Output Group ---
    output_group = Adw.PreferencesGroup()
    output_group.set_title(_("Output files"))

    # Suffix
    suffix_row = Adw.EntryRow()
    suffix_row.set_title(_("Suffix for signed files"))
    suffix_row.set_text(settings.output_suffix)
    suffix_row.set_show_apply_button(True)
    output_group.add(suffix_row)

    page.add(output_group)

    # Store references for saving
    dialog.template_combo = template_combo
    dialog.page_combo = page_combo
    dialog.suffix_row = suffix_row

    return page

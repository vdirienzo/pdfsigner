"""
signature_page.py - Visible signature settings page

Creates the visible signature appearance settings page with template selection.
"""

import io

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.gui.settings_pages.signature_template_actions import (
    build_create_template_button,
    build_delete_template_button,
    build_edit_template_button,
    build_import_template_button,
    connect_edit_delete_visibility,
    connect_preview_update,
)
from pdfsigner.i18n import _


def _get_template_choices() -> list[tuple[str, str]]:
    """Get available template choices for dropdown."""
    try:
        from pdfsigner.core.signature import list_all_templates

        templates = list_all_templates()
    except ImportError:
        templates = []

    choices = [("", _("Invisible (metadata only)"))]

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
    """Create a preview image widget for a template."""
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
        preview_img = render_preview(template, width_px=width, templates_dir=templates_dir)

        buffer = io.BytesIO()
        preview_img.save(buffer, format="PNG")
        gbytes = GLib.Bytes.new(buffer.getvalue())
        texture = Gdk.Texture.new_from_bytes(gbytes)

        picture = Gtk.Picture.new_for_paintable(texture)
        picture.set_content_fit(Gtk.ContentFit.CONTAIN)
        picture.set_size_request(width, texture.get_height())
        picture.set_can_shrink(False)
        return picture

    except Exception as e:
        logger.error(f"Failed to create preview for '{template_name}': {e}")
        import traceback

        logger.debug(traceback.format_exc())
        return None


def _build_template_combo(settings, dialog) -> tuple[Adw.ComboRow, str]:
    """Build the template dropdown combo row and return current template name."""
    template_combo = Adw.ComboRow()
    template_combo.set_title(_("Template"))
    set_accessible(template_combo, _("Signature template"), _("Select signature stamp template"))

    choices = _get_template_choices()
    template_model = Gtk.StringList.new([c[1] for c in choices])
    template_combo.set_model(template_model)

    current_template = settings.signature_template or ""
    selected_idx = 0
    for i, (value, label) in enumerate(choices):
        if value == current_template:
            selected_idx = i
            break
    template_combo.set_selected(selected_idx)

    dialog._template_choices = [c[0] for c in choices]
    return template_combo, current_template


def _build_page_combo(settings) -> Adw.ComboRow:
    """Build the default page selection combo row."""
    page_combo = Adw.ComboRow()
    page_combo.set_title(_("Default page"))
    page_combo.set_subtitle(_("Page where visible signature appears"))
    set_accessible(page_combo, _("Default page"), _("Select default page for signature"))
    pages = Gtk.StringList.new([_("Last page"), _("First page")])
    page_combo.set_model(pages)
    page_combo.set_selected(0 if settings.default_page == "last" else 1)
    return page_combo


def _build_preview_box(current_template: str, preview_frame: Gtk.Frame) -> Gtk.Box:
    """Build the template preview container with initial preview."""
    preview_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    preview_box.set_margin_top(12)
    preview_box.set_margin_bottom(12)
    preview_box.set_margin_start(12)
    preview_box.set_margin_end(12)
    preview_box.set_halign(Gtk.Align.CENTER)

    preview_label = Gtk.Label(label=_("Preview"))
    preview_label.add_css_class("dim-label")
    preview_box.append(preview_label)

    preview_picture = _create_preview_image(current_template)
    if preview_picture:
        preview_frame.set_child(preview_picture)
    else:
        placeholder = Gtk.Label(label=_("Text-only signature stamp"))
        placeholder.add_css_class("dim-label")
        placeholder.set_margin_top(20)
        placeholder.set_margin_bottom(20)
        placeholder.set_margin_start(40)
        placeholder.set_margin_end(40)
        preview_frame.set_child(placeholder)

    preview_box.append(preview_frame)
    return preview_box


def _build_template_group(settings, dialog) -> tuple[Adw.PreferencesGroup, Gtk.Frame]:
    """Build the signature template selection group with preview."""
    template_group = Adw.PreferencesGroup()
    template_group.set_title(_("Signature Template"))
    template_group.set_description(_("Choose a visual style for the signature stamp"))

    template_combo, current_template = _build_template_combo(settings, dialog)

    preview_frame = Gtk.Frame()
    preview_frame.add_css_class("view")
    preview_frame.set_halign(Gtk.Align.CENTER)
    preview_frame.set_size_request(300, -1)

    # Action buttons from signature_template_actions module
    create_btn = build_create_template_button(template_combo, preview_frame, dialog)
    import_btn = build_import_template_button(template_combo, preview_frame, dialog)
    edit_btn = build_edit_template_button(template_combo, preview_frame, dialog)
    delete_btn = build_delete_template_button(template_combo, dialog)
    for btn in (create_btn, import_btn, edit_btn, delete_btn):
        template_combo.add_suffix(btn)

    connect_edit_delete_visibility(template_combo, edit_btn, delete_btn, dialog)

    template_group.add(template_combo)
    template_group.add(_build_preview_box(current_template, preview_frame))

    connect_preview_update(template_combo, preview_frame, dialog)

    page_combo = _build_page_combo(settings)
    template_group.add(page_combo)

    dialog.template_combo = template_combo
    dialog.page_combo = page_combo

    return template_group, preview_frame


def _build_output_group(settings, dialog) -> Adw.PreferencesGroup:
    """Build the output files configuration group."""
    output_group = Adw.PreferencesGroup()
    output_group.set_title(_("Output files"))

    suffix_row = Adw.EntryRow()
    suffix_row.set_title(_("Suffix for signed files"))
    suffix_row.set_text(settings.output_suffix)
    suffix_row.set_show_apply_button(True)
    set_accessible(suffix_row, _("Output file suffix"), _("Suffix added to signed file names"))
    output_group.add(suffix_row)

    dialog.suffix_row = suffix_row
    return output_group


def create_signature_page(settings, dialog) -> Adw.PreferencesPage:
    """Creates the visible signature settings page."""
    page = Adw.PreferencesPage()
    page.set_title(_("Visible Signature"))
    page.set_icon_name("edit-symbolic")

    template_group, _preview_frame = _build_template_group(settings, dialog)
    page.add(template_group)

    output_group = _build_output_group(settings, dialog)
    page.add(output_group)

    return page

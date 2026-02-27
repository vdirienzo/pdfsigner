"""
signature_page.py - Visible signature settings page

Author: Homero Thompson del Lago del Terror

Creates the visible signature appearance settings page with template selection.
"""

import io
from pathlib import Path

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from pdfsigner.gui.a11y import set_accessible
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


def _connect_edit_delete_visibility(template_combo, edit_btn, delete_btn, dialog) -> None:
    """Wire up edit/delete button visibility based on template type."""

    def _update_edit_delete_visibility():
        idx = template_combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        is_user_template = False
        if template_name:
            try:
                from pdfsigner.core.signature import list_all_templates

                templates = list_all_templates()
                for name, source in templates:
                    if name == template_name and source == "user":
                        is_user_template = True
                        break
            except ImportError:
                pass

        edit_btn.set_visible(is_user_template)
        delete_btn.set_visible(is_user_template)

    delete_btn._update_visibility = _update_edit_delete_visibility
    template_combo.connect(
        "notify::selected", lambda combo, _pspec: _update_edit_delete_visibility()
    )
    GLib.idle_add(_update_edit_delete_visibility)


def _connect_preview_update(template_combo, preview_frame, dialog) -> None:
    """Wire up live preview updates when template selection changes."""

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


def _build_template_group(settings, dialog) -> tuple[Adw.PreferencesGroup, Gtk.Frame]:
    """
    Build the signature template selection group with preview.

    Returns:
        Tuple of (PreferencesGroup, preview_frame) since preview_frame
        is needed by callbacks for live preview updates.
    """
    template_group = Adw.PreferencesGroup()
    template_group.set_title(_("Signature Template"))
    template_group.set_description(_("Choose a visual style for the signature stamp"))

    template_combo, current_template = _build_template_combo(settings, dialog)

    # Preview frame created early so button callbacks can reference it
    preview_frame = Gtk.Frame()
    preview_frame.add_css_class("view")
    preview_frame.set_halign(Gtk.Align.CENTER)
    preview_frame.set_size_request(300, -1)

    # Add action buttons to combo row
    create_btn = _build_create_template_button(template_combo, preview_frame, dialog)
    import_btn = _build_import_template_button(template_combo, preview_frame, dialog)
    edit_btn = _build_edit_template_button(template_combo, preview_frame, dialog)
    delete_btn = _build_delete_template_button(template_combo, dialog)
    for btn in (create_btn, import_btn, edit_btn, delete_btn):
        template_combo.add_suffix(btn)

    _connect_edit_delete_visibility(template_combo, edit_btn, delete_btn, dialog)

    template_group.add(template_combo)
    template_group.add(_build_preview_box(current_template, preview_frame))

    _connect_preview_update(template_combo, preview_frame, dialog)

    page_combo = _build_page_combo(settings)
    template_group.add(page_combo)

    dialog.template_combo = template_combo
    dialog.page_combo = page_combo

    return template_group, preview_frame


def _build_create_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'create custom template' button."""
    create_btn = Gtk.Button()
    create_btn.set_icon_name("list-add-symbolic")
    create_btn.set_tooltip_text(_("Create custom template"))
    set_accessible(create_btn, _("Create template"), _("Create custom signature template"))
    create_btn.set_valign(Gtk.Align.CENTER)
    create_btn.add_css_class("flat")

    def _on_create_template_clicked(_button):
        """Open template editor dialog."""
        from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog

        def _on_template_created(name: str):
            """Refresh dropdown when new template is created."""
            _refresh_template_list(template_combo, dialog, select_name=name)
            preview = _create_preview_image(name)
            if preview:
                preview_frame.set_child(preview)

        editor = TemplateEditorDialog(on_template_created=_on_template_created)
        editor.set_transient_for(dialog)
        editor.present()

    create_btn.connect("clicked", _on_create_template_clicked)
    return create_btn


def _refresh_template_list(template_combo, dialog, select_name: str | None = None) -> None:
    """Refresh template dropdown after add/import/delete."""
    new_choices = _get_template_choices()
    new_model = Gtk.StringList.new([c[1] for c in new_choices])
    template_combo.set_model(new_model)
    dialog._template_choices = [c[0] for c in new_choices]

    if select_name:
        for i, (value, _label) in enumerate(new_choices):
            if value == select_name:
                template_combo.set_selected(i)
                break


def _handle_imported_file(file_chooser, result, template_combo, preview_frame, dialog) -> None:
    """Process a selected template file from the file chooser."""
    from pdfsigner.core.security.template_validator import validate_template_file
    from pdfsigner.core.signature import load_template_from_path, save_user_template

    try:
        file = file_chooser.open_finish(result)
        if not file:
            return

        file_path = Path(file.get_path())

        errors = validate_template_file(file_path)
        if errors:
            toast = Adw.Toast(title=_("Invalid template: {}").format(", ".join(errors)))
            toast.set_timeout(5)
            dialog.add_toast(toast)
            return

        template = load_template_from_path(file_path)
        if not template:
            toast = Adw.Toast(title=_("Failed to load template"))
            toast.set_timeout(3)
            dialog.add_toast(toast)
            return

        save_user_template(template)
        _refresh_template_list(template_combo, dialog, select_name=template.name)

        preview = _create_preview_image(template.name)
        if preview:
            preview_frame.set_child(preview)

        toast = Adw.Toast(title=_("Template '{}' imported successfully").format(template.name))
        toast.set_timeout(3)
        dialog.add_toast(toast)

    except Exception as e:
        from loguru import logger

        logger.error(f"Failed to import template: {e}")
        toast = Adw.Toast(title=_("Import failed: {}").format(str(e)))
        toast.set_timeout(5)
        dialog.add_toast(toast)


def _build_import_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'import template from file' button."""
    import_btn = Gtk.Button()
    import_btn.set_icon_name("document-open-symbolic")
    import_btn.set_tooltip_text(_("Import template from file"))
    set_accessible(import_btn, _("Import template"), _("Import template from JSON file"))
    import_btn.set_valign(Gtk.Align.CENTER)
    import_btn.add_css_class("flat")

    def _on_import_template_clicked(_button):
        """Open file chooser to import a template JSON file."""
        file_chooser = Gtk.FileDialog()
        file_chooser.set_title(_("Import Template"))

        json_filter = Gtk.FileFilter()
        json_filter.set_name(_("JSON files"))
        json_filter.add_pattern("*.json")

        all_filter = Gtk.FileFilter()
        all_filter.set_name(_("All files"))
        all_filter.add_pattern("*")

        filter_list = Gio.ListStore.new(Gtk.FileFilter)
        filter_list.append(json_filter)
        filter_list.append(all_filter)
        file_chooser.set_filters(filter_list)
        file_chooser.set_default_filter(json_filter)

        file_chooser.open(
            dialog,
            None,
            lambda src, res: _handle_imported_file(
                file_chooser, res, template_combo, preview_frame, dialog
            ),
        )

    import_btn.connect("clicked", _on_import_template_clicked)
    return import_btn


def _build_edit_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'edit template' button (visible only for user templates)."""
    edit_btn = Gtk.Button()
    edit_btn.set_icon_name("document-edit-symbolic")
    edit_btn.set_tooltip_text(_("Edit template"))
    set_accessible(edit_btn, _("Edit template"), _("Edit custom template"))
    edit_btn.set_valign(Gtk.Align.CENTER)
    edit_btn.add_css_class("flat")
    edit_btn.set_visible(False)

    def _on_edit_template_clicked(_button):
        """Open template editor in edit mode."""
        from pdfsigner.core.signature import load_template
        from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog

        idx = template_combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        if not template_name:
            return

        template = load_template(template_name)
        if not template:
            return

        def _on_template_updated(name: str):
            """Refresh preview when template is updated."""
            preview = _create_preview_image(name)
            if preview:
                preview_frame.set_child(preview)

        editor = TemplateEditorDialog(
            on_template_created=_on_template_updated,
            edit_template=template,
        )
        editor.set_transient_for(dialog)
        editor.present()

    edit_btn.connect("clicked", _on_edit_template_clicked)
    return edit_btn


def _build_delete_template_button(template_combo, dialog) -> Gtk.Button:
    """Build the 'delete template' button (visible only for user templates)."""
    delete_btn = Gtk.Button()
    delete_btn.set_icon_name("user-trash-symbolic")
    delete_btn.set_tooltip_text(_("Delete template"))
    set_accessible(delete_btn, _("Delete template"), _("Delete custom template"))
    delete_btn.set_valign(Gtk.Align.CENTER)
    delete_btn.add_css_class("flat")
    delete_btn.set_visible(False)

    def _on_delete_template_clicked(_button):
        """Delete user template with confirmation."""
        from pdfsigner.core.signature import delete_user_template

        idx = template_combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        if not template_name:
            return

        confirm = Adw.MessageDialog(
            transient_for=dialog,
            heading=_("Delete Template?"),
            body=_("Are you sure you want to delete the template '{}'?").format(template_name),
        )
        confirm.add_response("cancel", _("Cancel"))
        confirm.add_response("delete", _("Delete"))
        confirm.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        confirm.set_default_response("cancel")
        confirm.set_close_response("cancel")

        def on_response(_dialog, response):
            if response == "delete":
                if delete_user_template(template_name):
                    _refresh_template_list(template_combo, dialog)
                    template_combo.set_selected(0)
                    if hasattr(delete_btn, "_update_visibility"):
                        delete_btn._update_visibility()

        confirm.connect("response", on_response)
        confirm.present()

    delete_btn.connect("clicked", _on_delete_template_clicked)
    return delete_btn


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

    # Initial preview
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

    template_group, _preview_frame = _build_template_group(settings, dialog)
    page.add(template_group)

    output_group = _build_output_group(settings, dialog)
    page.add(output_group)

    return page

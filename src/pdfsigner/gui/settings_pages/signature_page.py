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
    template_combo.set_accessible_name(_("Signature template"))
    template_combo.set_accessible_description(_("Select signature stamp template"))

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
    create_btn.set_accessible_name(_("Create template"))
    create_btn.set_accessible_description(_("Create custom signature template"))
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

    # Import template button
    import_btn = Gtk.Button()
    import_btn.set_icon_name("document-open-symbolic")
    import_btn.set_tooltip_text(_("Import template from file"))
    import_btn.set_accessible_name(_("Import template"))
    import_btn.set_accessible_description(_("Import template from JSON file"))
    import_btn.set_valign(Gtk.Align.CENTER)
    import_btn.add_css_class("flat")

    def _on_import_template_clicked(_button):
        """Open file chooser to import a template JSON file."""
        from pdfsigner.core.security.template_validator import validate_template_file
        from pdfsigner.core.signature import load_template_from_path, save_user_template

        # Create file chooser dialog
        file_chooser = Gtk.FileDialog()
        file_chooser.set_title(_("Import Template"))

        # Add JSON filter
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

        def on_file_selected(_source, result):
            """Process selected template file."""
            try:
                file = file_chooser.open_finish(result)
                if not file:
                    return

                file_path = Path(file.get_path())

                # Validate template structure
                errors = validate_template_file(file_path)
                if errors:
                    # Show error toast
                    toast = Adw.Toast(title=_("Invalid template: {}").format(", ".join(errors)))
                    toast.set_timeout(5)
                    dialog.add_toast(toast)
                    return

                # Load template
                template = load_template_from_path(file_path)
                if not template:
                    toast = Adw.Toast(title=_("Failed to load template"))
                    toast.set_timeout(3)
                    dialog.add_toast(toast)
                    return

                # Save as user template
                save_user_template(template)

                # Refresh dropdown
                new_choices = _get_template_choices()
                new_model = Gtk.StringList.new([c[1] for c in new_choices])
                template_combo.set_model(new_model)
                dialog._template_choices = [c[0] for c in new_choices]

                # Select the imported template
                for i, (value, _label) in enumerate(new_choices):
                    if value == template.name:
                        template_combo.set_selected(i)
                        break

                # Update preview
                preview = _create_preview_image(template.name)
                if preview:
                    preview_frame.set_child(preview)

                # Show success toast
                toast = Adw.Toast(
                    title=_("Template '{}' imported successfully").format(template.name)
                )
                toast.set_timeout(3)
                dialog.add_toast(toast)

            except Exception as e:
                from loguru import logger

                logger.error(f"Failed to import template: {e}")
                toast = Adw.Toast(title=_("Import failed: {}").format(str(e)))
                toast.set_timeout(5)
                dialog.add_toast(toast)

        file_chooser.open(dialog, None, on_file_selected)

    import_btn.connect("clicked", _on_import_template_clicked)
    template_combo.add_suffix(import_btn)

    # Edit template button (only visible for user templates)
    edit_btn = Gtk.Button()
    edit_btn.set_icon_name("document-edit-symbolic")
    edit_btn.set_tooltip_text(_("Edit template"))
    edit_btn.set_accessible_name(_("Edit template"))
    edit_btn.set_accessible_description(_("Edit custom template"))
    edit_btn.set_valign(Gtk.Align.CENTER)
    edit_btn.add_css_class("flat")
    edit_btn.set_visible(False)  # Initially hidden

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
    template_combo.add_suffix(edit_btn)

    # Delete template button (only visible for user templates)
    delete_btn = Gtk.Button()
    delete_btn.set_icon_name("user-trash-symbolic")
    delete_btn.set_tooltip_text(_("Delete template"))
    delete_btn.set_accessible_name(_("Delete template"))
    delete_btn.set_accessible_description(_("Delete custom template"))
    delete_btn.set_valign(Gtk.Align.CENTER)
    delete_btn.add_css_class("flat")
    delete_btn.set_visible(False)  # Initially hidden

    def _on_delete_template_clicked(_button):
        """Delete user template with confirmation."""
        from pdfsigner.core.signature import delete_user_template

        idx = template_combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        if not template_name:
            return

        # Create confirmation dialog
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
                    # Refresh template list
                    new_choices = _get_template_choices()
                    new_model = Gtk.StringList.new([c[1] for c in new_choices])
                    template_combo.set_model(new_model)
                    dialog._template_choices = [c[0] for c in new_choices]
                    template_combo.set_selected(0)  # Select invisible
                    _update_edit_delete_visibility()

        confirm.connect("response", on_response)
        confirm.present()

    delete_btn.connect("clicked", _on_delete_template_clicked)
    template_combo.add_suffix(delete_btn)

    def _update_edit_delete_visibility():
        """Show edit/delete buttons only for user templates."""
        idx = template_combo.get_selected()
        template_name = dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""

        # Check if it's a user template
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

    # Update visibility on template change
    def on_template_changed_for_buttons(combo, _pspec):
        _update_edit_delete_visibility()

    template_combo.connect("notify::selected", on_template_changed_for_buttons)

    # Initial visibility check
    GLib.idle_add(_update_edit_delete_visibility)

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
    page_combo.set_accessible_name(_("Default page"))
    page_combo.set_accessible_description(_("Select default page for signature"))
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
    suffix_row.set_accessible_name(_("Output file suffix"))
    suffix_row.set_accessible_description(_("Suffix added to signed file names"))
    output_group.add(suffix_row)

    page.add(output_group)

    # Store references for saving
    dialog.template_combo = template_combo
    dialog.page_combo = page_combo
    dialog.suffix_row = suffix_row

    return page

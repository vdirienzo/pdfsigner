"""
signature_template_actions.py - Template action buttons for signature page

Provides create, import, edit, delete button builders and their
callback handlers for the signature template selection group.
"""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def _get_selected_template_name(template_combo, dialog) -> str:
    """Get the currently selected template name from the combo."""
    idx = template_combo.get_selected()
    return dialog._template_choices[idx] if idx < len(dialog._template_choices) else ""


def refresh_template_list(template_combo, dialog, select_name: str | None = None) -> None:
    """Refresh template dropdown after add/import/delete."""
    from pdfsigner.gui.settings_pages.signature_page import _get_template_choices

    new_choices = _get_template_choices()
    new_model = Gtk.StringList.new([c[1] for c in new_choices])
    template_combo.set_model(new_model)
    dialog._template_choices = [c[0] for c in new_choices]

    if select_name:
        for i, (value, _label) in enumerate(new_choices):
            if value == select_name:
                template_combo.set_selected(i)
                break


def connect_edit_delete_visibility(template_combo, edit_btn, delete_btn, dialog) -> None:
    """Wire up edit/delete button visibility based on template type."""

    def _update_edit_delete_visibility():
        template_name = _get_selected_template_name(template_combo, dialog)
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


def connect_preview_update(template_combo, preview_frame, dialog) -> None:
    """Wire up live preview updates when template selection changes."""
    from pdfsigner.gui.settings_pages.signature_page import _create_preview_image

    def on_template_changed(combo, _pspec):
        template_name = _get_selected_template_name(combo, dialog)
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


def build_create_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'create custom template' button."""
    create_btn = Gtk.Button()
    create_btn.set_icon_name("list-add-symbolic")
    create_btn.set_tooltip_text(_("Create custom template"))
    set_accessible(create_btn, _("Create template"), _("Create custom signature template"))
    create_btn.set_valign(Gtk.Align.CENTER)
    create_btn.add_css_class("flat")

    def _on_create_template_clicked(_button):
        from pdfsigner.gui.settings_pages.signature_page import _create_preview_image
        from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog

        def _on_template_created(name: str):
            refresh_template_list(template_combo, dialog, select_name=name)
            preview = _create_preview_image(name)
            if preview:
                preview_frame.set_child(preview)

        editor = TemplateEditorDialog(on_template_created=_on_template_created)
        editor.set_transient_for(dialog)
        editor.present()

    create_btn.connect("clicked", _on_create_template_clicked)
    return create_btn


def _handle_imported_file(file_chooser, result, template_combo, preview_frame, dialog) -> None:
    """Process a selected template file from the file chooser."""
    from pdfsigner.core.security.template_validator import validate_template_file
    from pdfsigner.core.signature import load_template_from_path, save_user_template
    from pdfsigner.gui.settings_pages.signature_page import _create_preview_image

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
        refresh_template_list(template_combo, dialog, select_name=template.name)

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


def build_import_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'import template from file' button."""
    import_btn = Gtk.Button()
    import_btn.set_icon_name("document-open-symbolic")
    import_btn.set_tooltip_text(_("Import template from file"))
    set_accessible(import_btn, _("Import template"), _("Import template from JSON file"))
    import_btn.set_valign(Gtk.Align.CENTER)
    import_btn.add_css_class("flat")

    def _on_import_template_clicked(_button):
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


def build_edit_template_button(template_combo, preview_frame, dialog) -> Gtk.Button:
    """Build the 'edit template' button (visible only for user templates)."""
    edit_btn = Gtk.Button()
    edit_btn.set_icon_name("document-edit-symbolic")
    edit_btn.set_tooltip_text(_("Edit template"))
    set_accessible(edit_btn, _("Edit template"), _("Edit custom template"))
    edit_btn.set_valign(Gtk.Align.CENTER)
    edit_btn.add_css_class("flat")
    edit_btn.set_visible(False)

    def _on_edit_template_clicked(_button):
        from pdfsigner.core.signature import load_template
        from pdfsigner.gui.settings_pages.signature_page import _create_preview_image
        from pdfsigner.gui.template_editor_dialog import TemplateEditorDialog

        template_name = _get_selected_template_name(template_combo, dialog)
        if not template_name:
            return

        template = load_template(template_name)
        if not template:
            return

        def _on_template_updated(name: str):
            preview = _create_preview_image(name)
            if preview:
                preview_frame.set_child(preview)

        editor = TemplateEditorDialog(
            on_template_created=_on_template_updated, edit_template=template
        )
        editor.set_transient_for(dialog)
        editor.present()

    edit_btn.connect("clicked", _on_edit_template_clicked)
    return edit_btn


def build_delete_template_button(template_combo, dialog) -> Gtk.Button:
    """Build the 'delete template' button (visible only for user templates)."""
    delete_btn = Gtk.Button()
    delete_btn.set_icon_name("user-trash-symbolic")
    delete_btn.set_tooltip_text(_("Delete template"))
    set_accessible(delete_btn, _("Delete template"), _("Delete custom template"))
    delete_btn.set_valign(Gtk.Align.CENTER)
    delete_btn.add_css_class("flat")
    delete_btn.set_visible(False)

    def _on_delete_template_clicked(_button):
        from pdfsigner.core.signature import delete_user_template

        template_name = _get_selected_template_name(template_combo, dialog)
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
                    refresh_template_list(template_combo, dialog)
                    template_combo.set_selected(0)
                    if hasattr(delete_btn, "_update_visibility"):
                        delete_btn._update_visibility()

        confirm.connect("response", on_response)
        confirm.present()

    delete_btn.connect("clicked", _on_delete_template_clicked)
    return delete_btn

"""
general_page.py - General settings page

Author: Homero Thompson del Lago del Terror

Creates the general settings page with NSS and TSA configuration.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _

from .tsa_presets import TSA_PRESET_NAMES, TSA_PRESETS


def create_general_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the general settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("General"))
    page.set_icon_name("preferences-system-symbolic")

    # Grupo: NSS/Token
    nss_group = Adw.PreferencesGroup()
    nss_group.set_title(_("USB Token"))
    nss_group.set_description(_("NSS database configuration"))

    # NSS Path - ActionRow with entry and browse button
    nss_path_row = Adw.ActionRow()
    nss_path_row.set_title(_("NSS Database Path"))
    nss_path_row.set_subtitle(_("Path to NSS database directory"))

    # Entry for typing path
    nss_path_entry = Gtk.Entry()
    nss_path_entry.set_text(str(settings.nss_db_path))
    nss_path_entry.set_hexpand(True)
    nss_path_entry.set_valign(Gtk.Align.CENTER)
    set_accessible(nss_path_entry, _("NSS database path"), _("Path to NSS database directory"))
    nss_path_row.add_suffix(nss_path_entry)

    # Browse button
    browse_button = Gtk.Button()
    browse_button.set_icon_name("folder-open-symbolic")
    browse_button.set_valign(Gtk.Align.CENTER)
    browse_button.set_tooltip_text(_("Browse for NSS database folder"))
    set_accessible(browse_button, _("Browse"), _("Browse for NSS database folder"))
    browse_button.connect(
        "clicked", lambda btn: _on_browse_nss_clicked(btn, nss_path_entry, dialog)
    )
    nss_path_row.add_suffix(browse_button)

    nss_group.add(nss_path_row)
    page.add(nss_group)

    # Grupo: TSA
    tsa_group = Adw.PreferencesGroup()
    tsa_group.set_title(_("Timestamp Server (TSA)"))
    tsa_group.set_description(_("Timestamp source for signatures"))

    # TSA presets
    presets_row = Adw.ComboRow()
    presets_row.set_title(_("Timestamp source"))
    presets_row.set_subtitle(_("Local time or external TSA server"))
    set_accessible(presets_row, _("Timestamp source"), _("Select timestamp server"))

    presets = Gtk.StringList.new(TSA_PRESET_NAMES)
    presets_row.set_model(presets)

    # Set default based on current TSA URL
    if not settings.tsa_url:
        presets_row.set_selected(0)  # Local time (no TSA)
    else:
        # Check if current URL matches a preset
        preset_found = False
        for idx, url in TSA_PRESETS.items():
            if url and url == settings.tsa_url:
                presets_row.set_selected(idx)
                preset_found = True
                break
        if not preset_found:
            presets_row.set_selected(6)  # Custom URL

    # TSA URL (only visible when Custom is selected)
    tsa_url_row = Adw.EntryRow()
    tsa_url_row.set_title(_("TSA URL"))
    tsa_url_row.set_text(settings.tsa_url or "")
    tsa_url_row.set_show_apply_button(True)
    set_accessible(tsa_url_row, _("TSA URL"), _("Timestamp server URL"))
    tsa_url_row.connect("apply", lambda row: None)  # Saved on "Save" button

    presets_row.connect(
        "notify::selected", lambda combo, param: _on_tsa_preset_selected(combo, tsa_url_row)
    )
    tsa_group.add(presets_row)
    tsa_group.add(tsa_url_row)

    # Credenciales TSA
    tsa_user_row = Adw.EntryRow()
    tsa_user_row.set_title(_("TSA Username (optional)"))
    tsa_user_row.set_text(settings.tsa_username or "")
    tsa_user_row.set_show_apply_button(True)
    set_accessible(tsa_user_row, _("TSA username"), _("Username for TSA authentication"))
    tsa_group.add(tsa_user_row)

    tsa_pass_row = Adw.PasswordEntryRow()
    tsa_pass_row.set_title(_("TSA Password (optional)"))
    tsa_pass_row.set_text(settings.tsa_password or "")
    tsa_pass_row.set_show_apply_button(True)
    set_accessible(tsa_pass_row, _("TSA password"), _("Password for TSA authentication"))
    tsa_group.add(tsa_pass_row)

    page.add(tsa_group)

    # Store references for saving
    dialog.nss_path_entry = nss_path_entry
    dialog.tsa_presets_row = presets_row
    dialog.tsa_url_row = tsa_url_row
    dialog.tsa_user_row = tsa_user_row
    dialog.tsa_pass_row = tsa_pass_row

    return page


def _on_browse_nss_clicked(button: Gtk.Button, entry: Gtk.Entry, dialog) -> None:
    """Opens file dialog to select NSS database folder."""
    file_dialog = Gtk.FileDialog()
    file_dialog.set_title(_("Select NSS Database Folder"))

    # Start from current path if valid
    current_path = Path(entry.get_text())
    if current_path.exists():
        file_dialog.set_initial_folder(Gio.File.new_for_path(str(current_path)))

    file_dialog.select_folder(dialog, None, lambda d, result: _on_folder_selected(d, result, entry))


def _on_folder_selected(dialog: Gtk.FileDialog, result, entry: Gtk.Entry) -> None:
    """Handles folder selection result."""
    try:
        folder = dialog.select_folder_finish(result)
        if folder:
            entry.set_text(folder.get_path())
    except GLib.Error:
        pass  # User cancelled


def _on_tsa_preset_selected(combo, tsa_url_row) -> None:
    """Handles timestamp source selection."""
    selected = combo.get_selected()

    if selected == 0:
        # Local time - clear URL
        tsa_url_row.set_text("")
    elif selected == 6:
        # Custom URL - don't change URL, user will type it
        pass
    else:
        # Preset TSA (indices 1-5)
        url = TSA_PRESETS.get(selected, "")
        tsa_url_row.set_text(url)

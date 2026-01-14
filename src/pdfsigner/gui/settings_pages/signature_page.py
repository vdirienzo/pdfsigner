"""
signature_page.py - Visible signature settings page

Author: Homero Thompson del Lago del Terror

Creates the visible signature appearance settings page.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


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
    page.set_title("Visible Signature")
    page.set_icon_name("edit-symbolic")

    # Grupo: Apariencia
    appearance_group = Adw.PreferencesGroup()
    appearance_group.set_title("Appearance")

    # Firma visible por defecto
    visible_switch = Adw.SwitchRow()
    visible_switch.set_title("Visible signature by default")
    visible_switch.set_subtitle("Show signature stamp on document")
    visible_switch.set_active(settings.default_visible)
    appearance_group.add(visible_switch)

    # Página por defecto
    page_combo = Adw.ComboRow()
    page_combo.set_title("Default page")
    pages = Gtk.StringList.new(["Last page", "First page"])
    page_combo.set_model(pages)
    page_combo.set_selected(0 if settings.default_page == "last" else 1)
    appearance_group.add(page_combo)

    page.add(appearance_group)

    # Grupo: Dimensiones
    dimensions_group = Adw.PreferencesGroup()
    dimensions_group.set_title("Stamp dimensions")

    # Ancho
    width_spin = Adw.SpinRow.new_with_range(20, 100, 5)
    width_spin.set_title("Width (mm)")
    width_spin.set_value(settings.signature_width_mm)
    dimensions_group.add(width_spin)

    # Alto
    height_spin = Adw.SpinRow.new_with_range(10, 50, 5)
    height_spin.set_title("Height (mm)")
    height_spin.set_value(settings.signature_height_mm)
    dimensions_group.add(height_spin)

    page.add(dimensions_group)

    # Grupo: Output
    output_group = Adw.PreferencesGroup()
    output_group.set_title("Output files")

    # Sufijo
    suffix_row = Adw.EntryRow()
    suffix_row.set_title("Suffix for signed files")
    suffix_row.set_text(settings.output_suffix)
    suffix_row.set_show_apply_button(True)
    output_group.add(suffix_row)

    page.add(output_group)

    # Store references for saving
    dialog.visible_switch = visible_switch
    dialog.page_combo = page_combo
    dialog.width_spin = width_spin
    dialog.height_spin = height_spin
    dialog.suffix_row = suffix_row

    return page

"""
advanced_page.py - Advanced settings page

Author: Homero Thompson del Lago del Terror

Creates the advanced settings page with PIN cache and logging configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.i18n import _


def create_advanced_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the advanced settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for storing widget references

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Advanced"))
    page.set_icon_name("applications-system-symbolic")

    # Grupo: PIN Cache
    pin_group = Adw.PreferencesGroup()
    pin_group.set_title(_("PIN Cache"))
    pin_group.set_description(_("Cache PIN during batch signing"))

    # Habilitar cache
    pin_cache_switch = Adw.SwitchRow()
    pin_cache_switch.set_title(_("Enable PIN cache"))
    pin_cache_switch.set_subtitle(_("More convenient but less secure"))
    pin_cache_switch.set_active(settings.pin_cache_enabled)
    pin_group.add(pin_cache_switch)

    # Timeout
    pin_timeout_spin = Adw.SpinRow.new_with_range(60, 3600, 60)
    pin_timeout_spin.set_title(_("Timeout (seconds)"))
    pin_timeout_spin.set_value(settings.pin_cache_timeout_seconds)
    pin_group.add(pin_timeout_spin)

    page.add(pin_group)

    # Grupo: Logging
    log_group = Adw.PreferencesGroup()
    log_group.set_title(_("Logging"))

    # Nivel de log
    log_level_combo = Adw.ComboRow()
    log_level_combo.set_title(_("Log level"))
    levels = Gtk.StringList.new([_("DEBUG"), _("INFO"), _("WARNING"), _("ERROR")])
    log_level_combo.set_model(levels)

    level_index = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
    log_level_combo.set_selected(level_index.get(settings.log_level, 1))
    log_group.add(log_level_combo)

    page.add(log_group)

    # Store references for saving
    dialog.pin_cache_switch = pin_cache_switch
    dialog.pin_timeout_spin = pin_timeout_spin
    dialog.log_level_combo = log_level_combo

    return page

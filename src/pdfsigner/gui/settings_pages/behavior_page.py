"""
behavior_page.py - Behavior settings page

Author: Homero Thompson del Lago del Terror

Creates the behavior settings page with recent files and notifications configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def create_behavior_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the behavior settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Behavior"))
    page.set_icon_name("preferences-other-symbolic")

    # Group: Recent Files
    recent_files_group = Adw.PreferencesGroup()
    recent_files_group.set_title(_("Recent Files"))
    recent_files_group.set_description(_("Recent PDF files history"))

    # Recent files enabled switch
    recent_files_switch = Adw.SwitchRow()
    recent_files_switch.set_title(_("Track recent files"))
    recent_files_switch.set_subtitle(_("Remember recently opened PDF files"))
    recent_files_switch.set_active(settings.recent_files_enabled)
    set_accessible(
        recent_files_switch,
        _("Track recent files"),
        _("Enable or disable recent files history"),
    )
    recent_files_group.add(recent_files_switch)

    # Recent files limit spin row
    recent_files_limit_spin = Adw.SpinRow()
    recent_files_limit_spin.set_title(_("Maximum files to show"))
    recent_files_limit_spin.set_subtitle(_("Number of files in recent list (5-50)"))
    set_accessible(
        recent_files_limit_spin,
        _("Maximum recent files"),
        _("Number of files to show in recent list"),
    )

    # Create adjustment (value, lower, upper, step, page_step, page_size)
    adjustment = Gtk.Adjustment.new(
        float(settings.recent_files_limit),  # current value
        5.0,  # lower limit
        50.0,  # upper limit
        1.0,  # step increment
        5.0,  # page increment
        0.0,  # page size (0 for spin buttons)
    )
    recent_files_limit_spin.set_adjustment(adjustment)
    recent_files_group.add(recent_files_limit_spin)

    page.add(recent_files_group)

    # Group: Notifications
    notifications_group = Adw.PreferencesGroup()
    notifications_group.set_title(_("Notifications"))
    notifications_group.set_description(_("Desktop notification settings"))

    # System notifications enabled switch
    notifications_switch = Adw.SwitchRow()
    notifications_switch.set_title(_("Show system notifications"))
    notifications_switch.set_subtitle(_("Notify when batch signing completes"))
    notifications_switch.set_active(settings.system_notifications_enabled)
    set_accessible(
        notifications_switch,
        _("Show system notifications"),
        _("Enable or disable desktop notifications"),
    )
    notifications_group.add(notifications_switch)

    page.add(notifications_group)

    # Store references for saving
    dialog.recent_files_switch = recent_files_switch
    dialog.recent_files_limit_spin = recent_files_limit_spin
    dialog.notifications_switch = notifications_switch

    return page

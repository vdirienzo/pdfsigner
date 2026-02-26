"""
validation_page.py - Validation settings page

Author: Homero Thompson del Lago del Terror

Creates the validation settings page with revocation checking configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def add_validation_groups(page: Adw.PreferencesPage, settings, dialog) -> None:
    """
    Add validation groups (Certificate Revocation) to an existing page.

    Args:
        page: Target PreferencesPage to add groups to
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks
    """
    # Grupo: Certificate Revocation
    revocation_group = Adw.PreferencesGroup()
    revocation_group.set_title(_("Certificate Revocation"))
    revocation_group.set_description(_("OCSP and CRL checking during validation"))

    # Enable revocation checking
    revocation_switch = Adw.SwitchRow()
    revocation_switch.set_title(_("Enable revocation checking"))
    revocation_switch.set_subtitle(_("Check OCSP/CRL during validation"))
    revocation_switch.set_active(settings.revocation_check_enabled)
    set_accessible(
        revocation_switch,
        _("Enable revocation checking"),
        _("Check certificate revocation status"),
    )
    revocation_group.add(revocation_switch)

    # Timeout (5-60 seconds)
    timeout_adjustment = Gtk.Adjustment.new(
        value=float(settings.revocation_check_timeout),
        lower=5.0,
        upper=60.0,
        step_increment=1.0,
        page_increment=5.0,
        page_size=0.0,
    )
    revocation_timeout_spin = Adw.SpinRow.new(timeout_adjustment, 1.0, 0)
    revocation_timeout_spin.set_title(_("Timeout (seconds)"))
    revocation_timeout_spin.set_subtitle(_("Request timeout (5-60s)"))
    set_accessible(
        revocation_timeout_spin,
        _("Revocation check timeout"),
        _("Timeout in seconds for revocation requests"),
    )
    revocation_group.add(revocation_timeout_spin)

    # Cache TTL (300-86400 seconds = 5min - 24h)
    cache_ttl_adjustment = Gtk.Adjustment.new(
        value=float(settings.revocation_cache_ttl),
        lower=300.0,
        upper=86400.0,
        step_increment=60.0,
        page_increment=600.0,
        page_size=0.0,
    )
    revocation_cache_ttl_spin = Adw.SpinRow.new(cache_ttl_adjustment, 60.0, 0)
    revocation_cache_ttl_spin.set_title(_("Cache TTL (seconds)"))
    revocation_cache_ttl_spin.set_subtitle(_("Cache duration (5min - 24h)"))
    set_accessible(
        revocation_cache_ttl_spin,
        _("Revocation cache TTL"),
        _("Time to live for revocation cache"),
    )
    revocation_group.add(revocation_cache_ttl_spin)

    # Prefer OCSP over CRL
    revocation_prefer_ocsp_switch = Adw.SwitchRow()
    revocation_prefer_ocsp_switch.set_title(_("Prefer OCSP over CRL"))
    revocation_prefer_ocsp_switch.set_subtitle(_("OCSP is faster, CRL is more reliable"))
    revocation_prefer_ocsp_switch.set_active(settings.revocation_prefer_ocsp)
    set_accessible(
        revocation_prefer_ocsp_switch,
        _("Prefer OCSP"),
        _("Prefer OCSP over CRL for revocation checks"),
    )
    revocation_group.add(revocation_prefer_ocsp_switch)

    page.add(revocation_group)

    # Store references for auto-save
    dialog.revocation_switch = revocation_switch
    dialog.revocation_timeout_spin = revocation_timeout_spin
    dialog.revocation_cache_ttl_spin = revocation_cache_ttl_spin
    dialog.revocation_prefer_ocsp_switch = revocation_prefer_ocsp_switch


def create_validation_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the validation settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Validation"))
    page.set_icon_name("security-high-symbolic")

    add_validation_groups(page, settings, dialog)

    return page

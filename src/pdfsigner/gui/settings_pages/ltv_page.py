"""
ltv_page.py - LTV (Long Term Validation) settings page

Author: Homero Thompson del Lago del Terror

Creates the LTV settings page with PAdES-LTV configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def create_ltv_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the LTV settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("LTV"))
    page.set_icon_name("security-high-symbolic")

    # Grupo: Long Term Validation
    ltv_group = Adw.PreferencesGroup()
    ltv_group.set_title(_("Long Term Validation"))
    ltv_group.set_description(_("PAdES-LTV signatures with embedded validation info (DSS)"))

    # Enable LTV
    ltv_switch = Adw.SwitchRow()
    ltv_switch.set_title(_("Enable LTV"))
    ltv_switch.set_subtitle(_("Embed OCSP/CRL responses for offline validation"))
    ltv_switch.set_active(settings.ltv_enabled)
    set_accessible(
        ltv_switch,
        _("Enable LTV signatures"),
        _("Enable PAdES-LTV signatures with embedded validation info"),
    )
    ltv_group.add(ltv_switch)

    # Fail open switch
    fail_open_switch = Adw.SwitchRow()
    fail_open_switch.set_title(_("Continue on LTV failure"))
    fail_open_switch.set_subtitle(_("Sign with basic signature if LTV embedding fails"))
    fail_open_switch.set_active(settings.ltv_fail_open)
    set_accessible(
        fail_open_switch,
        _("Continue if LTV fails"),
        _("Continue signing if LTV embedding fails (signature still valid)"),
    )
    ltv_group.add(fail_open_switch)

    page.add(ltv_group)

    # Grupo: Timeouts
    timeout_group = Adw.PreferencesGroup()
    timeout_group.set_title(_("Timeouts"))
    timeout_group.set_description(_("Network timeouts for fetching validation information"))

    # OCSP timeout (5-60 seconds)
    ocsp_timeout_adjustment = Gtk.Adjustment.new(
        value=float(settings.ltv_ocsp_timeout),
        lower=5.0,
        upper=60.0,
        step_increment=1.0,
        page_increment=5.0,
        page_size=0.0,
    )
    ltv_ocsp_timeout_spin = Adw.SpinRow.new(ocsp_timeout_adjustment, 1.0, 0)
    ltv_ocsp_timeout_spin.set_title(_("OCSP timeout (seconds)"))
    ltv_ocsp_timeout_spin.set_subtitle(_("Request timeout for OCSP (5-60s)"))
    set_accessible(
        ltv_ocsp_timeout_spin,
        _("OCSP timeout"),
        _("Timeout in seconds for OCSP requests"),
    )
    timeout_group.add(ltv_ocsp_timeout_spin)

    # CRL timeout (10-120 seconds)
    crl_timeout_adjustment = Gtk.Adjustment.new(
        value=float(settings.ltv_crl_timeout),
        lower=10.0,
        upper=120.0,
        step_increment=1.0,
        page_increment=10.0,
        page_size=0.0,
    )
    ltv_crl_timeout_spin = Adw.SpinRow.new(crl_timeout_adjustment, 1.0, 0)
    ltv_crl_timeout_spin.set_title(_("CRL timeout (seconds)"))
    ltv_crl_timeout_spin.set_subtitle(_("Download timeout for CRL (10-120s)"))
    set_accessible(
        ltv_crl_timeout_spin,
        _("CRL timeout"),
        _("Timeout in seconds for CRL downloads"),
    )
    timeout_group.add(ltv_crl_timeout_spin)

    page.add(timeout_group)

    # Grupo: Preferences
    pref_group = Adw.PreferencesGroup()
    pref_group.set_title(_("Preferences"))

    # Prefer OCSP over CRL
    ltv_prefer_ocsp_switch = Adw.SwitchRow()
    ltv_prefer_ocsp_switch.set_title(_("Prefer OCSP over CRL"))
    ltv_prefer_ocsp_switch.set_subtitle(_("OCSP is faster, CRL is more reliable"))
    ltv_prefer_ocsp_switch.set_active(settings.ltv_prefer_ocsp)
    set_accessible(
        ltv_prefer_ocsp_switch,
        _("Prefer OCSP"),
        _("Prefer OCSP over CRL for LTV validation info"),
    )
    pref_group.add(ltv_prefer_ocsp_switch)

    page.add(pref_group)

    # Store references for auto-save
    dialog.ltv_switch = ltv_switch
    dialog.ltv_fail_open_switch = fail_open_switch
    dialog.ltv_ocsp_timeout_spin = ltv_ocsp_timeout_spin
    dialog.ltv_crl_timeout_spin = ltv_crl_timeout_spin
    dialog.ltv_prefer_ocsp_switch = ltv_prefer_ocsp_switch

    return page

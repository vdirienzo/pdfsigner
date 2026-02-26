"""
security_page.py - Security settings page (consolidated)

Author: Homero Thompson del Lago del Terror

Creates the security settings page consolidating:
- Certificate Revocation (from validation_page)
- Long Term Validation / LTV (from ltv_page)
- PIN Cache and Logging (from advanced_page)
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _

from .validation_page import add_validation_groups


def create_security_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the consolidated security settings page.

    Includes Certificate Revocation, LTV, PIN Cache, and Logging groups.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Security"))
    page.set_icon_name("security-high-symbolic")

    # Certificate Revocation groups (from validation_page)
    add_validation_groups(page, settings, dialog)

    # LTV groups (inlined from ltv_page)
    _build_ltv_groups(page, settings, dialog)

    # Advanced groups (inlined from advanced_page)
    _build_advanced_groups(page, settings, dialog)

    return page


def _build_ltv_groups(page: Adw.PreferencesPage, settings, dialog) -> None:
    """Build Long Term Validation groups (ex ltv_page.py)."""
    # Group: Long Term Validation
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

    # Group: Timeouts
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

    # Group: Preferences
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


def _build_advanced_groups(page: Adw.PreferencesPage, settings, dialog) -> None:
    """Build PIN Cache and Logging groups (ex advanced_page.py)."""
    # Group: PIN Cache
    pin_group = Adw.PreferencesGroup()
    pin_group.set_title(_("PIN Cache"))
    pin_group.set_description(_("Cache PIN during batch signing"))

    # Enable cache
    pin_cache_switch = Adw.SwitchRow()
    pin_cache_switch.set_title(_("Enable PIN cache"))
    pin_cache_switch.set_subtitle(_("More convenient but less secure"))
    pin_cache_switch.set_active(settings.pin_cache_enabled)
    set_accessible(pin_cache_switch, _("Enable PIN cache"), _("Cache PIN during batch signing"))
    pin_group.add(pin_cache_switch)

    # Timeout
    pin_timeout_spin = Adw.SpinRow.new_with_range(60, 3600, 60)
    pin_timeout_spin.set_title(_("Timeout (seconds)"))
    pin_timeout_spin.set_value(settings.pin_cache_timeout_seconds)
    set_accessible(
        pin_timeout_spin,
        _("PIN cache timeout"),
        _("Seconds before cached PIN expires"),
    )
    pin_group.add(pin_timeout_spin)

    page.add(pin_group)

    # Group: Logging
    log_group = Adw.PreferencesGroup()
    log_group.set_title(_("Logging"))

    # Log level
    log_level_combo = Adw.ComboRow()
    log_level_combo.set_title(_("Log level"))
    set_accessible(log_level_combo, _("Log level"), _("Verbosity of application logs"))
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

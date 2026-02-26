"""
eidas_page.py - eIDAS / EU settings page

Author: Homero Thompson del Lago del Terror

Creates the eIDAS 2.0 settings page with EU Trusted Lists, remote signing
(QTSP/CSC API), and electronic seals configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.core.remote.qtsp_presets import QTSP_PRESETS
from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _

# fmt: off
# 27 EU + 3 EEA member state codes
EU_EEA_TERRITORIES: dict[str, str] = {
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "HR": "Croatia",
    "CY": "Cyprus", "CZ": "Czechia", "DK": "Denmark", "EE": "Estonia",
    "FI": "Finland", "FR": "France", "DE": "Germany", "GR": "Greece",
    "HU": "Hungary", "IE": "Ireland", "IT": "Italy", "LV": "Latvia",
    "LT": "Lithuania", "LU": "Luxembourg", "MT": "Malta", "NL": "Netherlands",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "SK": "Slovakia",
    "SI": "Slovenia", "ES": "Spain", "SE": "Sweden",
    "IS": "Iceland (EEA)", "LI": "Liechtenstein (EEA)", "NO": "Norway (EEA)",
}
# fmt: on

_VALIDATION_MODES = ["eutl", "custom", "offline"]
_VALIDATION_LABELS = [_("EU Trusted List"), _("Custom"), _("Offline")]
_SEAL_TYPES = ["basic", "advanced", "qualified"]
_SEAL_TYPE_LABELS = [_("Basic"), _("Advanced"), _("Qualified")]
_SEAL_APPEARANCES = ["invisible", "stamp", "banner", "logo"]
_SEAL_APPEARANCE_LABELS = [_("Invisible"), _("Stamp"), _("Banner"), _("Logo")]


def _build_core_group(settings, dialog) -> Adw.PreferencesGroup:
    """Group 1: eIDAS Core settings."""
    group = Adw.PreferencesGroup()
    group.set_title(_("eIDAS Compliance"))
    group.set_description(_("EU Regulation 2024/1183 (eIDAS 2) qualified signature validation"))

    switch = Adw.SwitchRow()
    switch.set_title(_("Enable eIDAS validation"))
    switch.set_subtitle(_("Validate signatures against EU Trusted Lists"))
    switch.set_active(settings.eidas_enabled)
    set_accessible(switch, _("Enable eIDAS validation"), _("Master switch for eIDAS compliance"))
    group.add(switch)
    dialog.eidas_enabled_switch = switch

    enforce = Adw.SwitchRow()
    enforce.set_title(_("Enforce qualified signatures"))
    enforce.set_subtitle(_("Reject signatures from non-qualified TSPs"))
    enforce.set_active(settings.eidas_enforce_qualified)
    set_accessible(enforce, _("Enforce qualified"), _("Only accept qualified TSP signatures"))
    group.add(enforce)
    dialog.eidas_enforce_qualified_switch = enforce

    mode_combo = Adw.ComboRow()
    mode_combo.set_title(_("Validation mode"))
    mode_combo.set_subtitle(_("Source for trusted service provider lists"))
    mode_combo.set_model(Gtk.StringList.new(_VALIDATION_LABELS))
    cur = settings.eidas_validation_mode
    mode_combo.set_selected(_VALIDATION_MODES.index(cur) if cur in _VALIDATION_MODES else 0)
    set_accessible(mode_combo, _("Validation mode"), _("Select TSP validation source"))
    group.add(mode_combo)
    dialog.eidas_validation_mode_combo = mode_combo

    return group


def _build_trusted_lists_group(settings, dialog) -> Adw.PreferencesGroup:
    """Group 2: EU Trusted Lists configuration."""
    group = Adw.PreferencesGroup()
    group.set_title(_("EU Trusted Lists"))
    group.set_description(_("Cache and territory settings for EUTL (eIDAS Art. 22)"))

    cache_adj = Gtk.Adjustment.new(float(settings.eidas_cache_days), 1, 30, 1, 7, 0)
    cache_spin = Adw.SpinRow.new(cache_adj, 1.0, 0)
    cache_spin.set_title(_("Cache duration (days)"))
    cache_spin.set_subtitle(_("Days to cache trusted lists before refresh (1-30)"))
    set_accessible(cache_spin, _("Cache duration"), _("Days to keep EUTL cache"))
    group.add(cache_spin)
    dialog.eidas_cache_days_spin = cache_spin

    auto_switch = Adw.SwitchRow()
    auto_switch.set_title(_("Auto-update trusted lists"))
    auto_switch.set_subtitle(_("Fetch updated lists when cache expires"))
    auto_switch.set_active(settings.eidas_auto_update)
    set_accessible(auto_switch, _("Auto-update"), _("Auto-refresh EU Trusted Lists"))
    group.add(auto_switch)
    dialog.eidas_auto_update_switch = auto_switch

    # Territory selection in an ExpanderRow
    selected = set(settings.eidas_eutl_territories)
    total = len(EU_EEA_TERRITORIES)

    expander = Adw.ExpanderRow()
    expander.set_title(_("Territories"))
    if not selected:
        expander.set_subtitle(_("All territories"))
    else:
        expander.set_subtitle(
            _("{count} of {total} selected").format(count=len(selected), total=total)
        )
    set_accessible(expander, _("Territory selection"), _("EU/EEA territories for EUTL"))

    checks: dict[str, Gtk.CheckButton] = {}

    def _on_toggled(_btn):
        count = sum(1 for cb in checks.values() if cb.get_active())
        if count == 0 or count == total:
            expander.set_subtitle(_("All territories"))
        else:
            expander.set_subtitle(_("{count} of {total} selected").format(count=count, total=total))

    for code, name in EU_EEA_TERRITORIES.items():
        row = Adw.ActionRow()
        row.set_title(f"{name} ({code})")
        check = Gtk.CheckButton()
        check.set_active(code in selected if selected else True)
        check.connect("toggled", _on_toggled)
        set_accessible(check, name, _("Include {name} in trusted list").format(name=name))
        row.add_prefix(check)
        row.set_activatable_widget(check)
        expander.add_row(row)
        checks[code] = check

    group.add(expander)
    dialog.eidas_territory_expander = expander
    dialog.eidas_territory_checks = checks

    return group


def _build_remote_signing_group(settings, dialog) -> Adw.PreferencesGroup:
    """Group 3: Remote Signing (CSC API v2) settings."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Remote Signing"))
    group.set_description(_("Qualified Trust Service Provider via CSC API v2"))

    switch = Adw.SwitchRow()
    switch.set_title(_("Enable remote signing"))
    switch.set_subtitle(_("Sign documents using a cloud-based QTSP"))
    switch.set_active(settings.remote_signing_enabled)
    set_accessible(switch, _("Enable remote signing"), _("Enable cloud-based QTSP signing"))
    group.add(switch)
    dialog.remote_signing_enabled_switch = switch

    # QTSP preset combo
    preset_keys = list(QTSP_PRESETS.keys())
    preset_labels = [QTSP_PRESETS[k].name for k in preset_keys]
    dialog._qtsp_preset_keys = preset_keys

    preset_combo = Adw.ComboRow()
    preset_combo.set_title(_("QTSP provider"))
    preset_combo.set_subtitle(_("Select a pre-configured trust service provider"))
    preset_combo.set_model(Gtk.StringList.new(preset_labels))
    cur_preset = settings.remote_signing_qtsp_preset
    if cur_preset in preset_keys:
        preset_combo.set_selected(preset_keys.index(cur_preset))
    else:
        preset_combo.set_selected(preset_keys.index("custom") if "custom" in preset_keys else 0)
    set_accessible(preset_combo, _("QTSP provider"), _("Choose a QTSP preset"))
    group.add(preset_combo)
    dialog.remote_signing_preset_combo = preset_combo

    # Custom service URL (visible only when "custom" is selected)
    url_row = Adw.EntryRow()
    url_row.set_title(_("Service URL"))
    url_row.set_text(settings.remote_signing_service_url)
    set_accessible(url_row, _("Service URL"), _("CSC API v2 endpoint URL for custom QTSP"))
    url_row.set_visible(preset_keys[preset_combo.get_selected()] == "custom")
    group.add(url_row)
    dialog.remote_signing_url_entry = url_row

    def _on_preset_changed(combo, _pspec):
        url_row.set_visible(preset_keys[combo.get_selected()] == "custom")

    preset_combo.connect("notify::selected", _on_preset_changed)

    timeout_adj = Gtk.Adjustment.new(float(settings.remote_signing_timeout), 5, 120, 5, 15, 0)
    timeout_spin = Adw.SpinRow.new(timeout_adj, 1.0, 0)
    timeout_spin.set_title(_("Request timeout (seconds)"))
    timeout_spin.set_subtitle(_("Timeout for remote signing requests (5-120)"))
    set_accessible(timeout_spin, _("Request timeout"), _("Seconds to wait for QTSP response"))
    group.add(timeout_spin)
    dialog.remote_signing_timeout_spin = timeout_spin

    ssl_switch = Adw.SwitchRow()
    ssl_switch.set_title(_("Verify SSL certificates"))
    ssl_switch.set_subtitle(_("Validate server certificates for QTSP connections"))
    ssl_switch.set_active(settings.remote_signing_verify_ssl)
    set_accessible(ssl_switch, _("Verify SSL"), _("SSL certificate verification for QTSP"))
    group.add(ssl_switch)
    dialog.remote_signing_verify_ssl_switch = ssl_switch

    return group


def _build_seals_group(settings, dialog) -> Adw.PreferencesGroup:
    """Group 4: Electronic Seals (eIDAS Art. 35-40) settings."""
    group = Adw.PreferencesGroup()
    group.set_title(_("Electronic Seals"))
    group.set_description(_("Organization seals per eIDAS Articles 35-40"))

    switch = Adw.SwitchRow()
    switch.set_title(_("Enable electronic seals"))
    switch.set_subtitle(_("Allow creating organizational electronic seals"))
    switch.set_active(settings.seal_enabled)
    set_accessible(switch, _("Enable electronic seals"), _("Master switch for seal features"))
    group.add(switch)
    dialog.seal_enabled_switch = switch

    type_combo = Adw.ComboRow()
    type_combo.set_title(_("Seal type"))
    type_combo.set_subtitle(_("Level of assurance for electronic seals"))
    type_combo.set_model(Gtk.StringList.new(_SEAL_TYPE_LABELS))
    cur_type = settings.seal_default_type
    type_combo.set_selected(_SEAL_TYPES.index(cur_type) if cur_type in _SEAL_TYPES else 1)
    set_accessible(type_combo, _("Seal type"), _("Assurance level for electronic seals"))
    group.add(type_combo)
    dialog.seal_type_combo = type_combo

    app_combo = Adw.ComboRow()
    app_combo.set_title(_("Seal appearance"))
    app_combo.set_subtitle(_("Visual style for seal on documents"))
    app_combo.set_model(Gtk.StringList.new(_SEAL_APPEARANCE_LABELS))
    cur_app = settings.seal_appearance
    app_combo.set_selected(_SEAL_APPEARANCES.index(cur_app) if cur_app in _SEAL_APPEARANCES else 1)
    set_accessible(app_combo, _("Seal appearance"), _("Visual style for electronic seals"))
    group.add(app_combo)
    dialog.seal_appearance_combo = app_combo

    ts_switch = Adw.SwitchRow()
    ts_switch.set_title(_("Include timestamp"))
    ts_switch.set_subtitle(_("Embed trusted timestamp in electronic seals"))
    ts_switch.set_active(settings.seal_include_timestamp)
    set_accessible(ts_switch, _("Include timestamp"), _("Add trusted timestamp to seals"))
    group.add(ts_switch)
    dialog.seal_include_timestamp_switch = ts_switch

    return group


def create_eidas_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the eIDAS / EU settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for widget reference storage

    Returns:
        Configured PreferencesPage with eIDAS 2 options
    """
    page = Adw.PreferencesPage()
    page.set_title(_("eIDAS / EU"))
    page.set_icon_name("globe-symbolic")

    page.add(_build_core_group(settings, dialog))
    page.add(_build_trusted_lists_group(settings, dialog))
    page.add(_build_remote_signing_group(settings, dialog))
    page.add(_build_seals_group(settings, dialog))

    return page

"""
settings_saver.py - Per-section settings serialization to TOML

Extracts the save logic from SettingsDialog._save_settings()
into focused per-section functions.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pdfsigner.config.settings import reload_settings
from pdfsigner.gui.settings_pages import get_selected_language, get_selected_theme

if TYPE_CHECKING:
    from pdfsigner.gui.settings_dialog import SettingsDialog


def _bool(dialog, attr: str) -> str:
    """Get a boolean widget value as lowercase string."""
    return str(getattr(dialog, attr).get_active()).lower()


def _int(dialog, attr: str) -> int:
    """Get a spin widget value as int."""
    return int(getattr(dialog, attr).get_value())


def _add_if(dialog, lines: list[str], attr: str, key: str, fmt: str = "bool") -> None:
    """Append a config line if the widget attribute exists on dialog."""
    if not hasattr(dialog, attr):
        return
    if fmt == "bool":
        lines.append(f"{key} = {_bool(dialog, attr)}")
    elif fmt == "int":
        lines.append(f"{key} = {_int(dialog, attr)}")


def save_core_settings(dialog: SettingsDialog, lines: list[str]) -> str:
    """Save core settings (NSS, TSA, template, PIN). Returns current log level."""
    lines.extend(
        [
            "# PDFSigner - Configuration",
            f'nss_db_path = "{dialog.nss_path_entry.get_text()}"',
            f'tsa_url = "{dialog.tsa_url_row.get_text()}"',
        ]
    )

    if dialog.tsa_user_row.get_text():
        lines.append(f'tsa_username = "{dialog.tsa_user_row.get_text()}"')
    if dialog.tsa_pass_row.get_text():
        lines.append(f'tsa_password = "{dialog.tsa_pass_row.get_text()}"')

    # Template determines visibility
    template_idx = dialog.template_combo.get_selected() if hasattr(dialog, "template_combo") else 0
    template_name = ""
    if hasattr(dialog, "_template_choices") and template_idx < len(dialog._template_choices):
        template_name = dialog._template_choices[template_idx]

    is_visible = bool(template_name)
    page = "last" if dialog.page_combo.get_selected() == 0 else "first"

    lines.extend(
        [
            f"default_visible = {str(is_visible).lower()}",
            f'default_page = "{page}"',
            f'signature_template = "{template_name}"',
            f'output_suffix = "{dialog.suffix_row.get_text()}"',
            f"pin_cache_enabled = {_bool(dialog, 'pin_cache_switch')}",
            f"pin_cache_timeout_seconds = {_int(dialog, 'pin_timeout_spin')}",
        ]
    )

    levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    current_level = levels[dialog.log_level_combo.get_selected()]
    lines.append(f'log_level = "{current_level}"')

    return current_level


def save_appearance_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save appearance settings (theme, language)."""
    lines.extend(["", "# Appearance"])
    lines.append(f'theme = "{get_selected_theme(dialog)}"')
    lines.append(f'language = "{get_selected_language(dialog)}"')


def save_validation_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save validation settings (revocation check)."""
    lines.extend(["", "# Validation"])
    _add_if(dialog, lines, "revocation_switch", "revocation_check_enabled")
    _add_if(dialog, lines, "revocation_timeout_spin", "revocation_check_timeout", "int")
    _add_if(dialog, lines, "revocation_cache_ttl_spin", "revocation_cache_ttl", "int")
    _add_if(dialog, lines, "revocation_prefer_ocsp_switch", "revocation_prefer_ocsp")


def save_ltv_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save LTV settings."""
    lines.extend(["", "# LTV"])
    _add_if(dialog, lines, "ltv_switch", "ltv_enabled")
    _add_if(dialog, lines, "ltv_fail_open_switch", "ltv_fail_open")
    _add_if(dialog, lines, "ltv_ocsp_timeout_spin", "ltv_ocsp_timeout", "int")
    _add_if(dialog, lines, "ltv_crl_timeout_spin", "ltv_crl_timeout", "int")
    _add_if(dialog, lines, "ltv_prefer_ocsp_switch", "ltv_prefer_ocsp")


def save_behavior_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save behavior settings."""
    lines.extend(["", "# Behavior"])
    _add_if(dialog, lines, "recent_files_switch", "recent_files_enabled")
    _add_if(dialog, lines, "recent_files_limit_spin", "recent_files_limit", "int")
    _add_if(dialog, lines, "notifications_switch", "system_notifications_enabled")


def save_healthcare_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save healthcare and encryption settings."""
    lines.extend(["", "# Healthcare Compliance (HIPAA)"])
    _add_if(dialog, lines, "healthcare_switch", "healthcare_mode")
    _add_if(
        dialog,
        lines,
        "healthcare_session_timeout_spin",
        "healthcare_session_timeout_minutes",
        "int",
    )
    _add_if(dialog, lines, "healthcare_max_sessions_spin", "healthcare_max_sessions", "int")
    _add_if(
        dialog,
        lines,
        "healthcare_emergency_duration_spin",
        "healthcare_emergency_duration_hours",
        "int",
    )
    _add_if(
        dialog,
        lines,
        "healthcare_emergency_approval_switch",
        "healthcare_emergency_require_approval",
    )

    lines.extend(["", "# Encryption"])
    _add_if(dialog, lines, "encryption_hipaa_switch", "encryption_hipaa_mode")
    if hasattr(dialog, "encryption_strength_combo"):
        strength = "aes128" if dialog.encryption_strength_combo.get_selected() == 0 else "aes256"
        lines.append(f'encryption_default_strength = "{strength}"')
    _add_if(dialog, lines, "encryption_keyring_switch", "encryption_store_in_keyring")
    _add_if(dialog, lines, "encryption_allow_print_switch", "encryption_default_allow_print")
    _add_if(dialog, lines, "encryption_allow_copy_switch", "encryption_default_allow_copy")


def save_argentina_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save Argentina compliance settings."""
    lines.extend(["", "# Argentina Compliance (Ley 25.506)"])
    _add_if(dialog, lines, "argentine_enabled", "argentine_compliance_enabled")
    _add_if(dialog, lines, "argentine_strict_mode", "argentine_strict_mode")


def save_eidas_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save eIDAS compliance settings."""
    lines.extend(["", "# eIDAS Compliance (EU 2024/1183)"])
    _add_if(dialog, lines, "eidas_enabled_switch", "eidas_enabled")
    _add_if(dialog, lines, "eidas_enforce_qualified_switch", "eidas_enforce_qualified")

    if hasattr(dialog, "eidas_validation_mode_combo"):
        modes = ["eutl", "custom", "offline"]
        idx = dialog.eidas_validation_mode_combo.get_selected()
        if idx < len(modes):
            lines.append(f'eidas_validation_mode = "{modes[idx]}"')

    _add_if(dialog, lines, "eidas_cache_days_spin", "eidas_cache_days", "int")
    _add_if(dialog, lines, "eidas_auto_update_switch", "eidas_auto_update")

    if hasattr(dialog, "eidas_territory_checks"):
        selected = [c for c, cb in dialog.eidas_territory_checks.items() if cb.get_active()]
        if len(selected) < len(dialog.eidas_territory_checks):
            territory_str = ", ".join(f'"{t}"' for t in sorted(selected))
            lines.append(f"eidas_eutl_territories = [{territory_str}]")
        else:
            lines.append("eidas_eutl_territories = []")


def save_remote_signing_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save remote signing settings."""
    lines.extend(["", "# Remote Signing (CSC API v2)"])
    _add_if(dialog, lines, "remote_signing_enabled_switch", "remote_signing_enabled")

    if hasattr(dialog, "remote_signing_preset_combo") and hasattr(dialog, "_qtsp_preset_keys"):
        idx = dialog.remote_signing_preset_combo.get_selected()
        if idx < len(dialog._qtsp_preset_keys):
            lines.append(f'remote_signing_qtsp_preset = "{dialog._qtsp_preset_keys[idx]}"')

    if hasattr(dialog, "remote_signing_url_entry"):
        lines.append(f'remote_signing_service_url = "{dialog.remote_signing_url_entry.get_text()}"')
    _add_if(dialog, lines, "remote_signing_timeout_spin", "remote_signing_timeout", "int")
    _add_if(dialog, lines, "remote_signing_verify_ssl_switch", "remote_signing_verify_ssl")


def save_seal_settings(dialog: SettingsDialog, lines: list[str]) -> None:
    """Save electronic seals settings."""
    lines.extend(["", "# Electronic Seals (eIDAS Art. 35-40)"])
    _add_if(dialog, lines, "seal_enabled_switch", "seal_enabled")

    if hasattr(dialog, "seal_type_combo"):
        types = ["basic", "advanced", "qualified"]
        idx = dialog.seal_type_combo.get_selected()
        if idx < len(types):
            lines.append(f'seal_default_type = "{types[idx]}"')

    if hasattr(dialog, "seal_appearance_combo"):
        appearances = ["invisible", "stamp", "banner", "logo"]
        idx = dialog.seal_appearance_combo.get_selected()
        if idx < len(appearances):
            lines.append(f'seal_appearance = "{appearances[idx]}"')

    _add_if(dialog, lines, "seal_include_timestamp_switch", "seal_include_timestamp")


def save_all_settings(dialog: SettingsDialog) -> str:
    """
    Collect all settings from dialog widgets and write to config.toml.

    Returns:
        The current log level string for immediate application.
    """
    config_path = Path.home() / ".config" / "pdfsigner" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    current_level = save_core_settings(dialog, lines)
    save_appearance_settings(dialog, lines)
    save_validation_settings(dialog, lines)
    save_ltv_settings(dialog, lines)
    save_behavior_settings(dialog, lines)
    save_healthcare_settings(dialog, lines)
    save_argentina_settings(dialog, lines)
    save_eidas_settings(dialog, lines)
    save_remote_signing_settings(dialog, lines)
    save_seal_settings(dialog, lines)

    config_path.write_text("\n".join(lines))
    reload_settings()

    return current_level

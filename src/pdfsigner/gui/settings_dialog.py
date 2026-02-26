"""
settings_dialog.py - Settings dialog

Author: Homero Thompson del Lago del Terror

GTK4 dialog to configure all parameters of PDFSigner.
Settings auto-save when modified.
"""

from pathlib import Path

import gi
from loguru import logger

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from pdfsigner.config.settings import get_settings, reload_settings
from pdfsigner.gui.settings_pages import (
    create_advanced_page,
    create_appearance_page,
    create_argentina_page,
    create_behavior_page,
    create_eidas_page,
    create_general_page,
    create_healthcare_page,
    create_ltv_page,
    create_signature_page,
    create_validation_page,
    get_selected_language,
    get_selected_theme,
)
from pdfsigner.i18n import _


class SettingsDialog(Adw.PreferencesWindow):
    """
    Settings dialog for PDFSigner.

    Organized in pages:
    - General (TSA, NSS)
    - Visible Signature
    - Appearance (Theme, Language)
    - Advanced (PIN cache, logging)
    - Argentina (Ley 25.506 compliance)

    All settings auto-save when modified.
    """

    def __init__(self, **kwargs):
        """Initializes the dialog."""
        super().__init__(**kwargs)

        self.set_title(_("Preferences"))
        self.set_default_size(600, 550)
        self.set_search_enabled(False)

        self.settings = get_settings()
        self._save_timeout_id = None

        # Create pages using extracted modules
        general_page = create_general_page(self.settings, self)
        self.add(general_page)

        signature_page = create_signature_page(self.settings, self)
        self.add(signature_page)

        validation_page = create_validation_page(self.settings, self)
        self.add(validation_page)

        ltv_page = create_ltv_page(self.settings, self)
        self.add(ltv_page)

        behavior_page = create_behavior_page(self.settings, self)
        self.add(behavior_page)

        appearance_page = create_appearance_page(self.settings, self)
        self.add(appearance_page)

        advanced_page = create_advanced_page(self.settings, self)
        self.add(advanced_page)

        healthcare_page = create_healthcare_page(self.settings, self)
        self.add(healthcare_page)

        argentina_page = create_argentina_page(self.settings, self)
        self.add(argentina_page)

        eidas_page = create_eidas_page(self.settings, self)
        self.add(eidas_page)

        # Connect auto-save signals after all pages are created
        self._connect_auto_save_signals()

    def _connect_auto_save_signals(self) -> None:
        """Connect all widget signals for auto-save."""
        # General page
        if hasattr(self, "nss_path_entry"):
            self.nss_path_entry.connect("changed", self._on_setting_changed)
        if hasattr(self, "tsa_presets_row"):
            self.tsa_presets_row.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "tsa_url_row"):
            self.tsa_url_row.connect("apply", self._on_setting_changed)
            self.tsa_url_row.connect("changed", self._on_setting_changed)
        if hasattr(self, "tsa_user_row"):
            self.tsa_user_row.connect("apply", self._on_setting_changed)
            self.tsa_user_row.connect("changed", self._on_setting_changed)
        if hasattr(self, "tsa_pass_row"):
            self.tsa_pass_row.connect("apply", self._on_setting_changed)
            self.tsa_pass_row.connect("changed", self._on_setting_changed)

        # Signature page
        if hasattr(self, "template_combo"):
            self.template_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "page_combo"):
            self.page_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "suffix_row"):
            self.suffix_row.connect("apply", self._on_setting_changed)
            self.suffix_row.connect("changed", self._on_setting_changed)

        # Advanced page
        if hasattr(self, "pin_cache_switch"):
            self.pin_cache_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "pin_timeout_spin"):
            self.pin_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "log_level_combo"):
            self.log_level_combo.connect("notify::selected", self._on_setting_changed)

        # Validation page
        if hasattr(self, "revocation_switch"):
            self.revocation_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "revocation_timeout_spin"):
            self.revocation_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "revocation_cache_ttl_spin"):
            self.revocation_cache_ttl_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "revocation_prefer_ocsp_switch"):
            self.revocation_prefer_ocsp_switch.connect("notify::active", self._on_setting_changed)

        # LTV page
        if hasattr(self, "ltv_switch"):
            self.ltv_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "ltv_fail_open_switch"):
            self.ltv_fail_open_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "ltv_ocsp_timeout_spin"):
            self.ltv_ocsp_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "ltv_crl_timeout_spin"):
            self.ltv_crl_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "ltv_prefer_ocsp_switch"):
            self.ltv_prefer_ocsp_switch.connect("notify::active", self._on_setting_changed)

        # Behavior page
        if hasattr(self, "recent_files_switch"):
            self.recent_files_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "recent_files_limit_spin"):
            self.recent_files_limit_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "notifications_switch"):
            self.notifications_switch.connect("notify::active", self._on_setting_changed)

        # Healthcare page
        if hasattr(self, "healthcare_switch"):
            self.healthcare_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "healthcare_session_timeout_spin"):
            self.healthcare_session_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "healthcare_max_sessions_spin"):
            self.healthcare_max_sessions_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "healthcare_emergency_duration_spin"):
            self.healthcare_emergency_duration_spin.connect(
                "notify::value", self._on_setting_changed
            )
        if hasattr(self, "healthcare_emergency_approval_switch"):
            self.healthcare_emergency_approval_switch.connect(
                "notify::active", self._on_setting_changed
            )
        if hasattr(self, "encryption_hipaa_switch"):
            self.encryption_hipaa_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "encryption_strength_combo"):
            self.encryption_strength_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "encryption_keyring_switch"):
            self.encryption_keyring_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "encryption_allow_print_switch"):
            self.encryption_allow_print_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "encryption_allow_copy_switch"):
            self.encryption_allow_copy_switch.connect("notify::active", self._on_setting_changed)

        # Argentina page
        if hasattr(self, "argentine_enabled"):
            self.argentine_enabled.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "argentine_strict_mode"):
            self.argentine_strict_mode.connect("notify::active", self._on_setting_changed)

        # eIDAS page
        if hasattr(self, "eidas_enabled_switch"):
            self.eidas_enabled_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "eidas_enforce_qualified_switch"):
            self.eidas_enforce_qualified_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "eidas_validation_mode_combo"):
            self.eidas_validation_mode_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "eidas_cache_days_spin"):
            self.eidas_cache_days_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "eidas_auto_update_switch"):
            self.eidas_auto_update_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "remote_signing_enabled_switch"):
            self.remote_signing_enabled_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "remote_signing_preset_combo"):
            self.remote_signing_preset_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "remote_signing_url_entry"):
            self.remote_signing_url_entry.connect("changed", self._on_setting_changed)
        if hasattr(self, "remote_signing_timeout_spin"):
            self.remote_signing_timeout_spin.connect("notify::value", self._on_setting_changed)
        if hasattr(self, "remote_signing_verify_ssl_switch"):
            self.remote_signing_verify_ssl_switch.connect(
                "notify::active", self._on_setting_changed
            )
        if hasattr(self, "seal_enabled_switch"):
            self.seal_enabled_switch.connect("notify::active", self._on_setting_changed)
        if hasattr(self, "seal_type_combo"):
            self.seal_type_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "seal_appearance_combo"):
            self.seal_appearance_combo.connect("notify::selected", self._on_setting_changed)
        if hasattr(self, "seal_include_timestamp_switch"):
            self.seal_include_timestamp_switch.connect("notify::active", self._on_setting_changed)

    def _on_setting_changed(self, *args) -> None:
        """Handle any setting change with debounced auto-save."""
        # Cancel previous pending save
        if self._save_timeout_id is not None:
            GLib.source_remove(self._save_timeout_id)

        # Schedule save after 500ms debounce
        self._save_timeout_id = GLib.timeout_add(500, self._auto_save)

    def _auto_save(self) -> bool:
        """Auto-save all settings."""
        self._save_timeout_id = None

        try:
            self._save_settings()
            logger.debug("Settings auto-saved")
        except Exception as e:
            logger.error(f"Auto-save failed: {e}")

        return False  # Don't repeat

    def _save_settings(self) -> None:
        """Save all settings to config file."""
        config_path = Path.home() / ".config" / "pdfsigner" / "config.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Build TOML configuration
        lines = [
            "# PDFSigner - Configuration",
            f'nss_db_path = "{self.nss_path_entry.get_text()}"',
            f'tsa_url = "{self.tsa_url_row.get_text()}"',
        ]

        if self.tsa_user_row.get_text():
            lines.append(f'tsa_username = "{self.tsa_user_row.get_text()}"')
        if self.tsa_pass_row.get_text():
            lines.append(f'tsa_password = "{self.tsa_pass_row.get_text()}"')

        # Get selected template - template determines visibility
        template_idx = self.template_combo.get_selected() if hasattr(self, "template_combo") else 0
        template_name = ""
        if hasattr(self, "_template_choices") and template_idx < len(self._template_choices):
            template_name = self._template_choices[template_idx]

        # Visibility is determined by template: no template = invisible
        is_visible = bool(template_name)

        lines.extend(
            [
                f"default_visible = {str(is_visible).lower()}",
                f'default_page = "{"last" if self.page_combo.get_selected() == 0 else "first"}"',
                f'signature_template = "{template_name}"',
                f'output_suffix = "{self.suffix_row.get_text()}"',
                f"pin_cache_enabled = {str(self.pin_cache_switch.get_active()).lower()}",
                f"pin_cache_timeout_seconds = {int(self.pin_timeout_spin.get_value())}",
            ]
        )

        # Log level
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        current_level = levels[self.log_level_combo.get_selected()]
        lines.append(f'log_level = "{current_level}"')

        # Appearance settings
        lines.append("")
        lines.append("# Appearance")
        lines.append(f'theme = "{get_selected_theme(self)}"')
        lines.append(f'language = "{get_selected_language(self)}"')

        # Validation settings
        lines.append("")
        lines.append("# Validation")
        if hasattr(self, "revocation_switch"):
            lines.append(
                f"revocation_check_enabled = {str(self.revocation_switch.get_active()).lower()}"
            )
        if hasattr(self, "revocation_timeout_spin"):
            lines.append(
                f"revocation_check_timeout = {int(self.revocation_timeout_spin.get_value())}"
            )
        if hasattr(self, "revocation_cache_ttl_spin"):
            lines.append(
                f"revocation_cache_ttl = {int(self.revocation_cache_ttl_spin.get_value())}"
            )
        if hasattr(self, "revocation_prefer_ocsp_switch"):
            lines.append(
                f"revocation_prefer_ocsp = "
                f"{str(self.revocation_prefer_ocsp_switch.get_active()).lower()}"
            )

        # LTV settings
        lines.append("")
        lines.append("# LTV")
        if hasattr(self, "ltv_switch"):
            lines.append(f"ltv_enabled = {str(self.ltv_switch.get_active()).lower()}")
        if hasattr(self, "ltv_fail_open_switch"):
            lines.append(f"ltv_fail_open = {str(self.ltv_fail_open_switch.get_active()).lower()}")
        if hasattr(self, "ltv_ocsp_timeout_spin"):
            lines.append(f"ltv_ocsp_timeout = {int(self.ltv_ocsp_timeout_spin.get_value())}")
        if hasattr(self, "ltv_crl_timeout_spin"):
            lines.append(f"ltv_crl_timeout = {int(self.ltv_crl_timeout_spin.get_value())}")
        if hasattr(self, "ltv_prefer_ocsp_switch"):
            lines.append(
                f"ltv_prefer_ocsp = {str(self.ltv_prefer_ocsp_switch.get_active()).lower()}"
            )

        # Behavior settings
        lines.append("")
        lines.append("# Behavior")
        if hasattr(self, "recent_files_switch"):
            lines.append(
                f"recent_files_enabled = {str(self.recent_files_switch.get_active()).lower()}"
            )
        if hasattr(self, "recent_files_limit_spin"):
            lines.append(f"recent_files_limit = {int(self.recent_files_limit_spin.get_value())}")
        if hasattr(self, "notifications_switch"):
            lines.append(
                f"system_notifications_enabled = "
                f"{str(self.notifications_switch.get_active()).lower()}"
            )

        # Healthcare Compliance settings
        lines.append("")
        lines.append("# Healthcare Compliance (HIPAA)")
        if hasattr(self, "healthcare_switch"):
            lines.append(f"healthcare_mode = {str(self.healthcare_switch.get_active()).lower()}")
        if hasattr(self, "healthcare_session_timeout_spin"):
            lines.append(
                f"healthcare_session_timeout_minutes = "
                f"{int(self.healthcare_session_timeout_spin.get_value())}"
            )
        if hasattr(self, "healthcare_max_sessions_spin"):
            lines.append(
                f"healthcare_max_sessions = {int(self.healthcare_max_sessions_spin.get_value())}"
            )
        if hasattr(self, "healthcare_emergency_duration_spin"):
            lines.append(
                f"healthcare_emergency_duration_hours = "
                f"{int(self.healthcare_emergency_duration_spin.get_value())}"
            )
        if hasattr(self, "healthcare_emergency_approval_switch"):
            lines.append(
                f"healthcare_emergency_require_approval = "
                f"{str(self.healthcare_emergency_approval_switch.get_active()).lower()}"
            )

        # Encryption settings
        lines.append("")
        lines.append("# Encryption")
        if hasattr(self, "encryption_hipaa_switch"):
            lines.append(
                f"encryption_hipaa_mode = {str(self.encryption_hipaa_switch.get_active()).lower()}"
            )
        if hasattr(self, "encryption_strength_combo"):
            strength = "aes128" if self.encryption_strength_combo.get_selected() == 0 else "aes256"
            lines.append(f'encryption_default_strength = "{strength}"')
        if hasattr(self, "encryption_keyring_switch"):
            lines.append(
                f"encryption_store_in_keyring = "
                f"{str(self.encryption_keyring_switch.get_active()).lower()}"
            )
        if hasattr(self, "encryption_allow_print_switch"):
            lines.append(
                f"encryption_default_allow_print = "
                f"{str(self.encryption_allow_print_switch.get_active()).lower()}"
            )
        if hasattr(self, "encryption_allow_copy_switch"):
            lines.append(
                f"encryption_default_allow_copy = "
                f"{str(self.encryption_allow_copy_switch.get_active()).lower()}"
            )

        # Argentina Compliance settings (Ley 25.506)
        lines.append("")
        lines.append("# Argentina Compliance (Ley 25.506)")
        if hasattr(self, "argentine_enabled"):
            lines.append(
                f"argentine_compliance_enabled = {str(self.argentine_enabled.get_active()).lower()}"
            )
        if hasattr(self, "argentine_strict_mode"):
            lines.append(
                f"argentine_strict_mode = {str(self.argentine_strict_mode.get_active()).lower()}"
            )

        # eIDAS Compliance settings
        lines.append("")
        lines.append("# eIDAS Compliance (EU 2024/1183)")
        if hasattr(self, "eidas_enabled_switch"):
            lines.append(f"eidas_enabled = {str(self.eidas_enabled_switch.get_active()).lower()}")
        if hasattr(self, "eidas_enforce_qualified_switch"):
            lines.append(
                f"eidas_enforce_qualified = "
                f"{str(self.eidas_enforce_qualified_switch.get_active()).lower()}"
            )
        if hasattr(self, "eidas_validation_mode_combo"):
            modes = ["eutl", "custom", "offline"]
            idx = self.eidas_validation_mode_combo.get_selected()
            if idx < len(modes):
                lines.append(f'eidas_validation_mode = "{modes[idx]}"')
        if hasattr(self, "eidas_cache_days_spin"):
            lines.append(f"eidas_cache_days = {int(self.eidas_cache_days_spin.get_value())}")
        if hasattr(self, "eidas_auto_update_switch"):
            lines.append(
                f"eidas_auto_update = {str(self.eidas_auto_update_switch.get_active()).lower()}"
            )
        if hasattr(self, "eidas_territory_checks"):
            selected = [c for c, cb in self.eidas_territory_checks.items() if cb.get_active()]
            if len(selected) < len(self.eidas_territory_checks):
                territory_str = ", ".join(f'"{t}"' for t in sorted(selected))
                lines.append(f"eidas_eutl_territories = [{territory_str}]")
            else:
                lines.append("eidas_eutl_territories = []")

        # Remote Signing settings
        lines.append("")
        lines.append("# Remote Signing (CSC API v2)")
        if hasattr(self, "remote_signing_enabled_switch"):
            lines.append(
                f"remote_signing_enabled = "
                f"{str(self.remote_signing_enabled_switch.get_active()).lower()}"
            )
        if hasattr(self, "remote_signing_preset_combo") and hasattr(self, "_qtsp_preset_keys"):
            idx = self.remote_signing_preset_combo.get_selected()
            if idx < len(self._qtsp_preset_keys):
                lines.append(f'remote_signing_qtsp_preset = "{self._qtsp_preset_keys[idx]}"')
        if hasattr(self, "remote_signing_url_entry"):
            lines.append(
                f'remote_signing_service_url = "{self.remote_signing_url_entry.get_text()}"'
            )
        if hasattr(self, "remote_signing_timeout_spin"):
            lines.append(
                f"remote_signing_timeout = {int(self.remote_signing_timeout_spin.get_value())}"
            )
        if hasattr(self, "remote_signing_verify_ssl_switch"):
            lines.append(
                f"remote_signing_verify_ssl = "
                f"{str(self.remote_signing_verify_ssl_switch.get_active()).lower()}"
            )

        # Electronic Seals settings
        lines.append("")
        lines.append("# Electronic Seals (eIDAS Art. 35-40)")
        if hasattr(self, "seal_enabled_switch"):
            lines.append(f"seal_enabled = {str(self.seal_enabled_switch.get_active()).lower()}")
        if hasattr(self, "seal_type_combo"):
            types = ["basic", "advanced", "qualified"]
            idx = self.seal_type_combo.get_selected()
            if idx < len(types):
                lines.append(f'seal_default_type = "{types[idx]}"')
        if hasattr(self, "seal_appearance_combo"):
            appearances = ["invisible", "stamp", "banner", "logo"]
            idx = self.seal_appearance_combo.get_selected()
            if idx < len(appearances):
                lines.append(f'seal_appearance = "{appearances[idx]}"')
        if hasattr(self, "seal_include_timestamp_switch"):
            lines.append(
                f"seal_include_timestamp = "
                f"{str(self.seal_include_timestamp_switch.get_active()).lower()}"
            )

        config_path.write_text("\n".join(lines))

        # Reload configuration
        reload_settings()

        # Apply log level immediately
        self._apply_log_level(current_level)

    def _apply_log_level(self, level: str) -> None:
        """Apply log level to loguru immediately."""
        import sys

        logger.remove()
        logger.add(sys.stderr, level=level)

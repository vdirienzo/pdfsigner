"""
settings_dialog.py - Settings dialog

GTK4 dialog to configure all parameters of PDFSigner.
Settings auto-save when modified.
"""

import gi
from loguru import logger

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from pdfsigner.config.settings import get_settings
from pdfsigner.gui.settings_pages import (
    create_compliance_page,
    create_general_page,
    create_healthcare_page,
    create_security_page,
    create_signature_page,
)
from pdfsigner.gui.settings_saver import save_all_settings
from pdfsigner.i18n import _


class SettingsDialog(Adw.PreferencesWindow):
    """
    Settings dialog for PDFSigner.

    Organized in 5 pages: General, Signature, Security, Healthcare, Compliance.
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

        self.add(create_general_page(self.settings, self))
        self.add(create_signature_page(self.settings, self))
        self.add(create_security_page(self.settings, self))
        self.add(create_healthcare_page(self.settings, self))
        self.add(create_compliance_page(self.settings, self))

        self._connect_auto_save_signals()

    def _connect_auto_save_signals(self) -> None:
        """Connect all widget signals for auto-save."""
        # Map widget attrs to signal types
        _switch_widgets = [
            "pin_cache_switch",
            "revocation_switch",
            "revocation_prefer_ocsp_switch",
            "ltv_switch",
            "ltv_fail_open_switch",
            "ltv_prefer_ocsp_switch",
            "recent_files_switch",
            "notifications_switch",
            "healthcare_switch",
            "healthcare_emergency_approval_switch",
            "encryption_hipaa_switch",
            "encryption_keyring_switch",
            "encryption_allow_print_switch",
            "encryption_allow_copy_switch",
            "argentine_enabled",
            "argentine_strict_mode",
            "eidas_enabled_switch",
            "eidas_enforce_qualified_switch",
            "eidas_auto_update_switch",
            "remote_signing_enabled_switch",
            "remote_signing_verify_ssl_switch",
            "seal_enabled_switch",
            "seal_include_timestamp_switch",
        ]
        _spin_widgets = [
            "pin_timeout_spin",
            "revocation_timeout_spin",
            "revocation_cache_ttl_spin",
            "ltv_ocsp_timeout_spin",
            "ltv_crl_timeout_spin",
            "recent_files_limit_spin",
            "healthcare_session_timeout_spin",
            "healthcare_max_sessions_spin",
            "healthcare_emergency_duration_spin",
            "eidas_cache_days_spin",
            "remote_signing_timeout_spin",
        ]
        _combo_widgets = [
            "tsa_presets_row",
            "template_combo",
            "page_combo",
            "log_level_combo",
            "encryption_strength_combo",
            "eidas_validation_mode_combo",
            "remote_signing_preset_combo",
            "seal_type_combo",
            "seal_appearance_combo",
        ]
        _entry_widgets = [
            "nss_path_entry",
            "tsa_url_row",
            "tsa_user_row",
            "tsa_pass_row",
            "suffix_row",
            "remote_signing_url_entry",
        ]

        for attr in _switch_widgets:
            if hasattr(self, attr):
                getattr(self, attr).connect("notify::active", self._on_setting_changed)

        for attr in _spin_widgets:
            if hasattr(self, attr):
                getattr(self, attr).connect("notify::value", self._on_setting_changed)

        for attr in _combo_widgets:
            if hasattr(self, attr):
                getattr(self, attr).connect("notify::selected", self._on_setting_changed)

        for attr in _entry_widgets:
            if hasattr(self, attr):
                widget = getattr(self, attr)
                if hasattr(widget, "connect"):
                    widget.connect("changed", self._on_setting_changed)
                    if hasattr(widget, "set_show_apply_button"):
                        widget.connect("apply", self._on_setting_changed)

    def _on_setting_changed(self, *args) -> None:
        """Handle any setting change with debounced auto-save."""
        if self._save_timeout_id is not None:
            GLib.source_remove(self._save_timeout_id)
        self._save_timeout_id = GLib.timeout_add(500, self._auto_save)

    def _auto_save(self) -> bool:
        """Auto-save all settings."""
        self._save_timeout_id = None
        try:
            current_level = save_all_settings(self)
            self._apply_log_level(current_level)
            logger.debug("Settings auto-saved")
        except Exception as e:
            logger.error(f"Auto-save failed: {e}")
        return False

    def _apply_log_level(self, level: str) -> None:
        """Apply log level to loguru immediately."""
        import sys

        logger.remove()
        logger.add(sys.stderr, level=level)

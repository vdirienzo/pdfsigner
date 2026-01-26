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
    create_general_page,
    create_signature_page,
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

        appearance_page = create_appearance_page(self.settings, self)
        self.add(appearance_page)

        advanced_page = create_advanced_page(self.settings, self)
        self.add(advanced_page)

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

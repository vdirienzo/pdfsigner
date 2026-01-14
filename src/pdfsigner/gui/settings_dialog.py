"""
settings_dialog.py - Settings dialog

Author: Homero Thompson del Lago del Terror

GTK4 dialog to configure all parameters of PDFSigner.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.config.settings import get_settings, reload_settings
from pdfsigner.gui.settings_pages import (
    create_advanced_page,
    create_appearance_page,
    create_general_page,
    create_signature_page,
    get_selected_accent_color,
    get_selected_language,
    get_selected_theme,
)


class SettingsDialog(Adw.PreferencesWindow):
    """
    Settings dialog for PDFSigner.

    Organized in pages:
    - General (TSA, NSS)
    - Visible Signature
    - Appearance (Theme, Language)
    - Advanced (PIN cache, logging)
    """

    def __init__(self, **kwargs):
        """Initializes the dialog."""
        super().__init__(**kwargs)

        self.set_title("Preferences")
        self.set_default_size(600, 550)
        self.set_search_enabled(False)

        self.settings = get_settings()
        self.selected_accent_color = self.settings.accent_color

        # Create pages using extracted modules
        general_page = create_general_page(self.settings, self)
        self.add(general_page)

        signature_page = create_signature_page(self.settings, self)
        self.add(signature_page)

        appearance_page = create_appearance_page(self.settings, self)
        self.add(appearance_page)

        advanced_page = create_advanced_page(self.settings, self, self._on_save_clicked)
        self.add(advanced_page)

    def _on_save_clicked(self, button: Gtk.Button) -> None:
        """Saves the settings."""
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

        lines.extend(
            [
                f"default_visible = {str(self.visible_switch.get_active()).lower()}",
                f"signature_width_mm = {int(self.width_spin.get_value())}",
                f"signature_height_mm = {int(self.height_spin.get_value())}",
                f'default_page = "{"last" if self.page_combo.get_selected() == 0 else "first"}"',
                f'output_suffix = "{self.suffix_row.get_text()}"',
                f"pin_cache_enabled = {str(self.pin_cache_switch.get_active()).lower()}",
                f"pin_cache_timeout_seconds = {int(self.pin_timeout_spin.get_value())}",
            ]
        )

        # Log level
        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        lines.append(f'log_level = "{levels[self.log_level_combo.get_selected()]}"')

        # Appearance settings
        lines.append("")
        lines.append("# Appearance")
        lines.append(f'theme = "{get_selected_theme(self)}"')
        lines.append(f'accent_color = "{get_selected_accent_color(self)}"')
        lines.append(f'language = "{get_selected_language(self)}"')

        config_path.write_text("\n".join(lines))

        # Reload configuration
        reload_settings()

        # Show confirmation
        self.add_toast(Adw.Toast(title="Settings saved"))

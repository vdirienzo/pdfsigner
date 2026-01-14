"""
settings_dialog.py - Diálogo de configuración

Author: Homero Thompson del Lago del Terror

GTK4 dialog to configure all parameters
of PDFSigner.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.config.settings import get_settings, reload_settings
from pdfsigner.gui.settings_pages import (
    create_advanced_page,
    create_general_page,
    create_signature_page,
)


class SettingsDialog(Adw.PreferencesWindow):
    """
    Diálogo de configuración of PDFSigner.

    Organizado en páginas:
    - General (TSA, NSS)
    - Firma Visible
    - Avanzado (PIN cache, logging)
    """

    def __init__(self, **kwargs):
        """Initializes the dialog."""
        super().__init__(**kwargs)

        self.set_title("Preferences")
        self.set_default_size(600, 500)
        self.set_search_enabled(False)

        self.settings = get_settings()

        # Create pages using extracted modules
        general_page = create_general_page(self.settings, self)
        self.add(general_page)

        signature_page = create_signature_page(self.settings, self)
        self.add(signature_page)

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

        levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        lines.append(f'log_level = "{levels[self.log_level_combo.get_selected()]}"')

        config_path.write_text("\n".join(lines))

        # Recargar configuración
        reload_settings()

        # Mostrar confirmación
        self.add_toast(Adw.Toast(title="Settings saved"))

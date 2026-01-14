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

        self._create_general_page()
        self._create_signature_page()
        self._create_advanced_page()

    def _create_general_page(self) -> None:
        """Creates the general settings page."""
        page = Adw.PreferencesPage()
        page.set_title("General")
        page.set_icon_name("preferences-system-symbolic")

        # Grupo: NSS/Token
        nss_group = Adw.PreferencesGroup()
        nss_group.set_title("USB Token")
        nss_group.set_description("NSS database configuration")

        # NSS Path
        self.nss_path_row = Adw.EntryRow()
        self.nss_path_row.set_title("NSS Database Path")
        self.nss_path_row.set_text(str(self.settings.nss_db_path))
        self.nss_path_row.set_show_apply_button(True)
        self.nss_path_row.connect("apply", self._on_setting_changed)
        nss_group.add(self.nss_path_row)

        page.add(nss_group)

        # Grupo: TSA
        tsa_group = Adw.PreferencesGroup()
        tsa_group.set_title("Timestamp Server (TSA)")
        tsa_group.set_description("Required for PAdES-LTV signatures with legal validity")

        # TSA URL
        self.tsa_url_row = Adw.EntryRow()
        self.tsa_url_row.set_title("TSA URL")
        self.tsa_url_row.set_text(self.settings.tsa_url or "")
        self.tsa_url_row.set_show_apply_button(True)
        self.tsa_url_row.connect("apply", self._on_setting_changed)
        tsa_group.add(self.tsa_url_row)

        # TSA presets
        presets_row = Adw.ComboRow()
        presets_row.set_title("Preconfigured TSAs")
        presets_row.set_subtitle("Select a free public TSA")

        presets = Gtk.StringList.new(
            [
                "Custom",
                "FreeTSA (freetsa.org)",
                "DigiCert",
                "Sectigo",
                "GlobalSign",
            ]
        )
        presets_row.set_model(presets)
        presets_row.connect("notify::selected", self._on_tsa_preset_selected)
        tsa_group.add(presets_row)
        self.tsa_presets_row = presets_row

        # Credenciales TSA
        self.tsa_user_row = Adw.EntryRow()
        self.tsa_user_row.set_title("TSA Username (optional)")
        self.tsa_user_row.set_text(self.settings.tsa_username or "")
        self.tsa_user_row.set_show_apply_button(True)
        tsa_group.add(self.tsa_user_row)

        self.tsa_pass_row = Adw.PasswordEntryRow()
        self.tsa_pass_row.set_title("TSA Password (optional)")
        self.tsa_pass_row.set_text(self.settings.tsa_password or "")
        self.tsa_pass_row.set_show_apply_button(True)
        tsa_group.add(self.tsa_pass_row)

        page.add(tsa_group)
        self.add(page)

    def _create_signature_page(self) -> None:
        """Creates the visible signature settings page."""
        page = Adw.PreferencesPage()
        page.set_title("Visible Signature")
        page.set_icon_name("edit-symbolic")

        # Grupo: Apariencia
        appearance_group = Adw.PreferencesGroup()
        appearance_group.set_title("Appearance")

        # Firma visible por defecto
        self.visible_switch = Adw.SwitchRow()
        self.visible_switch.set_title("Visible signature by default")
        self.visible_switch.set_subtitle("Show signature stamp on document")
        self.visible_switch.set_active(self.settings.default_visible)
        appearance_group.add(self.visible_switch)

        # Página por defecto
        self.page_combo = Adw.ComboRow()
        self.page_combo.set_title("Default page")
        pages = Gtk.StringList.new(["Last page", "First page"])
        self.page_combo.set_model(pages)
        self.page_combo.set_selected(0 if self.settings.default_page == "last" else 1)
        appearance_group.add(self.page_combo)

        page.add(appearance_group)

        # Grupo: Dimensiones
        dimensions_group = Adw.PreferencesGroup()
        dimensions_group.set_title("Stamp dimensions")

        # Ancho
        self.width_spin = Adw.SpinRow.new_with_range(20, 100, 5)
        self.width_spin.set_title("Width (mm)")
        self.width_spin.set_value(self.settings.signature_width_mm)
        dimensions_group.add(self.width_spin)

        # Alto
        self.height_spin = Adw.SpinRow.new_with_range(10, 50, 5)
        self.height_spin.set_title("Height (mm)")
        self.height_spin.set_value(self.settings.signature_height_mm)
        dimensions_group.add(self.height_spin)

        page.add(dimensions_group)

        # Grupo: Output
        output_group = Adw.PreferencesGroup()
        output_group.set_title("Output files")

        # Sufijo
        self.suffix_row = Adw.EntryRow()
        self.suffix_row.set_title("Suffix for signed files")
        self.suffix_row.set_text(self.settings.output_suffix)
        self.suffix_row.set_show_apply_button(True)
        output_group.add(self.suffix_row)

        page.add(output_group)
        self.add(page)

    def _create_advanced_page(self) -> None:
        """Creates the advanced settings page."""
        page = Adw.PreferencesPage()
        page.set_title("Advanced")
        page.set_icon_name("applications-system-symbolic")

        # Grupo: PIN Cache
        pin_group = Adw.PreferencesGroup()
        pin_group.set_title("PIN Cache")
        pin_group.set_description("Cache PIN during batch signing")

        # Habilitar cache
        self.pin_cache_switch = Adw.SwitchRow()
        self.pin_cache_switch.set_title("Enable PIN cache")
        self.pin_cache_switch.set_subtitle("More convenient but less secure")
        self.pin_cache_switch.set_active(self.settings.pin_cache_enabled)
        pin_group.add(self.pin_cache_switch)

        # Timeout
        self.pin_timeout_spin = Adw.SpinRow.new_with_range(60, 3600, 60)
        self.pin_timeout_spin.set_title("Timeout (seconds)")
        self.pin_timeout_spin.set_value(self.settings.pin_cache_timeout_seconds)
        pin_group.add(self.pin_timeout_spin)

        page.add(pin_group)

        # Grupo: Logging
        log_group = Adw.PreferencesGroup()
        log_group.set_title("Logging")

        # Nivel de log
        self.log_level_combo = Adw.ComboRow()
        self.log_level_combo.set_title("Log level")
        levels = Gtk.StringList.new(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.set_model(levels)

        level_index = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
        self.log_level_combo.set_selected(level_index.get(self.settings.log_level, 1))
        log_group.add(self.log_level_combo)

        page.add(log_group)

        # Grupo: Acciones
        actions_group = Adw.PreferencesGroup()

        # Botón guardar
        save_button = Gtk.Button(label="Save settings")
        save_button.add_css_class("suggested-action")
        save_button.connect("clicked", self._on_save_clicked)
        actions_group.add(save_button)

        page.add(actions_group)
        self.add(page)

    def _on_tsa_preset_selected(self, combo, param) -> None:
        """Handles preconfigured TSA selection."""
        presets = {
            0: "",  # Personalizado
            1: "https://freetsa.org/tsr",
            2: "http://timestamp.digicert.com",
            3: "http://timestamp.sectigo.com",
            4: "http://timestamp.globalsign.com/tsa/r6advanced1",
        }

        selected = combo.get_selected()
        if selected > 0:
            url = presets.get(selected, "")
            self.tsa_url_row.set_text(url)

    def _on_setting_changed(self, row) -> None:
        """Handles change in a setting."""
        pass  # Se guarda al presionar "Guardar"

    def _on_save_clicked(self, button: Gtk.Button) -> None:
        """Saves the settings."""
        config_path = Path.home() / ".config" / "pdfsigner" / "config.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Construir TOML
        lines = [
            "# PDFSigner - Configuración",
            f'nss_db_path = "{self.nss_path_row.get_text()}"',
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

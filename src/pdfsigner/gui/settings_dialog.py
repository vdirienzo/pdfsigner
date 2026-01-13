"""
settings_dialog.py - Diálogo de configuración

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 para configurar todos los parámetros
de PDFSigner.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.config.settings import get_settings, reload_settings


class SettingsDialog(Adw.PreferencesWindow):
    """
    Diálogo de configuración de PDFSigner.

    Organizado en páginas:
    - General (TSA, NSS)
    - Firma Visible
    - Avanzado (PIN cache, logging)
    """

    def __init__(self, **kwargs):
        """Inicializa el diálogo."""
        super().__init__(**kwargs)

        self.set_title("Configuración")
        self.set_default_size(600, 500)
        self.set_search_enabled(False)

        self.settings = get_settings()

        self._create_general_page()
        self._create_signature_page()
        self._create_advanced_page()

    def _create_general_page(self) -> None:
        """Crea la página de configuración general."""
        page = Adw.PreferencesPage()
        page.set_title("General")
        page.set_icon_name("preferences-system-symbolic")

        # Grupo: NSS/Token
        nss_group = Adw.PreferencesGroup()
        nss_group.set_title("Token USB")
        nss_group.set_description("Configuración de la base de datos NSS")

        # NSS Path
        self.nss_path_row = Adw.EntryRow()
        self.nss_path_row.set_title("Ruta NSS Database")
        self.nss_path_row.set_text(str(self.settings.nss_db_path))
        self.nss_path_row.set_show_apply_button(True)
        self.nss_path_row.connect("apply", self._on_setting_changed)
        nss_group.add(self.nss_path_row)

        page.add(nss_group)

        # Grupo: TSA
        tsa_group = Adw.PreferencesGroup()
        tsa_group.set_title("Servidor de Timestamp (TSA)")
        tsa_group.set_description("Requerido para firmas PAdES-LTV con validez legal")

        # TSA URL
        self.tsa_url_row = Adw.EntryRow()
        self.tsa_url_row.set_title("URL del TSA")
        self.tsa_url_row.set_text(self.settings.tsa_url or "")
        self.tsa_url_row.set_show_apply_button(True)
        self.tsa_url_row.connect("apply", self._on_setting_changed)
        tsa_group.add(self.tsa_url_row)

        # TSA presets
        presets_row = Adw.ComboRow()
        presets_row.set_title("TSA Preconfigurados")
        presets_row.set_subtitle("Selecciona un TSA público gratuito")

        presets = Gtk.StringList.new(
            [
                "Personalizado",
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
        self.tsa_user_row.set_title("Usuario TSA (opcional)")
        self.tsa_user_row.set_text(self.settings.tsa_username or "")
        self.tsa_user_row.set_show_apply_button(True)
        tsa_group.add(self.tsa_user_row)

        self.tsa_pass_row = Adw.PasswordEntryRow()
        self.tsa_pass_row.set_title("Contraseña TSA (opcional)")
        self.tsa_pass_row.set_text(self.settings.tsa_password or "")
        self.tsa_pass_row.set_show_apply_button(True)
        tsa_group.add(self.tsa_pass_row)

        page.add(tsa_group)
        self.add(page)

    def _create_signature_page(self) -> None:
        """Crea la página de configuración de firma visible."""
        page = Adw.PreferencesPage()
        page.set_title("Firma Visible")
        page.set_icon_name("edit-symbolic")

        # Grupo: Apariencia
        appearance_group = Adw.PreferencesGroup()
        appearance_group.set_title("Apariencia")

        # Firma visible por defecto
        self.visible_switch = Adw.SwitchRow()
        self.visible_switch.set_title("Firma visible por defecto")
        self.visible_switch.set_subtitle("Mostrar sello de firma en el documento")
        self.visible_switch.set_active(self.settings.default_visible)
        appearance_group.add(self.visible_switch)

        # Página por defecto
        self.page_combo = Adw.ComboRow()
        self.page_combo.set_title("Página por defecto")
        pages = Gtk.StringList.new(["Última página", "Primera página"])
        self.page_combo.set_model(pages)
        self.page_combo.set_selected(0 if self.settings.default_page == "last" else 1)
        appearance_group.add(self.page_combo)

        page.add(appearance_group)

        # Grupo: Dimensiones
        dimensions_group = Adw.PreferencesGroup()
        dimensions_group.set_title("Dimensiones del sello")

        # Ancho
        self.width_spin = Adw.SpinRow.new_with_range(20, 100, 5)
        self.width_spin.set_title("Ancho (mm)")
        self.width_spin.set_value(self.settings.signature_width_mm)
        dimensions_group.add(self.width_spin)

        # Alto
        self.height_spin = Adw.SpinRow.new_with_range(10, 50, 5)
        self.height_spin.set_title("Alto (mm)")
        self.height_spin.set_value(self.settings.signature_height_mm)
        dimensions_group.add(self.height_spin)

        page.add(dimensions_group)

        # Grupo: Output
        output_group = Adw.PreferencesGroup()
        output_group.set_title("Archivos de salida")

        # Sufijo
        self.suffix_row = Adw.EntryRow()
        self.suffix_row.set_title("Sufijo para archivos firmados")
        self.suffix_row.set_text(self.settings.output_suffix)
        self.suffix_row.set_show_apply_button(True)
        output_group.add(self.suffix_row)

        page.add(output_group)
        self.add(page)

    def _create_advanced_page(self) -> None:
        """Crea la página de configuración avanzada."""
        page = Adw.PreferencesPage()
        page.set_title("Avanzado")
        page.set_icon_name("applications-system-symbolic")

        # Grupo: PIN Cache
        pin_group = Adw.PreferencesGroup()
        pin_group.set_title("Cache de PIN")
        pin_group.set_description("Cachear PIN durante firma en lote")

        # Habilitar cache
        self.pin_cache_switch = Adw.SwitchRow()
        self.pin_cache_switch.set_title("Habilitar cache de PIN")
        self.pin_cache_switch.set_subtitle("Más cómodo pero menos seguro")
        self.pin_cache_switch.set_active(self.settings.pin_cache_enabled)
        pin_group.add(self.pin_cache_switch)

        # Timeout
        self.pin_timeout_spin = Adw.SpinRow.new_with_range(60, 3600, 60)
        self.pin_timeout_spin.set_title("Timeout (segundos)")
        self.pin_timeout_spin.set_value(self.settings.pin_cache_timeout_seconds)
        pin_group.add(self.pin_timeout_spin)

        page.add(pin_group)

        # Grupo: Logging
        log_group = Adw.PreferencesGroup()
        log_group.set_title("Logging")

        # Nivel de log
        self.log_level_combo = Adw.ComboRow()
        self.log_level_combo.set_title("Nivel de log")
        levels = Gtk.StringList.new(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.set_model(levels)

        level_index = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
        self.log_level_combo.set_selected(level_index.get(self.settings.log_level, 1))
        log_group.add(self.log_level_combo)

        page.add(log_group)

        # Grupo: Acciones
        actions_group = Adw.PreferencesGroup()

        # Botón guardar
        save_button = Gtk.Button(label="Guardar configuración")
        save_button.add_css_class("suggested-action")
        save_button.connect("clicked", self._on_save_clicked)
        actions_group.add(save_button)

        page.add(actions_group)
        self.add(page)

    def _on_tsa_preset_selected(self, combo, param) -> None:
        """Maneja selección de TSA preconfigurado."""
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
        """Maneja cambio en una configuración."""
        pass  # Se guarda al presionar "Guardar"

    def _on_save_clicked(self, button: Gtk.Button) -> None:
        """Guarda la configuración."""
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
        self.add_toast(Adw.Toast(title="Configuración guardada"))

"""
app.py - Aplicación GTK4 principal

Autor: Homero Thompson del Lago del Terror

Entry point de la aplicación GUI standalone.
"""

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk

from pdfsigner.gui.main_window import MainWindow

# Ruta al icono de la aplicación
ICON_PATH = Path(__file__).parent.parent / "ui" / "icon" / "icon.png"
APP_ID = "com.pdfsigner.app"


class PDFSignerApp(Adw.Application):
    """
    Aplicación principal de PDFSigner.

    Usa libadwaita para una apariencia moderna
    consistente con GNOME.
    """

    def __init__(self):
        """Inicializa la aplicación."""
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.HANDLES_OPEN,
        )

        self.window = None

        # Acciones
        self.create_actions()

    def create_actions(self) -> None:
        """Crea las acciones de la aplicación."""
        # Acción: Abrir archivos
        action_open = Gio.SimpleAction.new("open", None)
        action_open.connect("activate", self.on_open_action)
        self.add_action(action_open)

        # Acción: Configuración
        action_preferences = Gio.SimpleAction.new("preferences", None)
        action_preferences.connect("activate", self.on_preferences_action)
        self.add_action(action_preferences)

        # Acción: Acerca de
        action_about = Gio.SimpleAction.new("about", None)
        action_about.connect("activate", self.on_about_action)
        self.add_action(action_about)

        # Acción: Salir
        action_quit = Gio.SimpleAction.new("quit", None)
        action_quit.connect("activate", self.on_quit_action)
        self.add_action(action_quit)

        # Atajos de teclado
        self.set_accels_for_action("app.open", ["<Control>o"])
        self.set_accels_for_action("app.preferences", ["<Control>comma"])
        self.set_accels_for_action("app.quit", ["<Control>q"])

    def do_startup(self) -> None:
        """Inicialización al arrancar la aplicación."""
        Adw.Application.do_startup(self)

    def do_activate(self) -> None:
        """Activa la aplicación."""
        if not self.window:
            self.window = MainWindow(application=self)
            self.window.set_icon_name(APP_ID)

        self.window.present()

    def do_open(self, files: list, n_files: int, hint: str) -> None:
        """Maneja archivos abiertos desde el sistema."""
        self.do_activate()

        paths = [f.get_path() for f in files if f.get_path()]
        if paths:
            self.window.add_files(paths)

    def on_open_action(self, action, param) -> None:
        """Acción: Abrir archivos."""
        if self.window:
            self.window.show_file_chooser()

    def on_preferences_action(self, action, param) -> None:
        """Acción: Mostrar configuración."""
        if self.window:
            self.window.show_settings()

    def on_about_action(self, action, param) -> None:
        """Acción: Mostrar diálogo Acerca de."""
        about = Adw.AboutWindow(
            transient_for=self.window,
            application_name="PDFSigner",
            application_icon=APP_ID,
            developer_name="Homero Thompson del Lago del Terror",
            version="0.1.0",
            comments="Firma digital de PDFs con token USB SafeNet 5110",
            website="https://github.com/user/pdfsigner",
            license_type=Gtk.License.MIT_X11,
            developers=["Homero Thompson del Lago del Terror"],
        )
        about.present()

    def on_quit_action(self, action, param) -> None:
        """Acción: Salir."""
        self.quit()


def run_gui() -> int:
    """Entry point para la GUI."""
    app = PDFSignerApp()
    return app.run(sys.argv)

"""
main_window.py - Ventana principal de PDFSigner

Autor: Homero Thompson del Lago del Terror

Ventana principal con lista de archivos, drag & drop,
y acciones de firma/validación.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from pdfsigner.gui.file_list_widget import FileListWidget
from pdfsigner.gui.settings_dialog import SettingsDialog
from pdfsigner.gui.signing_handler import SigningHandler


class MainWindow(Adw.ApplicationWindow):
    """
    Ventana principal de PDFSigner.

    Contiene:
    - Área de drag & drop para archivos
    - Lista de archivos a procesar
    - Botones de acción (firmar, validar, limpiar)
    - Menú con configuración
    """

    def __init__(self, **kwargs):
        """Inicializa la ventana."""
        super().__init__(**kwargs)

        self.set_title("PDFSigner")
        self.set_default_size(700, 500)

        self.signing_handler = SigningHandler(self)
        self.validation_handler = self._create_validation_handler()

        self._setup_ui()
        self._setup_drag_drop()

    def _setup_ui(self) -> None:
        """Configura la interfaz de usuario."""
        # Header bar
        header = Adw.HeaderBar()

        # Menú principal
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(self._create_menu())
        header.pack_end(menu_button)

        # Botón de configuración rápida
        settings_button = Gtk.Button(icon_name="emblem-system-symbolic")
        settings_button.set_tooltip_text("Configuración")
        settings_button.connect("clicked", lambda b: self.show_settings())
        header.pack_end(settings_button)

        # Botón de agregar archivos
        add_button = Gtk.Button(icon_name="list-add-symbolic")
        add_button.set_tooltip_text("Agregar archivos")
        add_button.connect("clicked", lambda b: self.show_file_chooser())
        header.pack_start(add_button)

        # Toolbar box
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Área central
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Widget de lista de archivos
        self.file_list = FileListWidget()
        self.file_list.set_vexpand(True)
        content_box.append(self.file_list)

        # Barra de acciones inferior
        action_bar = self._create_action_bar()
        content_box.append(action_bar)

        toolbar.set_content(content_box)

        # Envolver en ToastOverlay para notificaciones
        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(toolbar)
        self.set_content(self.toast_overlay)

    def _create_menu(self) -> Gio.Menu:
        """Crea el menú principal."""
        menu = Gio.Menu()

        menu.append("Abrir archivos...", "app.open")
        menu.append("Configuración", "app.preferences")

        section = Gio.Menu()
        section.append("Acerca de", "app.about")
        section.append("Salir", "app.quit")
        menu.append_section(None, section)

        return menu

    def _create_action_bar(self) -> Gtk.Box:
        """Crea la barra de acciones inferior."""
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        bar.set_margin_top(12)
        bar.set_margin_bottom(12)
        bar.set_margin_start(12)
        bar.set_margin_end(12)

        # Info de archivos
        self.info_label = Gtk.Label(label="Arrastra archivos PDF aquí")
        self.info_label.set_hexpand(True)
        self.info_label.set_xalign(0)
        self.info_label.add_css_class("dim-label")
        bar.append(self.info_label)

        # Botón limpiar
        clear_button = Gtk.Button(label="Limpiar")
        clear_button.connect("clicked", self._on_clear_clicked)
        bar.append(clear_button)

        # Botón validar
        validate_button = Gtk.Button(label="Validar")
        validate_button.add_css_class("suggested-action")
        validate_button.connect("clicked", self._on_validate_clicked)
        bar.append(validate_button)

        # Botón firmar
        self.sign_button = Gtk.Button(label="Firmar")
        self.sign_button.add_css_class("suggested-action")
        self.sign_button.connect("clicked", self._on_sign_clicked)
        bar.append(self.sign_button)

        return bar

    def _setup_drag_drop(self) -> None:
        """Configura drag & drop."""
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop_target.connect("drop", self._on_drop)
        self.add_controller(drop_target)

    def _on_drop(self, target, value, x, y) -> bool:
        """Maneja archivos soltados."""
        if isinstance(value, Gdk.FileList):
            files = value.get_files()
            paths = [f.get_path() for f in files if f.get_path()]
            self.add_files(paths)
            return True
        return False

    def add_files(self, paths: list[str]) -> None:
        """
        Agrega archivos a la lista.

        Args:
            paths: Lista de rutas de archivos
        """
        added = 0
        for path_str in paths:
            path = Path(path_str)
            if path.is_file() and path.suffix.lower() == ".pdf":
                self.file_list.add_file(path)
                added += 1
            elif path.is_dir():
                for pdf in path.glob("*.pdf"):
                    self.file_list.add_file(pdf)
                    added += 1

        self._update_info_label()

        if added > 0:
            self.show_toast(f"{added} archivo(s) agregado(s)")

    def _update_info_label(self) -> None:
        """Actualiza el label de información."""
        count = self.file_list.get_file_count()
        if count == 0:
            self.info_label.set_label("Arrastra archivos PDF aquí")
        else:
            self.info_label.set_label(f"{count} archivo(s) seleccionado(s)")

    def _on_clear_clicked(self, button: Gtk.Button) -> None:
        """Limpia la lista de archivos."""
        self.file_list.clear()
        self._update_info_label()

    def _create_validation_handler(self):
        """Crea el handler de validación (import lazy para evitar circular)."""
        from pdfsigner.gui.validation_handler import ValidationHandler

        return ValidationHandler(self)

    def _on_validate_clicked(self, button: Gtk.Button) -> None:
        """Valida los archivos seleccionados."""
        files = self.file_list.get_files()
        if not files:
            self.show_toast("No hay archivos para validar")
            return

        self.validation_handler.validate_files(files)

    def _on_sign_clicked(self, button: Gtk.Button) -> None:
        """Firma los archivos seleccionados."""
        files = self.file_list.get_files()
        if not files:
            self.show_toast("No hay archivos para firmar")
            return

        self.signing_handler.sign_files(files)

    def show_file_chooser(self) -> None:
        """Muestra diálogo de selección de archivos."""
        dialog = Gtk.FileDialog()
        dialog.set_title("Seleccionar PDFs")

        # Filtro PDF
        filter_pdf = Gtk.FileFilter()
        filter_pdf.set_name("Archivos PDF")
        filter_pdf.add_mime_type("application/pdf")

        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_pdf)
        dialog.set_filters(filters)

        dialog.open_multiple(self, None, self._on_files_selected)

    def _on_files_selected(self, dialog, result) -> None:
        """Callback cuando se seleccionan archivos."""
        try:
            files = dialog.open_multiple_finish(result)
            if files:
                paths = [f.get_path() for f in files if f.get_path()]
                self.add_files(paths)
        except GLib.Error:
            pass  # Usuario canceló

    def show_settings(self) -> None:
        """Muestra el diálogo de configuración."""
        dialog = SettingsDialog(transient_for=self)
        dialog.present()

    def show_toast(self, message: str) -> None:
        """Muestra una notificación toast."""
        toast = Adw.Toast(title=message)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

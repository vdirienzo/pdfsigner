"""
file_list_widget.py - Widget de lista de archivos

Author: Homero Thompson del Lago del Terror

GTK4 widget that displays the list of PDF files
with status and individual actions.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.validator.pdf_validator import PDFValidator


class FileRow(Gtk.Box):
    """Individual row for a PDF file."""

    def __init__(self, file_path: Path):
        """
        Initializes the row.

        Args:
            file_path: Ruta al archivo PDF
        """
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        self.file_path = file_path
        self.status = "pending"  # pending, signed, error

        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(12)
        self.set_margin_end(12)

        # Icono de estado
        self.status_icon = Gtk.Label(label="○")
        self.status_icon.set_size_request(24, -1)
        self.append(self.status_icon)

        # Info del archivo
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        info_box.set_hexpand(True)

        # Nombre
        self.name_label = Gtk.Label(label=file_path.name)
        self.name_label.set_xalign(0)
        self.name_label.set_ellipsize(True)
        self.name_label.add_css_class("heading")
        info_box.append(self.name_label)

        # Ruta
        self.path_label = Gtk.Label(label=str(file_path.parent))
        self.path_label.set_xalign(0)
        self.path_label.set_ellipsize(True)
        self.path_label.add_css_class("dim-label")
        self.path_label.add_css_class("caption")
        info_box.append(self.path_label)

        self.append(info_box)

        # Info de firma (si está firmado)
        self.signature_label = Gtk.Label()
        self.signature_label.add_css_class("dim-label")
        self.append(self.signature_label)

        # Botón quitar
        remove_button = Gtk.Button(icon_name="user-trash-symbolic")
        remove_button.add_css_class("flat")
        remove_button.set_tooltip_text("Remove from list")
        remove_button.connect("clicked", self._on_remove_clicked)
        self.append(remove_button)

        # Verificar si ya está firmado
        self._check_signature_status()

    def _check_signature_status(self) -> None:
        """Checks if the file already has signatures."""
        try:
            validator = PDFValidator()
            count = validator.get_signature_count(self.file_path)
            if count > 0:
                self.signature_label.set_label(f"{count} signature(s)")
                self.status_icon.set_label("✓")
                self.status_icon.add_css_class("success")
        except Exception:
            pass

    def _on_remove_clicked(self, button: Gtk.Button) -> None:
        """Removes this file from the list."""
        # En GTK4, el widget está envuelto en un ListBoxRow
        # Necesitamos obtener el ListBox (abuelo) para remover
        row = self.get_parent()  # ListBoxRow
        if row:
            listbox = row.get_parent()  # ListBox
            if listbox and hasattr(listbox, "remove"):
                listbox.remove(row)

    def set_status(self, status: str, message: str = "") -> None:
        """
        Updates the file status.

        Args:
            status: pending, processing, signed, error
            message: Mensaje adicional
        """
        self.status = status

        icons = {
            "pending": ("○", ""),
            "processing": ("→", ""),
            "signed": ("✓", "success"),
            "error": ("✗", "error"),
        }

        icon, css_class = icons.get(status, ("○", ""))
        self.status_icon.set_label(icon)

        # Limpiar clases anteriores
        for cls in ["success", "error", "warning"]:
            self.status_icon.remove_css_class(cls)

        if css_class:
            self.status_icon.add_css_class(css_class)

        if message:
            self.signature_label.set_label(message)


class FileListWidget(Gtk.ScrolledWindow):
    """
    Widget de lista de archivos PDF.

    Muestra archivos con estado y permite
    agregar/quitar archivos.
    """

    def __init__(self):
        """Initializes the widget."""
        super().__init__()

        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        # ListBox para los archivos
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_placeholder(self._create_placeholder())

        # Frame
        frame = Gtk.Frame()
        frame.set_margin_top(12)
        frame.set_margin_bottom(0)
        frame.set_margin_start(12)
        frame.set_margin_end(12)
        frame.set_child(self.listbox)

        self.set_child(frame)

        # Set de paths para evitar duplicados
        self._file_paths: set[Path] = set()

    def _create_placeholder(self) -> Gtk.Box:
        """Creates the placeholder when there are no files."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_margin_top(48)
        box.set_margin_bottom(48)

        icon = Gtk.Image.new_from_icon_name("document-open-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("dim-label")
        box.append(icon)

        label = Gtk.Label(label="Drag PDF files here\nor use the + button to add them")
        label.set_justify(Gtk.Justification.CENTER)
        label.add_css_class("dim-label")
        box.append(label)

        return box

    def add_file(self, file_path: Path) -> bool:
        """
        Adds a file to the list.

        Args:
            file_path: Ruta al archivo

        Returns:
            True si se agregó, False si ya existía
        """
        if file_path in self._file_paths:
            return False

        self._file_paths.add(file_path)

        row = FileRow(file_path)
        self.listbox.append(row)

        return True

    def remove_file(self, file_path: Path) -> None:
        """Removes a file from the list."""
        self._file_paths.discard(file_path)

        # Buscar y quitar la fila
        child = self.listbox.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            if hasattr(child, "file_path") and child.file_path == file_path:
                self.listbox.remove(child)
                break
            child = next_child

    def clear(self) -> None:
        """Clears all files."""
        self._file_paths.clear()

        # Quitar todas las filas
        while True:
            child = self.listbox.get_first_child()
            if child is None:
                break
            self.listbox.remove(child)

    def get_files(self) -> list[Path]:
        """Gets the list of files."""
        return list(self._file_paths)

    def get_file_count(self) -> int:
        """Gets the number of files."""
        return len(self._file_paths)

    def get_rows(self) -> list[FileRow]:
        """Gets all rows."""
        rows = []
        child = self.listbox.get_first_child()
        while child:
            if isinstance(child, FileRow):
                rows.append(child)
            child = child.get_next_sibling()
        return rows

    def update_file_status(self, file_path: Path, status: str, message: str = "") -> None:
        """
        Updates a file status.

        Args:
            file_path: Ruta del archivo
            status: Nuevo estado
            message: Mensaje opcional
        """
        for row in self.get_rows():
            if row.file_path == file_path:
                row.set_status(status, message)
                break

"""
file_list_widget.py - Widget de lista de archivos

Author: Homero Thompson del Lago del Terror

GTK4 widget that displays the list of PDF files
with status and individual actions.
"""

from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from pdfsigner.core.validator.pdf_validator import PDFValidator, ValidationResult
from pdfsigner.i18n import _


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
        self.validation_result: ValidationResult | None = None

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

        # Botón info (oculto hasta que haya firmas)
        self.info_button = Gtk.Button(icon_name="dialog-information-symbolic")
        self.info_button.add_css_class("flat")
        self.info_button.set_tooltip_text(_("View signature details"))
        self.info_button.connect("clicked", self._on_info_clicked)
        self.info_button.set_visible(False)
        self.append(self.info_button)

        # Botón quitar
        remove_button = Gtk.Button(icon_name="user-trash-symbolic")
        remove_button.add_css_class("flat")
        remove_button.set_tooltip_text(_("Remove from list"))
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
                # Quick display (immediate)
                self.signature_label.set_label(_("{} signature(s)").format(count))
                self.status_icon.set_label("✓")
                self.status_icon.add_css_class("success")
                self.info_button.set_visible(True)

                # Detailed validation (background thread)
                Thread(target=self._load_signature_details, daemon=True).start()
        except Exception:
            pass

    def _load_signature_details(self) -> None:
        """Load full signature details in background thread."""
        try:
            validator = PDFValidator()
            self.validation_result = validator.validate(self.file_path)
            GLib.idle_add(self._update_signature_summary)
        except Exception:
            pass

    def _update_signature_summary(self) -> bool:
        """Update UI with validation status icon (main thread)."""
        if not self.validation_result:
            return False

        # Update icon based on validity (keep count text as-is)
        if self.validation_result.all_valid:
            icon, css = "✓", "success"
        else:
            icon, css = "⚠", "warning"

        # Update status icon only
        for cls in ["success", "error", "warning"]:
            self.status_icon.remove_css_class(cls)
        self.status_icon.set_label(icon)
        self.status_icon.add_css_class(css)

        return False  # Don't repeat GLib.idle_add

    def _on_info_clicked(self, button: Gtk.Button) -> None:
        """Open validation dialog with signature details."""
        from pdfsigner.ui.dialogs.validation_dialog import ValidationResultDialog

        # Validate now if not cached
        if not self.validation_result:
            validator = PDFValidator()
            self.validation_result = validator.validate(self.file_path)

        # Get main window
        window = self.get_root()

        # Show dialog (Adw.Dialog handles its own lifecycle)
        ValidationResultDialog(parent=window, result=self.validation_result)

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

        label = Gtk.Label(label=_("Drag PDF files here\nor use the + button to add them"))
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

        # Re-establecer el placeholder (GTK lo pierde al remover children)
        self.listbox.set_placeholder(self._create_placeholder())

    def get_files(self) -> list[Path]:
        """Gets the list of files."""
        return list(self._file_paths)

    def get_unsigned_files(self) -> list[Path]:
        """Gets the list of files that don't have signatures yet."""
        unsigned = []
        for row in self.get_rows():
            # A file is unsigned if validation_result is None and status_icon is not "✓"
            # OR if it's pending status
            if row.status_icon.get_label() == "○":
                unsigned.append(row.file_path)
        return unsigned

    def get_signed_count(self) -> int:
        """Gets the count of already signed files."""
        return sum(1 for row in self.get_rows() if row.status_icon.get_label() in ("✓", "⚠"))

    def get_file_count(self) -> int:
        """Gets the number of files."""
        return len(self._file_paths)

    def get_rows(self) -> list[FileRow]:
        """Gets all rows.

        Note: In GTK4, ListBox.append() wraps widgets in Gtk.ListBoxRow,
        so we need to get the child of each ListBoxRow.
        """
        rows = []
        child = self.listbox.get_first_child()
        while child:
            # GTK4 wraps our FileRow in a ListBoxRow
            if isinstance(child, Gtk.ListBoxRow):
                inner = child.get_child()
                if isinstance(inner, FileRow):
                    rows.append(inner)
            elif isinstance(child, FileRow):
                # Direct child (shouldn't happen but handle anyway)
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

"""
progress_dialog.py - Diálogo de progreso de firma

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 que muestra el progreso de firma en lote
con lista de archivos y estado individual.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.core.signer.batch_manager import BatchProgress, BatchResult


class ProgressDialog(Gtk.Dialog):
    """
    Diálogo de progreso para firma en lote.

    Muestra:
    - Barra de progreso general
    - Lista de archivos con estado (✓/✗/⏳)
    - Botón de cancelar
    """

    # Iconos de estado
    ICON_PENDING = "⏳"
    ICON_SUCCESS = "✓"
    ICON_FAILED = "✗"
    ICON_CURRENT = "→"

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        file_names: list[str] | None = None,
    ):
        """
        Inicializa el diálogo de progreso.

        Args:
            parent: Ventana padre
            file_names: Lista de nombres de archivos a procesar
        """
        super().__init__(
            title="Firmando documentos...",
            transient_for=parent,
            modal=True,
        )

        self.file_names = file_names or []
        self._cancelled = False

        self.set_default_size(500, 400)
        self.set_deletable(False)

        # Botón cancelar
        cancel_button = self.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        cancel_button.connect("clicked", self._on_cancel_clicked)

        # Contenido
        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        # Label de estado actual
        self.status_label = Gtk.Label(label="Preparando...")
        self.status_label.set_xalign(0)
        self.status_label.add_css_class("heading")
        content.append(self.status_label)

        # Barra de progreso
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        content.append(self.progress_bar)

        # Lista de archivos
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        # ListBox para archivos
        self.file_list = Gtk.ListBox()
        self.file_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.file_list.add_css_class("boxed-list")

        # Agregar filas para cada archivo
        self._file_rows: dict[str, Gtk.Box] = {}
        for name in self.file_names:
            row = self._create_file_row(name)
            self.file_list.append(row)
            self._file_rows[name] = row

        scrolled.set_child(self.file_list)
        content.append(scrolled)

    def _create_file_row(self, file_name: str) -> Gtk.Box:
        """Crea una fila para un archivo."""
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # Icono de estado
        status_label = Gtk.Label(label=self.ICON_PENDING)
        status_label.set_name("status_icon")
        status_label.set_size_request(24, -1)
        box.append(status_label)

        # Nombre del archivo
        name_label = Gtk.Label(label=file_name)
        name_label.set_hexpand(True)
        name_label.set_xalign(0)
        name_label.set_ellipsize(True)
        box.append(name_label)

        return box

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Maneja click en cancelar."""
        self._cancelled = True
        self.status_label.set_label("Cancelando...")
        button.set_sensitive(False)

    def is_cancelled(self) -> bool:
        """Verifica si se solicitó cancelación."""
        return self._cancelled

    def update_progress(self, progress: BatchProgress) -> None:
        """
        Actualiza el progreso mostrado.

        Args:
            progress: Estado actual del lote
        """
        # Actualizar barra de progreso
        fraction = (progress.completed + progress.failed) / max(progress.total, 1)
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"{progress.completed + progress.failed}/{progress.total}")

        # Actualizar estado
        if progress.current_file:
            self.status_label.set_label(f"Firmando: {progress.current_file}")

            # Actualizar icono del archivo actual
            if progress.current_file in self._file_rows:
                row = self._file_rows[progress.current_file]
                status_label = row.get_first_child()
                if status_label:
                    status_label.set_label(self.ICON_CURRENT)
        else:
            self.status_label.set_label("Completado")

        # En GTK4, los eventos se procesan automáticamente via GLib main loop
        # No es necesario llamar a events_pending/main_iteration

    def mark_file_complete(self, file_name: str, success: bool) -> None:
        """
        Marca un archivo como completado.

        Args:
            file_name: Nombre del archivo
            success: True si fue exitoso
        """
        if file_name in self._file_rows:
            row = self._file_rows[file_name]
            status_label = row.get_first_child()
            if status_label:
                icon = self.ICON_SUCCESS if success else self.ICON_FAILED
                status_label.set_label(icon)

                # Agregar clase CSS según estado
                if success:
                    status_label.add_css_class("success")
                else:
                    status_label.add_css_class("error")

    def show_result(self, result: BatchResult) -> None:
        """
        Muestra el resultado final.

        Args:
            result: Resultado del lote
        """
        # Actualizar estado final
        if result.all_successful:
            self.status_label.set_label(
                f"✓ {result.successful} archivo(s) firmado(s) correctamente"
            )
            self.status_label.add_css_class("success")
        else:
            self.status_label.set_label(
                f"{result.successful} exitoso(s), {result.failed} fallido(s)"
            )
            if result.failed > 0:
                self.status_label.add_css_class("warning")

        # Cambiar botón a "Cerrar"
        self.get_widget_for_response(Gtk.ResponseType.CANCEL).set_label("Cerrar")
        self.get_widget_for_response(Gtk.ResponseType.CANCEL).set_sensitive(True)

        # Barra al 100%
        self.progress_bar.set_fraction(1.0)

    def pulse(self) -> None:
        """Pulsa la barra de progreso (para operaciones indeterminadas)."""
        self.progress_bar.pulse()
        while Gtk.events_pending():
            Gtk.main_iteration()

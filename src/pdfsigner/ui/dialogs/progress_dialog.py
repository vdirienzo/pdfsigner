"""
progress_dialog.py - Diálogo de progreso de firma

Author: Homero Thompson del Lago del Terror

GTK4 dialog that shows batch signing progress
with file list and individual status.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, Gtk

from pdfsigner.core.signer.batch_manager import BatchProgress, BatchResult
from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


class ProgressDialog(Gtk.Dialog):
    """
    Progress dialog for batch signing.

    Shows:
    - Overall progress bar
    - List of files with status (✓/✗/⏳)
    - Cancel button (becomes Close when finished)
    - Folder icons to open output location
    """

    # Status icons
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
        Initializes the progress dialog.

        Args:
            parent: Parent window
            file_names: List of file names to process
        """
        super().__init__(
            title=_("Signing documents..."),
            transient_for=parent,
            modal=True,
        )

        self.file_names = file_names or []
        self._cancelled = False
        self._output_paths: dict[str, Path] = {}  # Maps file names to output paths

        self.set_default_size(500, 400)
        self.set_deletable(False)

        # Botón cancelar
        cancel_button = self.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        set_accessible(cancel_button, _("Cancel signing"))
        cancel_button.connect("clicked", self._on_cancel_clicked)

        # Contenido
        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        # Label de estado actual
        self.status_label = Gtk.Label(label=_("Preparing..."))
        self.status_label.set_xalign(0)
        self.status_label.add_css_class("heading")
        content.append(self.status_label)

        # Barra de progreso
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        set_accessible(
            self.progress_bar,
            _("Signing progress"),
            _("Shows progress of batch signing operation"),
        )
        content.append(self.progress_bar)

        # Lista de archivos
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        # ListBox para archivos
        self.file_list = Gtk.ListBox()
        self.file_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.file_list.add_css_class("boxed-list")
        set_accessible(self.file_list, _("Signed files"))

        # Agregar filas para cada archivo
        self._file_rows: dict[str, Gtk.Box] = {}
        for name in self.file_names:
            row = self._create_file_row(name)
            self.file_list.append(row)
            self._file_rows[name] = row

        scrolled.set_child(self.file_list)
        content.append(scrolled)

    def _create_file_row(self, file_name: str) -> Gtk.Box:
        """Creates a row for a file."""
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

        # File name (and later output path)
        name_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        name_box.set_hexpand(True)

        name_label = Gtk.Label(label=file_name)
        name_label.set_name("file_name")
        name_label.set_xalign(0)
        name_label.set_ellipsize(True)
        name_box.append(name_label)

        # Output path label (hidden initially, shown after completion)
        output_label = Gtk.Label()
        output_label.set_name("output_path")
        output_label.set_xalign(0)
        output_label.set_ellipsize(True)
        output_label.add_css_class("dim-label")
        output_label.add_css_class("caption")
        output_label.set_visible(False)
        name_box.append(output_label)

        box.append(name_box)

        # Open folder button (hidden initially)
        folder_button = Gtk.Button.new_from_icon_name("folder-open-symbolic")
        folder_button.set_name("folder_button")
        folder_button.set_tooltip_text(_("Open containing folder"))
        set_accessible(
            folder_button,
            _("Open folder"),
            _("Open containing folder in file manager"),
        )
        folder_button.set_valign(Gtk.Align.CENTER)
        folder_button.add_css_class("flat")
        folder_button.set_visible(False)
        folder_button.connect("clicked", self._on_folder_clicked, file_name)
        box.append(folder_button)

        return box

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handles click on cancel."""
        self._cancelled = True
        self.status_label.set_label(_("Cancelling..."))
        button.set_sensitive(False)

    def _on_folder_clicked(self, button: Gtk.Button, file_name: str) -> None:
        """Opens the folder containing the output file."""
        output_path = self._output_paths.get(file_name)
        if output_path and output_path.exists():
            folder_uri = output_path.parent.as_uri()
            Gio.AppInfo.launch_default_for_uri(folder_uri, None)

    def is_cancelled(self) -> bool:
        """Checks if cancellation was requested."""
        return self._cancelled

    def update_progress(self, progress: BatchProgress) -> None:
        """
        Updates the displayed progress.

        Args:
            progress: Current batch status
        """
        # Actualizar barra de progreso
        fraction = (progress.completed + progress.failed) / max(progress.total, 1)
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"{progress.completed + progress.failed}/{progress.total}")

        # Actualizar estado
        if progress.current_file:
            self.status_label.set_label(_("Signing: {}").format(progress.current_file))

            # Actualizar icono del archivo actual
            if progress.current_file in self._file_rows:
                row = self._file_rows[progress.current_file]
                status_label = row.get_first_child()
                if status_label:
                    status_label.set_label(self.ICON_CURRENT)
        else:
            self.status_label.set_label(_("Completed"))

        # En GTK4, los eventos se procesan automáticamente via GLib main loop
        # No es necesario llamar a events_pending/main_iteration

    def _find_child_by_name(self, parent: Gtk.Widget, name: str) -> Gtk.Widget | None:
        """Recursively finds a child widget by its name."""
        child = parent.get_first_child()
        while child:
            if child.get_name() == name:
                return child
            # Search in children
            found = self._find_child_by_name(child, name)
            if found:
                return found
            child = child.get_next_sibling()
        return None

    def mark_file_complete(
        self, file_name: str, success: bool, output_path: Path | None = None
    ) -> None:
        """
        Marks a file as completed.

        Args:
            file_name: File name
            success: True if successful
            output_path: Path to the output file (for successful files)
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

            # Show output path and folder button for successful files
            if success and output_path:
                self._output_paths[file_name] = output_path

                # Show output path label
                output_label = self._find_child_by_name(row, "output_path")
                if output_label and isinstance(output_label, Gtk.Label):
                    output_label.set_label(f"→ {output_path.name}")
                    output_label.set_tooltip_text(str(output_path))
                    output_label.set_visible(True)

                # Show folder button
                folder_button = self._find_child_by_name(row, "folder_button")
                if folder_button:
                    folder_button.set_visible(True)

    def show_result(self, result: BatchResult) -> None:
        """
        Shows the final result.

        Args:
            result: Batch result
        """
        # Mark each file with its result and output path
        for signing_result in result.results:
            file_name = signing_result.input_path.name
            self.mark_file_complete(
                file_name,
                signing_result.success,
                signing_result.output_path if signing_result.success else None,
            )

        # Actualizar estado final
        if result.all_successful:
            self.status_label.set_label(
                _("✓ {} file(s) signed successfully").format(result.successful)
            )
            self.status_label.add_css_class("success")
        else:
            self.status_label.set_label(
                _("{} successful, {} failed").format(result.successful, result.failed)
            )
            if result.failed > 0:
                self.status_label.add_css_class("warning")

        # Update dialog title and allow closing
        self.set_title(_("Signing completed"))
        self.set_deletable(True)

        # Cambiar botón a "Close"
        close_button = self.get_widget_for_response(Gtk.ResponseType.CANCEL)
        close_button.set_label(_("Close"))
        set_accessible(close_button, _("Close"))
        close_button.set_sensitive(True)
        close_button.add_css_class("suggested-action")

        # Barra al 100%
        self.progress_bar.set_fraction(1.0)
        self.progress_bar.set_text(_("Completed"))

    def pulse(self) -> None:
        """Pulses the progress bar (for indeterminate operations)."""
        self.progress_bar.pulse()
        while Gtk.events_pending():
            Gtk.main_iteration()

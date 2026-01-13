"""
validation_handler.py - Manejador de validación para GUI

Autor: Homero Thompson del Lago del Terror

Orquesta la validación de firmas desde la GUI,
ejecutando operaciones en threads separados.
"""

from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from pdfsigner.core.validator.pdf_validator import PDFValidator


class ValidationHandler:
    """Manejador de validación de firmas para la GUI."""

    def __init__(self, window: Adw.ApplicationWindow):
        """
        Inicializa el handler.

        Args:
            window: Ventana principal de la aplicación
        """
        self.window = window

    def validate_files(self, files: list[Path]) -> None:
        """
        Valida las firmas de los archivos dados.

        Args:
            files: Lista de archivos PDF a validar
        """
        if not files:
            return

        Thread(
            target=self._run_validation,
            args=(files,),
            daemon=True,
        ).start()

    def _run_validation(self, files: list[Path]) -> None:
        """
        Ejecuta validación de firmas (en thread separado).

        Args:
            files: Archivos a validar
        """
        validator = PDFValidator()
        all_valid = True
        total_signatures = 0

        for file_path in files:
            try:
                validation = validator.validate(file_path)
                sig_count = len(validation.signatures) if validation.signatures else 0
                total_signatures += sig_count

                if sig_count > 0:
                    status = "signed" if validation.all_valid else "error"
                    message = f"{sig_count} firma(s)"
                    if not validation.all_valid:
                        all_valid = False
                else:
                    status = "pending"
                    message = "Sin firmas"

                GLib.idle_add(
                    self.window.file_list.update_file_status,
                    file_path,
                    status,
                    message,
                )

            except Exception as e:
                all_valid = False
                GLib.idle_add(
                    self.window.file_list.update_file_status,
                    file_path,
                    "error",
                    f"Error: {e}",
                )

        # Mostrar resumen
        if total_signatures > 0:
            msg = (
                f"✓ {total_signatures} firma(s) válida(s)"
                if all_valid
                else f"⚠ {total_signatures} firma(s), algunas inválidas"
            )
        else:
            msg = "No se encontraron firmas"

        GLib.idle_add(self.window.show_toast, msg)

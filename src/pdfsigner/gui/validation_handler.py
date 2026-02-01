"""
validation_handler.py - Manejador de validación para GUI

Author: Homero Thompson del Lago del Terror

Orchestrates signature validation from the GUI,
executing operations in separate threads.
"""

from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.i18n import _


class ValidationHandler:
    """Manejador de validación de firmas para la GUI."""

    def __init__(self, window: Adw.ApplicationWindow):
        """
        Initializes the handler.

        Args:
            window: Ventana principal de la aplicación
        """
        self.window = window

    def validate_files(self, files: list[Path]) -> None:
        """
        Validates the signatures of the given files.

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
        Executes signature validation (in separate thread).

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

                    # Extract PAdES level from first signature
                    pades_level_str = ""
                    if (
                        validation.signatures
                        and validation.signatures[0].ltv_info
                        and validation.signatures[0].ltv_info.pades_level
                    ):
                        level = validation.signatures[0].ltv_info.pades_level
                        # Convert enum to display string (B_LT -> "B-LT")
                        pades_level_str = f" • {level.name.replace('_', '-')}"

                    message = _("{}signature(s){}").format(sig_count, pades_level_str)
                    if not validation.all_valid:
                        all_valid = False
                else:
                    status = "pending"
                    message = _("No signatures")

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
                _("✓ {}valid signature(s)").format(total_signatures)
                if all_valid
                else _("⚠ {}signature(s), some invalid").format(total_signatures)
            )
        else:
            msg = _("No signatures found")

        GLib.idle_add(self.window.show_toast, msg)

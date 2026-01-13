"""
signing_handler.py - Manejador de firma para GUI

Autor: Homero Thompson del Lago del Terror

Orquesta el proceso de firma desde la GUI,
ejecutando operaciones en threads separados.
Soporta modo dry-run para testing sin token real.
"""

from pathlib import Path
from threading import Thread

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

from pdfsigner.config.settings import get_settings
from pdfsigner.exceptions import PDFSignerError, TokenError
from pdfsigner.ui.dialogs.options_dialog import SignatureOptionsDialog
from pdfsigner.ui.dialogs.pin_dialog import PinDialog
from pdfsigner.ui.dialogs.progress_dialog import ProgressDialog


class SigningHandler:
    """
    Manejador de operaciones de firma para la GUI.

    Coordina:
    - Solicitud de PIN
    - Diálogo de opciones
    - Proceso de firma en background
    - Actualización de progreso
    """

    def __init__(self, window: Adw.ApplicationWindow):
        """
        Inicializa el handler.

        Args:
            window: Ventana principal de la aplicación
        """
        self.window = window
        self.settings = get_settings()
        self._current_pin: str | None = None
        self._progress_dialog: ProgressDialog | None = None
        self._current_options: dict = {}

    def sign_files(self, files: list[Path]) -> None:
        """
        Inicia el proceso de firma para los archivos dados.

        Args:
            files: Lista de archivos PDF a firmar
        """
        if not files:
            return

        options_dialog = SignatureOptionsDialog(parent=self.window)
        options_dialog.connect("response", self._on_options_response, files)
        options_dialog.present()

    def _on_options_response(
        self,
        dialog: SignatureOptionsDialog,
        response: int,
        files: list[Path],
    ) -> None:
        """Callback cuando se cierra el diálogo de opciones."""
        if response != Gtk.ResponseType.OK:
            dialog.destroy()
            return

        appearance = dialog.get_appearance()
        self._current_options = {
            "visible": appearance.visible if appearance else False,
            "page": appearance.page if appearance else "last",
        }
        dialog.destroy()
        self._request_pin(files)

    def _request_pin(self, files: list[Path]) -> None:
        """Solicita el PIN del token."""
        pin_dialog = PinDialog(parent=self.window)
        pin_dialog.connect("response", self._on_pin_response, files)
        pin_dialog.present()

    def _on_pin_response(
        self,
        dialog: PinDialog,
        response: int,
        files: list[Path],
    ) -> None:
        """Callback cuando se ingresa el PIN."""
        if response != Gtk.ResponseType.OK:
            dialog.destroy()
            return

        pin = dialog.get_pin()
        dialog.destroy()

        if not pin:
            self._show_error("PIN vacío", "Debe ingresar el PIN del token")
            return

        self._current_pin = pin
        Thread(
            target=self._verify_pin_and_sign,
            args=(files,),
            daemon=True,
        ).start()

    def _verify_pin_and_sign(self, files: list[Path]) -> None:
        """Verifica el PIN y procede a firmar (en thread separado)."""
        try:
            pin = self._current_pin or ""

            if self.settings.dry_run:
                from pdfsigner.core.mock import MockNSSHandler

                nss = MockNSSHandler()
                nss.initialize()
                nss.login(pin)
                GLib.idle_add(self.window.show_toast, "⚠️ Modo simulación (dry-run)")
            else:
                from pdfsigner.core.token.nss_handler import NSSHandler

                nss = NSSHandler()
                nss.initialize()
                nss.login(pin)

            GLib.idle_add(self._start_signing, files)

        except TokenError as e:
            GLib.idle_add(self._show_error, "Error de token", str(e))
        except Exception as e:
            GLib.idle_add(self._show_error, "Error", str(e))

    def _start_signing(self, files: list[Path]) -> None:
        """Inicia el proceso de firma mostrando progreso."""
        file_names = [f.name for f in files]
        self._progress_dialog = ProgressDialog(
            parent=self.window,
            file_names=file_names,
        )
        self._progress_dialog.connect("response", self._on_progress_cancel)
        self._progress_dialog.present()

        Thread(
            target=self._run_signing,
            args=(files,),
            daemon=True,
        ).start()

    def _on_progress_cancel(self, dialog: ProgressDialog, response: int) -> None:
        """Callback cuando se cancela el progreso."""
        dialog.destroy()
        self._progress_dialog = None

    def _run_signing(self, files: list[Path]) -> None:
        """Ejecuta el proceso de firma (en thread separado)."""
        try:
            pin = self._current_pin or ""

            if self.settings.dry_run:
                from pdfsigner.core.mock import MockBatchManager

                batch_manager = MockBatchManager()

                def on_progress(progress) -> None:
                    GLib.idle_add(self._update_progress, progress)

                results = batch_manager.sign_batch(
                    files=files,
                    pin=pin,
                    visible=self._current_options.get("visible", False),
                    page=self._current_options.get("page", "last"),
                    progress_callback=on_progress,
                )
            else:
                from pdfsigner.core.signer.batch_manager import BatchManager
                from pdfsigner.core.token.nss_handler import NSSHandler

                # Para firma real, necesitamos el nss_handler
                nss = NSSHandler()
                nss.initialize()
                nss.authenticate(pin)

                batch_manager = BatchManager(nss)

                def on_progress_real(progress) -> None:
                    GLib.idle_add(self._update_progress, progress)

                results = batch_manager.sign_batch(
                    pdf_files=files,
                    progress_callback=on_progress_real,
                )

            GLib.idle_add(self._signing_complete, results, self.settings.dry_run)

        except PDFSignerError as e:
            GLib.idle_add(self._show_error, "Error de firma", str(e))
        except Exception as e:
            GLib.idle_add(self._show_error, "Error inesperado", str(e))
        finally:
            self._current_pin = None

    def _update_progress(self, progress) -> None:
        """Actualiza el diálogo de progreso."""
        if self._progress_dialog:
            self._progress_dialog.update_progress(progress)

            if progress.current_file:
                file_path = Path(progress.current_file)
                if progress.status == "success":
                    self.window.file_list.update_file_status(file_path, "signed", "Firmado")
                elif progress.status == "error":
                    msg = getattr(progress, "message", None) or "Error"
                    self.window.file_list.update_file_status(file_path, "error", msg)
                else:
                    self.window.file_list.update_file_status(file_path, "processing", "Firmando...")

    def _signing_complete(self, results, dry_run: bool = False) -> None:
        """Callback cuando la firma se completa."""
        if self._progress_dialog:
            self._progress_dialog.destroy()
            self._progress_dialog = None

        if hasattr(results, "successful"):
            success = results.successful
            failed = results.failed
        else:
            success = results.get("success", 0)
            failed = results.get("failed", 0)
        total = success + failed

        prefix = "[SIMULADO] " if dry_run else ""
        suffix = " (dry-run)" if dry_run else ""

        if failed == 0:
            self.window.show_toast(f"✓ {prefix}{success} archivo(s) firmado(s){suffix}")
        else:
            self.window.show_toast(
                f"{prefix}Firmados: {success}/{total} (Errores: {failed}){suffix}"
            )

    def _show_error(self, title: str, message: str) -> None:
        """Muestra un diálogo de error."""
        if self._progress_dialog:
            self._progress_dialog.destroy()
            self._progress_dialog = None

        dialog = Adw.MessageDialog(
            transient_for=self.window,
            heading=title,
            body=message,
        )
        dialog.add_response("ok", "Aceptar")
        dialog.present()

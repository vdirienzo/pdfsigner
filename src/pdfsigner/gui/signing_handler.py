"""
signing_handler.py - Manejador de firma para GUI

Author: Homero Thompson del Lago del Terror

Orchestrates the signing process from the GUI,
executing operations in separate threads.
Supports dry-run mode for testing without real token.
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
        Initializes the handler.

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
        Starts the signing process for the given files.

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
        """Callback when the options dialog is closed."""
        if response != Gtk.ResponseType.OK:
            dialog.destroy()
            return

        appearance = dialog.get_appearance()
        self._current_options = {
            "visible": appearance.visible if appearance else False,
            "page": appearance.page if appearance else "last",
            "appearance": appearance,  # Store full appearance for position_preference
        }
        dialog.destroy()
        self._request_pin(files)

    def _request_pin(self, files: list[Path]) -> None:
        """Requests the token PIN."""
        pin_dialog = PinDialog(parent=self.window)
        pin_dialog.connect("response", self._on_pin_response, files)
        pin_dialog.present()

    def _on_pin_response(
        self,
        dialog: PinDialog,
        response: int,
        files: list[Path],
    ) -> None:
        """Callback when PIN is entered."""
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
        """Verifies PIN and proceeds to sign (in separate thread)."""
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
            GLib.idle_add(self._show_error, "Token error", str(e))
        except Exception as e:
            GLib.idle_add(self._show_error, "Error", str(e))

    def _start_signing(self, files: list[Path]) -> None:
        """Starts the signing process showing progress."""
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
        """Callback when progress is cancelled."""
        dialog.destroy()
        self._progress_dialog = None

    def _run_signing(self, files: list[Path]) -> None:
        """Executes the signing process (in separate thread)."""
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
                    appearance=self._current_options.get("appearance"),
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
            GLib.idle_add(self._show_error, "Signature error", str(e))
        except Exception as e:
            GLib.idle_add(self._show_error, "Unexpected error", str(e))
        finally:
            self._current_pin = None

    def _update_progress(self, progress) -> None:
        """Updates the progress dialog."""
        if self._progress_dialog:
            self._progress_dialog.update_progress(progress)

            if progress.current_file:
                file_path = Path(progress.current_file)
                if progress.status == "success":
                    self.window.file_list.update_file_status(file_path, "signed", "Signed")
                elif progress.status == "error":
                    msg = getattr(progress, "message", None) or "Error"
                    self.window.file_list.update_file_status(file_path, "error", msg)
                else:
                    self.window.file_list.update_file_status(file_path, "processing", "Signing...")

    def _signing_complete(self, results, dry_run: bool = False) -> None:
        """Callback when signing completes."""
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
            self.window.show_toast(f"✓ {prefix}{success} file(s) firmado(s){suffix}")
        else:
            self.window.show_toast(
                f"{prefix}Firmados: {success}/{total} (Errores: {failed}){suffix}"
            )

    def _show_error(self, title: str, message: str) -> None:
        """Shows an error dialog."""
        if self._progress_dialog:
            self._progress_dialog.destroy()
            self._progress_dialog = None

        dialog = Adw.MessageDialog(
            transient_for=self.window,
            heading=title,
            body=message,
        )
        dialog.add_response("ok", "Accept")
        dialog.present()

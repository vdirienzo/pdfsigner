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
from pdfsigner.core.token.pin_cache import get_pin_cache
from pdfsigner.exceptions import PDFSignerError, TokenError
from pdfsigner.i18n import _
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
        self._nss_handler = None  # Reutilizable entre verificación y firma

    def sign_files(self, files: list[Path]) -> None:
        """
        Starts the signing process for the given files.

        Documents that already have signatures can receive additional signatures.
        Unique field names are generated to avoid conflicts.

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
        selected_template = dialog.get_selected_template()

        self._current_options = {
            "visible": appearance.visible if appearance else False,
            "page": appearance.page if appearance else "last",
            "appearance": appearance,  # Store full appearance for position_preference
            "template": selected_template,  # Store selected template for override
        }
        dialog.destroy()
        self._request_pin_or_use_cache(files)

    def _request_pin_or_use_cache(self, files: list[Path]) -> None:
        """Requests PIN or uses cached PIN if available and enabled."""
        # Reload settings to get current configuration
        from pdfsigner.config.settings import get_settings

        settings = get_settings()

        # Check if PIN cache is enabled and has a valid PIN
        if settings.pin_cache_enabled:
            pin_cache = get_pin_cache(settings.pin_cache_timeout_seconds)
            cached_pin = pin_cache.get()
            if cached_pin:
                # Use cached PIN directly
                self._current_pin = cached_pin
                Thread(
                    target=self._verify_pin_and_sign,
                    args=(files,),
                    daemon=True,
                ).start()
                return

        # No cache or cache disabled, request PIN
        self._request_pin(files)

    def _request_pin(self, files: list[Path]) -> None:
        """Requests the token PIN via dialog."""
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
            self._show_error(_("Empty PIN"), _("You must enter the token PIN"))
            return

        self._current_pin = pin

        # Store in cache if enabled (get fresh settings)
        settings = get_settings()
        if settings.pin_cache_enabled:
            pin_cache = get_pin_cache(settings.pin_cache_timeout_seconds)
            pin_cache.store(pin)

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
                nss.connect_token()
                nss.authenticate(pin)
                self._nss_handler = nss  # Guardar para reutilizar en _run_signing
                GLib.idle_add(self.window.show_toast, _("⚠️ Simulation mode (dry-run)"))
            else:
                from pdfsigner.core.token.nss_handler import NSSHandler

                nss = NSSHandler()
                nss.initialize()
                nss.connect_token()
                nss.authenticate(pin)
                self._nss_handler = nss  # Guardar para reutilizar en _run_signing

            GLib.idle_add(self._start_signing, files)

        except TokenError as e:
            self._nss_handler = None
            GLib.idle_add(self._show_error, _("Token error"), str(e))
        except Exception as e:
            self._nss_handler = None
            GLib.idle_add(self._show_error, _("Error"), str(e))

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
                    template_override=self._current_options.get("template"),
                )
            else:
                from pdfsigner.core.signer.batch_manager import BatchManager

                # Reutilizar el nss_handler ya autenticado en _verify_pin_and_sign
                if self._nss_handler is None:
                    raise PDFSignerError(_("Token session not available"))

                batch_manager = BatchManager(self._nss_handler)

                def on_progress_real(progress) -> None:
                    GLib.idle_add(self._update_progress, progress)

                results = batch_manager.sign_batch(
                    pdf_files=files,
                    appearance=self._current_options.get("appearance"),
                    progress_callback=on_progress_real,
                    template_override=self._current_options.get("template"),
                )

            GLib.idle_add(self._signing_complete, results, files, self.settings.dry_run)

        except PDFSignerError as e:
            GLib.idle_add(self._show_error, _("Signature error"), str(e))
        except Exception as e:
            GLib.idle_add(self._show_error, _("Unexpected error"), str(e))
        finally:
            self._current_pin = None
            # Cerrar la sesión PKCS#11 al terminar
            if self._nss_handler is not None:
                try:
                    self._nss_handler.close()
                except Exception:
                    pass
                self._nss_handler = None

    def _update_progress(self, progress) -> None:
        """Updates the progress dialog."""
        if self._progress_dialog:
            self._progress_dialog.update_progress(progress)

            # Show current file being processed
            if progress.current_file:
                file_path = Path(progress.current_file)
                self.window.file_list.update_file_status(file_path, "processing", _("Signing..."))

    def _signing_complete(self, results, files: list[Path], dry_run: bool = False) -> None:
        """Callback when signing completes."""
        # Get list of successful files from results
        successful_files: set[Path] = set()
        if hasattr(results, "results") and results.results:
            for r in results.results:
                if r.success:
                    successful_files.add(r.input_path)
        elif hasattr(results, "failed"):
            # Fallback: if no individual results but failed == 0, all were successful
            if results.failed == 0:
                successful_files = set(files)

        # Update file status in the UI for each file
        for file_path in files:
            if file_path in successful_files:
                self.window.file_list.update_file_status(file_path, "signed", _("Signed"))
            else:
                self.window.file_list.update_file_status(file_path, "error", _("Error"))

        # Show results in progress dialog (don't auto-close)
        if self._progress_dialog and hasattr(results, "results") and results.results:
            self._progress_dialog.show_result(results)

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
        dialog.add_response("ok", _("Accept"))
        dialog.present()

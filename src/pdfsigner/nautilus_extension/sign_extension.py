"""
sign_extension.py - Extensión de Nautilus para firma de PDFs

Autor: Homero Thompson del Lago del Terror

Agrega opción "Firmar digitalmente" al menú contextual
de Nautilus para archivos PDF.
"""

from pathlib import Path
from urllib.parse import unquote, urlparse

import gi

gi.require_version("Nautilus", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("GObject", "2.0")

from gi.repository import GObject, Gtk, Nautilus
from loguru import logger

# Importaciones del proyecto (se cargan bajo demanda)
_pdfsigner_loaded = False


def _ensure_pdfsigner_loaded():
    """Carga las dependencias de pdfsigner bajo demanda."""
    global _pdfsigner_loaded
    if not _pdfsigner_loaded:
        try:
            # Configurar logging
            from pdfsigner.config.settings import get_settings

            settings = get_settings()
            logger.add(
                settings.log_dir / "pdfsigner.log",
                rotation="1 week",
                level=settings.log_level,
            )
            _pdfsigner_loaded = True
        except Exception as e:
            logger.error(f"Error cargando pdfsigner: {e}")


class PDFSignerExtension(GObject.GObject, Nautilus.MenuProvider):
    """
    Extensión de Nautilus para firma digital de PDFs.

    Agrega opción al menú contextual cuando se seleccionan
    archivos PDF.
    """

    def __init__(self):
        """Inicializa la extensión."""
        super().__init__()
        logger.debug("PDFSignerExtension inicializada")

    def get_file_items(
        self,
        files: list[Nautilus.FileInfo],
    ) -> list[Nautilus.MenuItem] | None:
        """
        Callback de Nautilus para obtener items del menú.

        Args:
            files: Lista de archivos seleccionados

        Returns:
            Lista de items de menú o None
        """
        # Filtrar solo PDFs
        pdf_files = [f for f in files if self._is_pdf(f)]

        if not pdf_files:
            return None

        # Crear item de menú
        count = len(pdf_files)
        label = "Firmar digitalmente" if count == 1 else f"Firmar {count} PDFs"

        item = Nautilus.MenuItem(
            name="PDFSigner::Sign",
            label=label,
            tip="Firmar con certificado digital (token USB)",
        )

        item.connect("activate", self._on_sign_activate, pdf_files)

        return [item]

    def _is_pdf(self, file_info: Nautilus.FileInfo) -> bool:
        """Verifica si un archivo es PDF."""
        mime = file_info.get_mime_type()
        return mime == "application/pdf"

    def _get_path_from_uri(self, uri: str) -> Path:
        """Convierte URI de Nautilus a Path."""
        parsed = urlparse(uri)
        return Path(unquote(parsed.path))

    def _on_sign_activate(
        self,
        menu: Nautilus.MenuItem,
        files: list[Nautilus.FileInfo],
    ) -> None:
        """
        Maneja la activación del menú de firma.

        Args:
            menu: Item de menú activado
            files: Lista de archivos PDF seleccionados
        """
        _ensure_pdfsigner_loaded()

        # Convertir URIs a paths
        pdf_paths = [self._get_path_from_uri(f.get_uri()) for f in files]

        logger.info(f"Iniciando firma de {len(pdf_paths)} archivo(s)")

        # Ejecutar en hilo separado para no bloquear Nautilus
        import threading

        thread = threading.Thread(
            target=self._run_signing_workflow,
            args=(pdf_paths,),
            daemon=True,
        )
        thread.start()

    def _run_signing_workflow(self, pdf_paths: list[Path]) -> None:
        """
        Ejecuta el workflow de firma en un hilo separado.

        Args:
            pdf_paths: Lista de paths a PDFs
        """
        from gi.repository import GLib

        # Ejecutar UI en el hilo principal de GTK
        GLib.idle_add(self._show_signing_dialog, pdf_paths)

    def _show_signing_dialog(self, pdf_paths: list[Path]) -> bool:
        """
        Muestra los diálogos de firma.

        Args:
            pdf_paths: Lista de paths a PDFs

        Returns:
            False (para GLib.idle_add)
        """
        try:
            from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
            from pdfsigner.core.signer.batch_manager import BatchManager
            from pdfsigner.core.signer.lta_handler import create_lta_handler_from_settings
            from pdfsigner.core.token.cert_selector import CertificateSelector
            from pdfsigner.core.token.nss_handler import NSSHandler
            from pdfsigner.core.token.pin_cache import get_pin_cache
            from pdfsigner.ui.dialogs.options_dialog import SignatureOptionsDialog
            from pdfsigner.ui.dialogs.pin_dialog import PinDialog
            from pdfsigner.ui.dialogs.progress_dialog import ProgressDialog

            # 1. Mostrar opciones de firma
            # Obtener número de páginas del primer PDF
            total_pages = 1
            try:
                with ContentAnalyzer(pdf_paths[0]) as analyzer:
                    total_pages = analyzer.page_count
            except Exception:
                pass

            options_dialog = SignatureOptionsDialog(total_pages=total_pages)
            response = options_dialog.run()

            if response != Gtk.ResponseType.OK:
                options_dialog.destroy()
                return False

            appearance = options_dialog.get_appearance()
            options_dialog.destroy()

            # 2. Conectar con token y pedir PIN
            nss_handler = NSSHandler()
            nss_handler.initialize()
            tokens = nss_handler.get_available_tokens()

            if not tokens:
                self._show_error("No se detectó token USB")
                return False

            nss_handler.connect_token()

            # Verificar cache de PIN
            pin_cache = get_pin_cache()
            pin = pin_cache.get()

            if pin is None:
                pin_dialog = PinDialog()
                response = pin_dialog.run()

                if response != Gtk.ResponseType.OK:
                    pin_dialog.destroy()
                    nss_handler.close()
                    return False

                pin = pin_dialog.get_pin()
                pin_dialog.destroy()

            # Autenticar
            try:
                nss_handler.authenticate(pin)
                pin_cache.store(pin)  # Cachear para el lote
            except Exception as e:
                self._show_error(f"Error de autenticación: {e}")
                nss_handler.close()
                return False

            # 3. Seleccionar certificado
            cert_selector = CertificateSelector(nss_handler)
            try:
                cert = cert_selector.get_default_certificate()
                logger.info(f"Usando certificado: {cert.display_name}")
            except Exception as e:
                self._show_error(f"No hay certificado válido: {e}")
                nss_handler.close()
                return False

            # 4. Configurar LTA handler
            try:
                lta_handler = create_lta_handler_from_settings()
            except Exception as e:
                logger.warning(f"TSA no disponible: {e}")
                lta_handler = None

            # 5. Mostrar progreso y firmar
            file_names = [p.name for p in pdf_paths]
            progress_dialog = ProgressDialog(file_names=file_names)
            progress_dialog.show()

            batch_manager = BatchManager(nss_handler, lta_handler)

            def progress_callback(progress):
                progress_dialog.update_progress(progress)
                if progress_dialog.is_cancelled():
                    batch_manager.cancel()

            result = batch_manager.sign_batch(
                pdf_files=pdf_paths,
                appearance=appearance,
                cert_id=cert.info.pkcs11_id,
                progress_callback=progress_callback,
            )

            # 6. Mostrar resultado
            progress_dialog.show_result(result)
            progress_dialog.run()
            progress_dialog.destroy()

            # Limpiar
            nss_handler.close()

            # Notificar éxito
            if result.all_successful:
                self._show_notification(f"✓ {result.successful} file(s) signed")

        except Exception as e:
            logger.exception("Error en workflow de firma")
            self._show_error(f"Error inesperado: {e}")

        return False

    def _show_error(self, message: str) -> None:
        """Muestra diálogo de error."""
        dialog = Gtk.MessageDialog(
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Error de Firma",
            secondary_text=message,
        )
        dialog.run()
        dialog.destroy()

    def _show_notification(self, message: str) -> None:
        """Muestra notificación del sistema."""
        try:
            from gi.repository import Gio

            app = Gio.Application.get_default()
            if app:
                notification = Gio.Notification.new("PDFSigner")
                notification.set_body(message)
                app.send_notification(None, notification)
        except Exception:
            pass  # Notificación opcional

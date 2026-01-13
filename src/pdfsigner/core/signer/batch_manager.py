"""
batch_manager.py - Gestor de firma en lote

Autor: Homero Thompson del Lago del Terror

Orquesta la firma de múltiples PDFs, manejando
progreso, errores parciales y reportes.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.pdf_signer import PDFSigner, SignatureAppearance, SigningResult
from pdfsigner.core.token.nss_handler import NSSHandler


@dataclass
class BatchProgress:
    """Estado de progreso del lote."""

    total: int
    completed: int
    failed: int
    current_file: str | None

    @property
    def pending(self) -> int:
        """Archivos pendientes."""
        return self.total - self.completed - self.failed

    @property
    def percentage(self) -> float:
        """Porcentaje completado."""
        if self.total == 0:
            return 100.0
        return (self.completed + self.failed) / self.total * 100


@dataclass
class BatchResult:
    """Resultado de firma en lote."""

    total: int
    successful: int
    failed: int
    results: list[SigningResult] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def all_successful(self) -> bool:
        """True si todos los archivos se firmaron correctamente."""
        return self.failed == 0

    @property
    def duration_seconds(self) -> float | None:
        """Duración total en segundos."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def get_failed_files(self) -> list[tuple[Path, str]]:
        """Lista de archivos fallidos con sus errores."""
        return [
            (r.input_path, r.error or "Error desconocido") for r in self.results if not r.success
        ]

    def get_successful_files(self) -> list[Path]:
        """Lista de archivos firmados exitosamente."""
        return [r.output_path for r in self.results if r.success and r.output_path]


# Tipo para callback de progreso
ProgressCallback = Callable[[BatchProgress], None]


class BatchManager:
    """
    Gestor de firma en lote.

    Coordina la firma de múltiples PDFs con:
    - Manejo de errores parciales (continúa con otros archivos)
    - Callbacks de progreso para actualizar UI
    - Soporte para cancelación
    """

    def __init__(
        self,
        nss_handler: NSSHandler,
        lta_handler: LTAHandler | None = None,
    ):
        """
        Inicializa el gestor de lote.

        Args:
            nss_handler: Handler de NSS autenticado
            lta_handler: Handler LTA para timestamp
        """
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        self._cancelled = False
        self._signer: PDFSigner | None = None

    def _get_signer(self) -> PDFSigner:
        """Obtiene o crea el signer."""
        if self._signer is None:
            self._signer = PDFSigner(self.nss_handler, self.lta_handler)
        return self._signer

    def cancel(self) -> None:
        """Solicita cancelación del lote actual."""
        self._cancelled = True
        logger.info("Cancelación solicitada")

    def reset(self) -> None:
        """Resetea el estado de cancelación."""
        self._cancelled = False

    def sign_batch(
        self,
        pdf_files: list[Path],
        appearance: SignatureAppearance | None = None,
        cert_id: bytes | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> BatchResult:
        """
        Firma un lote de PDFs.

        Args:
            pdf_files: Lista de rutas a PDFs
            appearance: Configuración de apariencia
            cert_id: ID del certificado a usar
            progress_callback: Callback para actualizar progreso

        Returns:
            Resultado del lote con estadísticas y detalles
        """
        self.reset()

        total = len(pdf_files)
        result = BatchResult(
            total=total,
            successful=0,
            failed=0,
            started_at=datetime.now(),
        )

        if total == 0:
            result.finished_at = datetime.now()
            return result

        signer = self._get_signer()
        logger.info(f"Iniciando firma de {total} archivo(s)")

        for i, pdf_path in enumerate(pdf_files):
            # Verificar cancelación
            if self._cancelled:
                logger.info("Firma cancelada por el usuario")
                break

            # Notificar progreso
            if progress_callback:
                progress = BatchProgress(
                    total=total,
                    completed=result.successful,
                    failed=result.failed,
                    current_file=pdf_path.name,
                )
                progress_callback(progress)

            # Firmar archivo
            signing_result = signer.sign_pdf(
                input_path=pdf_path,
                appearance=appearance,
                cert_id=cert_id,
            )

            result.results.append(signing_result)

            if signing_result.success:
                result.successful += 1
            else:
                result.failed += 1
                logger.warning(f"Error en {pdf_path.name}: {signing_result.error}")

        result.finished_at = datetime.now()

        # Notificar progreso final
        if progress_callback:
            progress = BatchProgress(
                total=total,
                completed=result.successful,
                failed=result.failed,
                current_file=None,
            )
            progress_callback(progress)

        # Log resumen
        duration = result.duration_seconds or 0
        logger.info(
            f"Lote completado: {result.successful}/{total} exitosos, "
            f"{result.failed} fallidos, {duration:.1f}s"
        )

        return result


def create_batch_manager(
    nss_handler: NSSHandler,
    lta_handler: LTAHandler | None = None,
) -> BatchManager:
    """
    Factory para crear BatchManager.

    Args:
        nss_handler: Handler de NSS autenticado
        lta_handler: Handler LTA opcional

    Returns:
        BatchManager configurado
    """
    return BatchManager(nss_handler, lta_handler)

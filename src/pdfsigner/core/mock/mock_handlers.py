"""
mock_handlers.py - Handlers mock para modo dry-run

Autor: Homero Thompson del Lago del Terror

Simula el comportamiento del token y firma sin hardware real.
Útil para testing y demostración.
"""

import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger


@dataclass
class MockCertificateInfo:
    """Información de certificado simulado."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    pkcs11_id: bytes = b"MOCK_CERT_ID"


@dataclass
class MockCertificate:
    """Certificado simulado para dry-run."""

    info: MockCertificateInfo
    display_name: str
    days_until_expiry: int
    is_expiring_soon: bool = False


def create_mock_certificate(name: str = "Usuario de Prueba") -> MockCertificate:
    """
    Crea un certificado mock para pruebas.

    Args:
        name: Nombre del titular del certificado

    Returns:
        Certificado simulado
    """
    now = datetime.now()
    info = MockCertificateInfo(
        subject=f"CN={name}, O=Organización de Prueba, C=AR",
        issuer="CN=CA de Prueba, O=Autoridad Certificante, C=AR",
        serial_number="1234567890ABCDEF",
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=365),
    )

    return MockCertificate(
        info=info,
        display_name=name,
        days_until_expiry=365,
        is_expiring_soon=False,
    )


class MockNSSHandler:
    """
    Handler NSS simulado para modo dry-run.

    Simula todas las operaciones del token sin hardware real.
    """

    def __init__(self):
        """Inicializa el handler mock."""
        self._initialized = False
        self._authenticated = False
        self._connected = False
        logger.info("[DRY-RUN] MockNSSHandler creado")

    def initialize(self) -> None:
        """Simula inicialización de NSS."""
        logger.info("[DRY-RUN] Inicializando NSS (simulado)...")
        time.sleep(0.2)  # Simular latencia
        self._initialized = True
        logger.info("[DRY-RUN] NSS inicializado correctamente")

    def get_available_tokens(self) -> list[str]:
        """Retorna tokens simulados."""
        if not self._initialized:
            return []
        return ["SafeNet 5110 (SIMULADO)"]

    def connect_token(self) -> None:
        """Simula conexión al token."""
        logger.info("[DRY-RUN] Conectando al token simulado...")
        time.sleep(0.3)
        self._connected = True
        logger.info("[DRY-RUN] Token conectado")

    def authenticate(self, pin: str) -> None:
        """
        Simula autenticación con PIN.

        Acepta cualquier PIN de 4+ dígitos.
        """
        logger.info("[DRY-RUN] Autenticando con PIN...")
        time.sleep(0.5)  # Simular verificación

        if len(pin) < 4:
            raise ValueError("[DRY-RUN] PIN debe tener al menos 4 dígitos")

        self._authenticated = True
        logger.info("[DRY-RUN] Autenticación exitosa")

    def login(self, pin: str) -> None:
        """Alias para authenticate."""
        self.authenticate(pin)

    def is_authenticated(self) -> bool:
        """Verifica si está autenticado."""
        return self._authenticated

    def get_certificates(self) -> list[MockCertificate]:
        """Retorna certificados simulados."""
        if not self._authenticated:
            return []

        return [
            create_mock_certificate("Juan Pérez (PRUEBA)"),
            create_mock_certificate("María García (PRUEBA)"),
        ]

    def close(self) -> None:
        """Cierra la conexión simulada."""
        logger.info("[DRY-RUN] Cerrando conexión con token...")
        self._authenticated = False
        self._connected = False
        self._initialized = False


@dataclass
class MockBatchProgress:
    """Progreso de firma en lote simulado (compatible con BatchProgress)."""

    current: int
    total: int
    current_file: str
    status: str
    message: str = ""

    @property
    def completed(self) -> int:
        """Archivos completados exitosamente (para compatibilidad con BatchProgress)."""
        return self.current if self.status == "success" else max(0, self.current - 1)

    @property
    def failed(self) -> int:
        """Archivos fallidos (para compatibilidad con BatchProgress)."""
        return 0  # En dry-run no hay fallos durante el progreso


@dataclass
class MockBatchResult:
    """Resultado de firma en lote simulado."""

    successful: int
    failed: int
    all_successful: bool
    errors: dict[Path, str]

    def get_failed_files(self):
        """Retorna archivos fallidos."""
        return list(self.errors.items())


class MockBatchManager:
    """
    Manager de firma en lote simulado.

    Simula el proceso de firma copiando archivos
    con sufijo _firmado sin modificar el contenido.
    """

    def __init__(self, nss_handler=None, lta_handler=None):
        """Inicializa el manager mock."""
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        logger.info("[DRY-RUN] MockBatchManager creado")

    def sign_batch(
        self,
        files: list[Path] | None = None,
        pdf_files: list[Path] | None = None,
        pin: str | None = None,
        visible: bool = False,
        page: str | int = "last",
        appearance=None,
        cert_id: bytes | None = None,
        progress_callback=None,
    ) -> MockBatchResult:
        """
        Simula firma de archivos en lote.

        Copia cada PDF con sufijo _firmado simulando el proceso.

        Args:
            files: Lista de archivos (alias)
            pdf_files: Lista de archivos
            pin: PIN (ignorado en mock)
            visible: Firma visible
            page: Página para firma visible
            appearance: Configuración de apariencia
            cert_id: ID del certificado
            progress_callback: Callback de progreso

        Returns:
            Resultado de la firma simulada
        """
        # Soportar ambos nombres de parámetro
        file_list = files or pdf_files or []

        if not file_list:
            return MockBatchResult(successful=0, failed=0, all_successful=True, errors={})

        total = len(file_list)
        successful = 0
        failed = 0
        errors = {}

        logger.info(f"[DRY-RUN] Simulando firma de {total} archivo(s)...")

        for i, pdf_path in enumerate(file_list):
            current_file = str(pdf_path)

            # Notificar inicio
            if progress_callback:
                progress = MockBatchProgress(
                    current=i + 1,
                    total=total,
                    current_file=current_file,
                    status="processing",
                    message="Firmando...",
                )
                progress_callback(progress)

            # Simular tiempo de firma
            time.sleep(0.5)

            try:
                # Crear archivo "firmado" (copia con sufijo)
                output_path = pdf_path.parent / f"{pdf_path.stem}_firmado{pdf_path.suffix}"
                shutil.copy2(pdf_path, output_path)

                logger.info(f"[DRY-RUN] Firmado: {pdf_path.name} → {output_path.name}")
                successful += 1

                # Notificar éxito
                if progress_callback:
                    progress = MockBatchProgress(
                        current=i + 1,
                        total=total,
                        current_file=current_file,
                        status="success",
                        message="Firmado (simulado)",
                    )
                    progress_callback(progress)

            except Exception as e:
                logger.error(f"[DRY-RUN] Error copiando {pdf_path}: {e}")
                failed += 1
                errors[pdf_path] = str(e)

                if progress_callback:
                    progress = MockBatchProgress(
                        current=i + 1,
                        total=total,
                        current_file=current_file,
                        status="error",
                        message=str(e),
                    )
                    progress_callback(progress)

        logger.info(f"[DRY-RUN] Firma completada: {successful} éxito, {failed} fallidos")

        return MockBatchResult(
            successful=successful,
            failed=failed,
            all_successful=(failed == 0),
            errors=errors,
        )


def enable_dry_run_mode():
    """
    Habilita el modo dry-run globalmente.

    Modifica el setting para que los componentes
    usen implementaciones mock automáticamente.
    """
    import os

    # Settings es inmutable, usamos variable de entorno
    os.environ["PDFSIGNER_DRY_RUN"] = "true"
    logger.warning("⚠️  MODO DRY-RUN ACTIVADO - Sin firma real")

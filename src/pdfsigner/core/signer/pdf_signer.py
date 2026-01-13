"""
pdf_signer.py - Firmador de PDFs con PAdES-LTV

Autor: Homero Thompson del Lago del Terror

Implementa firma digital PAdES-LTV usando pyHanko
con soporte para token USB vía PKCS#11/NSS.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
from pdfsigner.core.pdf_analyzer.position_finder import PositionFinder, PositionPreference
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFCorruptedError, PDFProtectedError


@dataclass
class SignatureAppearance:
    """Configuración de apariencia de firma visible."""

    visible: bool = False
    page: int | str = "last"  # Número de página o "last", "first", "all"
    width_mm: float = 50
    height_mm: float = 20
    position_preference: PositionPreference = PositionPreference.AUTO
    image_path: Path | None = None
    show_date: bool = True
    show_name: bool = True


@dataclass
class SigningResult:
    """Resultado de una operación de firma."""

    success: bool
    input_path: Path
    output_path: Path | None
    error: str | None = None
    signed_at: datetime | None = None


class PDFSigner:
    """
    Firmador de PDFs con PAdES-LTV.

    Usa pyHanko para crear firmas digitales válidas
    según el estándar PAdES-LTV.
    """

    def __init__(
        self,
        nss_handler: NSSHandler,
        lta_handler: LTAHandler | None = None,
    ):
        """
        Inicializa el firmador.

        Args:
            nss_handler: Handler de NSS autenticado
            lta_handler: Handler LTA para timestamp (opcional)
        """
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        self._signer: signers.Signer | None = None

    def _create_signer(self, cert_id: bytes | None = None) -> signers.Signer:
        """Crea el signer de pyHanko con el certificado del token."""
        priv_key, cert_der = self.nss_handler.get_signing_key_and_cert(cert_id)

        # Cargar certificado
        cert = x509.load_der_x509_certificate(cert_der)

        # Crear signer PKCS#11
        # pyHanko espera un SimpleSigner o PKCS11Signer
        # Como estamos usando python-pkcs11, creamos un wrapper
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=priv_key,
            cert_registry=None,
        )

        return signer

    def _validate_pdf(self, pdf_path: Path) -> None:
        """Valida que el PDF pueda ser firmado."""
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Verificar que no esté corrupto
                if reader.root is None:
                    raise PDFCorruptedError(pdf_path.name)

                # Verificar permisos
                if reader.security_handler is not None:
                    # PDF está encriptado
                    perms = reader.security_handler.permissions
                    if perms is not None and not perms.can_modify:
                        raise PDFProtectedError(pdf_path.name)

        except PDFCorruptedError:
            raise
        except PDFProtectedError:
            raise
        except Exception as e:
            raise PDFCorruptedError(pdf_path.name) from e

    def _get_output_path(self, input_path: Path) -> Path:
        """Genera el path de salida para el PDF firmado."""
        settings = get_settings()
        suffix = settings.output_suffix
        return input_path.with_stem(f"{input_path.stem}{suffix}")

    def _mm_to_points(self, mm: float) -> float:
        """Convierte milímetros a puntos PDF."""
        return mm * 72 / 25.4

    def _create_signature_field_spec(
        self,
        pdf_path: Path,
        appearance: SignatureAppearance,
    ) -> SigFieldSpec | None:
        """Crea la especificación del campo de firma visible."""
        if not appearance.visible:
            return None

        # Determinar página
        with ContentAnalyzer(pdf_path) as analyzer:
            total_pages = analyzer.page_count

            if appearance.page == "last":
                page_num = total_pages - 1
            elif appearance.page == "first":
                page_num = 0
            elif isinstance(appearance.page, int):
                page_num = min(appearance.page, total_pages - 1)
            else:
                page_num = total_pages - 1

            # Encontrar posición óptima
            finder = PositionFinder(analyzer)
            sig_width = self._mm_to_points(appearance.width_mm)
            sig_height = self._mm_to_points(appearance.height_mm)

            position = finder.find_position(
                page_num,
                sig_width,
                sig_height,
                appearance.position_preference,
            )

        # Crear especificación del campo
        box = (
            position.x,
            position.y,
            position.x + position.width,
            position.y + position.height,
        )

        return SigFieldSpec(
            sig_field_name="Signature1",
            on_page=page_num,
            box=box,
        )

    def sign_pdf(
        self,
        input_path: Path,
        output_path: Path | None = None,
        appearance: SignatureAppearance | None = None,
        cert_id: bytes | None = None,
    ) -> SigningResult:
        """
        Firma un PDF.

        Args:
            input_path: Ruta al PDF a firmar
            output_path: Ruta de salida (None = automática)
            appearance: Configuración de apariencia
            cert_id: ID del certificado a usar (None = default)

        Returns:
            Resultado de la operación de firma
        """
        input_path = Path(input_path)
        output_path = output_path or self._get_output_path(input_path)
        appearance = appearance or SignatureAppearance()

        logger.info(f"Firmando: {input_path.name}")

        try:
            # Validar PDF
            self._validate_pdf(input_path)

            # Crear signer
            signer = self._create_signer(cert_id)

            # Configurar firma
            sig_kwargs = {}

            # Agregar timestamper si está disponible
            if self.lta_handler and self.lta_handler.tsa_config.url:
                sig_kwargs["timestamper"] = self.lta_handler.get_timestamper()
                sig_kwargs["embed_validation_info"] = True

            # Abrir PDF
            with open(input_path, "rb") as f:
                writer = IncrementalPdfFileWriter(f)

                # Agregar campo de firma si es visible
                field_spec = self._create_signature_field_spec(input_path, appearance)
                if field_spec:
                    append_signature_field(writer, field_spec)

                # Crear configuración de firma
                sig_field_name = field_spec.sig_field_name if field_spec else None

                # Firmar
                with open(output_path, "wb") as out:
                    signers.sign_pdf(
                        writer,
                        signers.PdfSignatureMetadata(
                            field_name=sig_field_name,
                            md_algorithm="sha256",
                            subfilter=signers.SigSeedSubFilter.PADES,
                        ),
                        signer=signer,
                        output=out,
                        **sig_kwargs,
                    )

            logger.info(f"PDF firmado exitosamente: {output_path.name}")

            return SigningResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                signed_at=datetime.now(),
            )

        except (PDFCorruptedError, PDFProtectedError) as e:
            logger.error(f"Error en PDF: {e}")
            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
        except Exception as e:
            logger.error(f"Error firmando PDF: {e}")
            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )

"""
pdf_validator.py - Validador de firmas digitales en PDFs

Autor: Homero Thompson del Lago del Terror

Verifica firmas existentes en documentos PDF y extrae
información sobre los firmantes.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints


class SignatureStatus(Enum):
    """Estado de validación de una firma."""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    INDETERMINATE = "indeterminate"


@dataclass
class SignatureInfo:
    """Información de una firma en el PDF."""

    signer_name: str
    signer_email: str | None
    signing_time: datetime | None
    is_timestamp_valid: bool
    certificate_issuer: str
    certificate_serial: str
    certificate_valid_from: datetime | None
    certificate_valid_to: datetime | None
    status: SignatureStatus
    status_message: str
    field_name: str
    covers_whole_document: bool
    is_modification_allowed: bool
    page_number: int | None  # Página donde está la firma visible (si aplica)


@dataclass
class ValidationResult:
    """Resultado de validación de un PDF."""

    file_path: Path
    is_signed: bool
    signature_count: int
    all_valid: bool
    signatures: list[SignatureInfo]
    error: str | None = None


class PDFValidator:
    """
    Validador de firmas digitales en PDFs.

    Verifica la integridad y autenticidad de las firmas
    existentes en un documento PDF.
    """

    def __init__(self):
        """Inicializa el validador."""
        pass

    def validate(self, pdf_path: Path | str) -> ValidationResult:
        """
        Valida todas las firmas de un PDF.

        Args:
            pdf_path: Ruta al archivo PDF

        Returns:
            ValidationResult con información de todas las firmas
        """
        pdf_path = Path(pdf_path)
        signatures: list[SignatureInfo] = []

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Obtener campos de firma
                sig_fields = self._get_signature_fields(reader)

                if not sig_fields:
                    return ValidationResult(
                        file_path=pdf_path,
                        is_signed=False,
                        signature_count=0,
                        all_valid=True,
                        signatures=[],
                    )

                # Validar cada firma
                all_valid = True
                for field_name in sig_fields:
                    sig_info = self._validate_signature(reader, field_name)
                    signatures.append(sig_info)

                    if sig_info.status != SignatureStatus.VALID:
                        all_valid = False

                logger.info(
                    f"Validación completada: {pdf_path.name} - "
                    f"{len(signatures)} firma(s), válidas: {all_valid}"
                )

                return ValidationResult(
                    file_path=pdf_path,
                    is_signed=True,
                    signature_count=len(signatures),
                    all_valid=all_valid,
                    signatures=signatures,
                )

        except Exception as e:
            logger.error(f"Error validando {pdf_path.name}: {e}")
            return ValidationResult(
                file_path=pdf_path,
                is_signed=False,
                signature_count=0,
                all_valid=False,
                signatures=[],
                error=str(e),
            )

    def _get_signature_fields(self, reader: PdfFileReader) -> list[str]:
        """Obtiene los nombres de campos de firma del PDF."""
        sig_fields = []
        try:
            if reader.embedded_signatures:
                for sig in reader.embedded_signatures:
                    sig_fields.append(sig.field_name)
        except Exception as e:
            logger.warning(f"Error obteniendo campos de firma: {e}")
        return sig_fields

    def _validate_signature(self, reader: PdfFileReader, field_name: str) -> SignatureInfo:
        """Valida una firma específica."""
        try:
            # Encontrar la firma
            sig = None
            for s in reader.embedded_signatures:
                if s.field_name == field_name:
                    sig = s
                    break

            if sig is None:
                return self._create_error_info(field_name, "Firma no encontrada")

            # Validar la firma
            status = validate_pdf_signature(
                sig,
                key_usage_settings=KeyUsageConstraints(
                    key_usage={"digital_signature", "non_repudiation"},
                ),
            )

            # Extraer información del certificado
            cert = sig.signer_cert
            signer_name = self._extract_cn(cert.subject.human_friendly)
            signer_email = self._extract_email(cert)
            issuer = self._extract_cn(cert.issuer.human_friendly)

            # Determinar estado
            if status.valid:
                sig_status = SignatureStatus.VALID
                status_msg = "Firma válida"
            elif status.intact:
                sig_status = SignatureStatus.INDETERMINATE
                status_msg = "Firma intacta pero no se pudo verificar cadena"
            else:
                sig_status = SignatureStatus.INVALID
                status_msg = "Firma inválida o documento modificado"

            return SignatureInfo(
                signer_name=signer_name,
                signer_email=signer_email,
                signing_time=status.timestamp_validity.timestamp
                if status.timestamp_validity
                else None,
                is_timestamp_valid=status.timestamp_validity is not None
                and status.timestamp_validity.valid,
                certificate_issuer=issuer,
                certificate_serial=format(cert.serial_number, "x"),
                certificate_valid_from=cert.not_valid_before,
                certificate_valid_to=cert.not_valid_after,
                status=sig_status,
                status_message=status_msg,
                field_name=field_name,
                covers_whole_document=status.coverage.value >= 2,  # ENTIRE_REVISION o más
                is_modification_allowed=status.modification_level is not None,
                page_number=None,  # TODO: extraer de annotation
            )

        except Exception as e:
            logger.warning(f"Error validando firma {field_name}: {e}")
            return self._create_error_info(field_name, str(e))

    def _create_error_info(self, field_name: str, error: str) -> SignatureInfo:
        """Crea SignatureInfo para errores."""
        return SignatureInfo(
            signer_name="Desconocido",
            signer_email=None,
            signing_time=None,
            is_timestamp_valid=False,
            certificate_issuer="Desconocido",
            certificate_serial="",
            certificate_valid_from=None,
            certificate_valid_to=None,
            status=SignatureStatus.UNKNOWN,
            status_message=f"Error: {error}",
            field_name=field_name,
            covers_whole_document=False,
            is_modification_allowed=False,
            page_number=None,
        )

    def _extract_cn(self, subject: str) -> str:
        """Extrae el Common Name (CN) de un subject."""
        # subject viene como "CN=Nombre,O=Org,..."
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:]
        return subject

    def _extract_email(self, cert) -> str | None:
        """Extrae email del certificado si existe."""
        try:
            for ext in cert.extensions:
                if ext.oid.dotted_string == "2.5.29.17":  # Subject Alt Name
                    for name in ext.value:
                        if hasattr(name, "value") and "@" in str(name.value):
                            return str(name.value)
        except Exception:
            pass
        return None

    def get_signature_count(self, pdf_path: Path | str) -> int:
        """
        Cuenta rápidamente las firmas en un PDF.

        Args:
            pdf_path: Ruta al PDF

        Returns:
            Número de firmas
        """
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)
                return len(list(reader.embedded_signatures))
        except Exception:
            return 0

    def is_signed(self, pdf_path: Path | str) -> bool:
        """
        Verifica rápidamente si un PDF está firmado.

        Args:
            pdf_path: Ruta al PDF

        Returns:
            True si tiene al menos una firma
        """
        return self.get_signature_count(pdf_path) > 0

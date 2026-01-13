"""
multi_signer.py - Soporte para múltiples firmas en un PDF

Autor: Homero Thompson del Lago del Terror

Permite agregar firmas adicionales a PDFs que ya están firmados,
preservando las firmas existentes.
"""

from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec

from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.core.validator.pdf_validator import PDFValidator


@dataclass
class ExistingSignatureInfo:
    """Información resumida de firma existente."""

    field_name: str
    signer_name: str
    is_valid: bool


class MultiSignatureHandler:
    """
    Manejador de múltiples firmas en PDF.

    Permite:
    - Detectar firmas existentes
    - Agregar firmas adicionales sin invalidar las anteriores
    - Generar nombres únicos para campos de firma
    """

    def __init__(self):
        """Inicializa el handler."""
        self.validator = PDFValidator()

    def get_existing_signatures(self, pdf_path: Path) -> list[ExistingSignatureInfo]:
        """
        Obtiene información de firmas existentes.

        Args:
            pdf_path: Ruta al PDF

        Returns:
            Lista de firmas existentes
        """
        result = self.validator.validate(pdf_path)

        return [
            ExistingSignatureInfo(
                field_name=sig.field_name,
                signer_name=sig.signer_name,
                is_valid=sig.status.value == "valid",
            )
            for sig in result.signatures
        ]

    def get_next_signature_field_name(self, pdf_path: Path) -> str:
        """
        Genera nombre único para el siguiente campo de firma.

        Args:
            pdf_path: Ruta al PDF

        Returns:
            Nombre único para el campo (ej: "Signature2")
        """
        existing = self.get_existing_signatures(pdf_path)

        # Encontrar el número más alto
        max_num = 0
        for sig in existing:
            if sig.field_name.startswith("Signature"):
                try:
                    num = int(sig.field_name.replace("Signature", ""))
                    max_num = max(max_num, num)
                except ValueError:
                    pass

        return f"Signature{max_num + 1}"

    def can_add_signature(self, pdf_path: Path) -> tuple[bool, str]:
        """
        Verifica si se puede agregar una firma adicional.

        Args:
            pdf_path: Ruta al PDF

        Returns:
            Tupla (puede_firmar, mensaje)
        """
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Verificar si el PDF está encriptado
                if reader.security_handler is not None:
                    return False, "El PDF está protegido con contraseña"

                # Verificar si permite modificaciones
                # En PAdES, las firmas incrementales siempre son permitidas
                return True, "OK"

        except Exception as e:
            return False, f"Error leyendo PDF: {e}"

    def prepare_for_additional_signature(
        self,
        pdf_path: Path,
        appearance: SignatureAppearance,
    ) -> tuple[SigFieldSpec | None, str]:
        """
        Prepara el PDF para una firma adicional.

        Args:
            pdf_path: Ruta al PDF
            appearance: Configuración de apariencia

        Returns:
            Tupla (spec_campo_firma, nombre_campo)
        """
        field_name = self.get_next_signature_field_name(pdf_path)

        if not appearance.visible:
            return None, field_name

        # Para firma visible, crear spec con posición
        from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
        from pdfsigner.core.pdf_analyzer.position_finder import PositionFinder

        with ContentAnalyzer(pdf_path) as analyzer:
            total_pages = analyzer.page_count

            # Determinar página
            if appearance.page == "last":
                page_num = total_pages - 1
            elif appearance.page == "first":
                page_num = 0
            elif isinstance(appearance.page, int):
                page_num = min(appearance.page, total_pages - 1)
            else:
                page_num = total_pages - 1

            # Encontrar posición
            finder = PositionFinder(analyzer)
            sig_width = appearance.width_mm * 72 / 25.4
            sig_height = appearance.height_mm * 72 / 25.4

            position = finder.find_position(
                page_num,
                sig_width,
                sig_height,
                appearance.position_preference,
            )

        box = (
            position.x,
            position.y,
            position.x + position.width,
            position.y + position.height,
        )

        spec = SigFieldSpec(
            sig_field_name=field_name,
            on_page=page_num,
            box=box,
        )

        return spec, field_name


def get_signature_summary(pdf_path: Path) -> str:
    """
    Genera resumen de firmas para mostrar al usuario.

    Args:
        pdf_path: Ruta al PDF

    Returns:
        Texto con resumen de firmas
    """
    handler = MultiSignatureHandler()
    signatures = handler.get_existing_signatures(pdf_path)

    if not signatures:
        return "Este documento no tiene firmas digitales."

    lines = [f"Este documento tiene {len(signatures)} firma(s):"]
    for i, sig in enumerate(signatures, 1):
        status = "✓" if sig.is_valid else "✗"
        lines.append(f"  {i}. {status} {sig.signer_name}")

    lines.append("")
    lines.append("Se agregará una firma adicional sin invalidar las existentes.")

    return "\n".join(lines)

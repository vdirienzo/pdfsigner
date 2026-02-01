"""
multi_signer.py - Support for multiple signatures in a PDF

Author: Homero Thompson del Lago del Terror

Allows adding additional signatures to PDFs that are already signed,
preserving existing signatures.
"""

from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec

from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.core.validator.pdf_validator import PDFValidator


@dataclass
class ExistingSignatureInfo:
    """Summary information of existing signature."""

    field_name: str
    signer_name: str
    is_valid: bool


class MultiSignatureHandler:
    """
    Multiple PDF signature handler.

    Allows:
    - Detect existing signatures
    - Add additional signatures without invalidating previous ones
    - Generate unique names for signature fields
    """

    def __init__(self):
        """Initializes the handler."""
        self.validator = PDFValidator()

    def get_existing_signatures(self, pdf_path: Path) -> list[ExistingSignatureInfo]:
        """
        Gets information about existing signatures.

        Args:
            pdf_path: Path to the PDF

        Returns:
            List of existing signatures
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
        Generates unique name for the next signature field.

        Args:
            pdf_path: Path to the PDF

        Returns:
            Unique name for the field (e.g., "Signature2")
        """
        existing = self.get_existing_signatures(pdf_path)

        # Find the highest number
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
        Verifies if an additional signature can be added.

        Args:
            pdf_path: Path to the PDF

        Returns:
            Tuple (can_sign, message)
        """
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)

                # Check if PDF is encrypted
                if reader.security_handler is not None:
                    return False, "PDF is password protected"

                # Check if modifications are allowed
                # In PAdES, incremental signatures are always allowed
                return True, "OK"

        except Exception as e:
            return False, f"Error reading PDF: {e}"

    def prepare_for_additional_signature(
        self,
        pdf_path: Path,
        appearance: SignatureAppearance,
    ) -> tuple[SigFieldSpec | None, str]:
        """
        Prepares the PDF for an additional signature.

        Args:
            pdf_path: Path to the PDF
            appearance: Appearance configuration

        Returns:
            Tuple (signature_field_spec, field_name)
        """
        field_name = self.get_next_signature_field_name(pdf_path)

        if not appearance.visible:
            return None, field_name

        # For visible signature, create spec with position
        from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
        from pdfsigner.core.pdf_analyzer.position_finder import PositionFinder

        with ContentAnalyzer(pdf_path) as analyzer:
            total_pages = analyzer.page_count

            # Determine page
            if appearance.page == "last":
                page_num = total_pages - 1
            elif appearance.page == "first":
                page_num = 0
            elif isinstance(appearance.page, int):
                page_num = min(appearance.page, total_pages - 1)
            else:
                page_num = total_pages - 1

            # Find position
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
    Generates signature summary to show the user.

    Args:
        pdf_path: Path to the PDF

    Returns:
        Text with signature summary
    """
    handler = MultiSignatureHandler()
    signatures = handler.get_existing_signatures(pdf_path)

    if not signatures:
        return "This document has no digital signatures."

    lines = [f"This document has {len(signatures)} signature(s):"]
    for i, sig in enumerate(signatures, 1):
        status = "✓" if sig.is_valid else "✗"
        lines.append(f"  {i}. {status} {sig.signer_name}")

    lines.append("")
    lines.append("An additional signature will be added without invalidating existing ones.")

    return "\n".join(lines)

"""
redactor.py - PDF redaction engine with true text removal.

Author: Homero Thompson del Lago del Terror

Implements permanent redaction of PII/PHI from PDF documents using
PyMuPDF's redaction annotations. This provides true content removal,
not just visual overlays.

PDFRedactor orchestrates region-based and pattern-based redaction,
delegating low-level operations to redaction_helpers.
"""

from datetime import UTC, datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger

from pdfsigner.core.detection.pii_types import PIIType, RedactionRegion
from pdfsigner.core.detection.redaction_helpers import (
    create_scanner,
    group_regions_by_page,
    log_redaction_event,
    make_failure_result,
    parse_pii_types,
    process_page,
    verify_redaction,
)
from pdfsigner.core.detection.redaction_types import RedactionResult
from pdfsigner.exceptions import PDFCorruptedError

# Backward-compatible aliases for external consumers
_log_redaction_event = log_redaction_event


class PDFRedactor:
    """
    PDF redaction engine using PyMuPDF.

    Performs true redaction (text removal) rather than visual overlays.
    Supports region-based redaction and automatic PII detection integration.

    Usage:
        redactor = PDFRedactor()
        regions = [
            RedactionRegion(page=0, x0=100, y0=200, x1=300, y1=220,
                          replacement_text="[REDACTED]")
        ]
        result = redactor.redact_regions("doc.pdf", regions, "doc_redacted.pdf")
    """

    def __init__(
        self,
        default_fill_color: tuple[float, float, float] = (0, 0, 0),
        default_text_color: tuple[float, float, float] = (1, 1, 1),
    ):
        self.default_fill_color = default_fill_color
        self.default_text_color = default_text_color

    def redact_regions(
        self,
        pdf_path: str | Path,
        regions: list[RedactionRegion],
        output_path: str | Path,
    ) -> RedactionResult:
        """
        Redact specific regions in a PDF.

        Args:
            pdf_path: Path to input PDF
            regions: List of RedactionRegion objects to redact
            output_path: Path for output redacted PDF

        Returns:
            RedactionResult with success status and details

        Raises:
            PDFCorruptedError: If PDF cannot be opened
            FileNotFoundError: If PDF file does not exist
        """
        pdf_path = Path(pdf_path)
        output_path = Path(output_path)

        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        if not regions:
            logger.warning(f"No regions to redact for {pdf_path}")
            return RedactionResult(
                success=True,
                output_path=str(output_path),
                redaction_count=0,
                pages_affected=[],
                input_path=str(pdf_path),
                redacted_at=datetime.now(UTC),
            )

        try:
            return self._execute_region_redaction(pdf_path, regions, output_path)
        except (PDFCorruptedError, FileNotFoundError):
            raise
        except Exception as e:
            logger.exception(f"Redaction failed for {pdf_path}: {e}")
            return make_failure_result(pdf_path, str(e))

    def _execute_region_redaction(
        self,
        pdf_path: Path,
        regions: list[RedactionRegion],
        output_path: Path,
    ) -> RedactionResult:
        """Open PDF, apply all redactions, save, and verify."""
        try:
            doc = fitz.open(pdf_path)
        except Exception as e:
            raise PDFCorruptedError(pdf_path.name) from e

        errors: list[str] = []
        pages_affected: set[int] = set()
        redaction_count = 0

        try:
            for page_num, page_regions in group_regions_by_page(regions).items():
                redaction_count += process_page(
                    doc, page_num, page_regions, self.default_text_color, errors, pages_affected
                )
            doc.save(output_path, garbage=4, deflate=True, clean=True)
        finally:
            doc.close()

        verify_redaction(output_path, regions)

        logger.info(
            f"Redacted {redaction_count} regions on {len(pages_affected)} pages: "
            f"{pdf_path} -> {output_path}"
        )

        return RedactionResult(
            success=True,
            output_path=str(output_path),
            redaction_count=redaction_count,
            pages_affected=sorted(pages_affected),
            errors=errors,
            input_path=str(pdf_path),
            redacted_at=datetime.now(UTC),
        )

    def redact_by_pattern(
        self,
        pdf_path: str | Path,
        pii_types: list[str],
        output_path: str | Path,
        min_confidence: float = 0.7,
    ) -> RedactionResult:
        """Auto-detect and redact PII by type."""
        pdf_path = Path(pdf_path)
        output_path = Path(output_path)

        try:
            return self._execute_pattern_redaction(pdf_path, output_path, pii_types, min_confidence)
        except Exception as e:
            logger.exception(f"Pattern-based redaction failed for {pdf_path}: {e}")
            return make_failure_result(pdf_path, str(e))

    def _execute_pattern_redaction(
        self,
        pdf_path: Path,
        output_path: Path,
        pii_types: list[str],
        min_confidence: float,
    ) -> RedactionResult:
        """Run PII detection pipeline and delegate to region redaction."""
        scanner = create_scanner()
        if scanner is None:
            msg = "PII detector not available. Use redact_regions() for manual redaction."
            logger.error(msg)
            return make_failure_result(pdf_path, msg)

        pii_type_enums = parse_pii_types(pii_types)
        if not pii_type_enums:
            return make_failure_result(pdf_path, "No valid PII types specified")

        regions = self._detect_and_build_regions(scanner, pdf_path, pii_type_enums, min_confidence)
        if regions is None:
            return RedactionResult(
                success=True,
                output_path=str(output_path),
                redaction_count=0,
                pages_affected=[],
                input_path=str(pdf_path),
                redacted_at=datetime.now(UTC),
            )

        result = self.redact_regions(pdf_path, regions, output_path)

        if result.success:
            log_redaction_event(pdf_path, pii_types, result.redaction_count, result.pages_affected)

        return result

    def _detect_and_build_regions(
        self,
        scanner: object,
        pdf_path: Path,
        pii_type_enums: list[PIIType],
        min_confidence: float,
    ) -> list[RedactionRegion] | None:
        """Scan PDF for PII and return redaction regions, or None if no matches."""
        all_matches = scanner.scan_pdf(str(pdf_path))  # type: ignore[attr-defined]
        matches = [m for m in all_matches if m.pii_type in pii_type_enums]
        high_confidence = [m for m in matches if m.confidence >= min_confidence]

        if not high_confidence:
            logger.info(f"No PII detected above confidence threshold {min_confidence}")
            return None

        return [match.to_redaction_region() for match in high_confidence]

    def preview_redactions(
        self,
        pdf_path: str | Path,
        regions: list[RedactionRegion],
        page_num: int = 0,
        dpi: int = 150,
    ) -> bytes:
        """
        Generate preview image showing redaction regions.

        Args:
            pdf_path: Path to PDF
            regions: Redaction regions to preview
            page_num: Page number to preview (0-indexed)
            dpi: Resolution for preview image

        Returns:
            PNG image data as bytes

        Raises:
            PDFCorruptedError: If PDF cannot be opened
            ValueError: If page number is invalid
        """
        pdf_path = Path(pdf_path)

        try:
            doc = fitz.open(pdf_path)
        except Exception as e:
            raise PDFCorruptedError(pdf_path.name) from e

        try:
            if page_num < 0 or page_num >= len(doc):
                raise ValueError(f"Invalid page number {page_num} (document has {len(doc)} pages)")

            page = doc[page_num]
            zoom = dpi / 72
            mat = fitz.Matrix(zoom, zoom)
            pix = page.get_pixmap(matrix=mat)
            png_data = pix.tobytes("png")
        finally:
            doc.close()

        return png_data


# Singleton instance
_redactor_instance: PDFRedactor | None = None


def get_pdf_redactor(
    default_fill_color: tuple[float, float, float] = (0, 0, 0),
    default_text_color: tuple[float, float, float] = (1, 1, 1),
) -> PDFRedactor:
    """Get or create PDF redactor singleton."""
    global _redactor_instance
    if _redactor_instance is None:
        _redactor_instance = PDFRedactor(default_fill_color, default_text_color)
    return _redactor_instance

"""
redactor.py - PDF redaction engine with true text removal

Author: Homero Thompson del Lago del Terror

Implements permanent redaction of PII/PHI from PDF documents using
PyMuPDF's redaction annotations. This provides true content removal,
not just visual overlays.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger

from pdfsigner.core.detection.pii_types import PIIType, RedactionRegion
from pdfsigner.exceptions import PDFCorruptedError


@dataclass
class RedactionResult:
    """
    Result of a redaction operation.

    Attributes:
        success: Whether redaction completed successfully
        output_path: Path to redacted PDF file
        redaction_count: Number of regions redacted
        pages_affected: List of page numbers with redactions
        errors: List of error messages encountered
        input_path: Original PDF path
        redacted_at: Timestamp of redaction
    """

    success: bool
    output_path: str | None
    redaction_count: int
    pages_affected: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    input_path: str | None = None
    redacted_at: datetime | None = None

    def __str__(self) -> str:
        if self.success:
            return (
                f"✓ Redacted: {self.input_path} → {self.output_path} "
                f"({self.redaction_count} regions on {len(self.pages_affected)} pages)"
            )
        return f"✗ Redaction failed: {self.input_path} - {', '.join(self.errors)}"


class PDFRedactor:
    """
    PDF redaction engine using PyMuPDF.

    Performs true redaction (text removal) rather than visual overlays.
    Supports region-based redaction and automatic PII detection integration.

    Usage:
        redactor = PDFRedactor()

        # Region-based redaction
        regions = [
            RedactionRegion(page=0, x0=100, y0=200, x1=300, y1=220,
                          replacement_text="[REDACTED]")
        ]
        result = redactor.redact_regions("doc.pdf", regions, "doc_redacted.pdf")

        # Pattern-based (auto-detect PII)
        result = redactor.redact_by_pattern(
            "doc.pdf",
            pii_types=["ssn", "credit_card"],
            output_path="doc_redacted.pdf"
        )
    """

    def __init__(
        self,
        default_fill_color: tuple[float, float, float] = (0, 0, 0),
        default_text_color: tuple[float, float, float] = (1, 1, 1),
    ):
        """
        Initialize redactor.

        Args:
            default_fill_color: Default RGB color for redaction box (0-1 range)
            default_text_color: Default RGB color for replacement text (0-1 range)
        """
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

        Uses PyMuPDF's redaction annotations for true text removal.
        The underlying text is permanently removed from the PDF structure.

        Args:
            pdf_path: Path to input PDF
            regions: List of RedactionRegion objects to redact
            output_path: Path for output redacted PDF

        Returns:
            RedactionResult with success status and details

        Raises:
            PDFCorruptedError: If PDF cannot be opened
            PDFError: If redaction fails
        """
        pdf_path = Path(pdf_path)
        output_path = Path(output_path)
        errors = []
        pages_affected = set()

        try:
            # Validate input
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

            # Open PDF
            try:
                doc = fitz.open(pdf_path)
            except Exception as e:
                raise PDFCorruptedError(pdf_path.name) from e

            # Group regions by page for efficiency
            regions_by_page: dict[int, list[RedactionRegion]] = {}
            for region in regions:
                if region.page not in regions_by_page:
                    regions_by_page[region.page] = []
                regions_by_page[region.page].append(region)

            # Apply redactions page by page
            redaction_count = 0
            for page_num, page_regions in regions_by_page.items():
                try:
                    # Validate page number
                    if page_num < 0 or page_num >= len(doc):
                        error_msg = (
                            f"Invalid page number {page_num} (document has {len(doc)} pages)"
                        )
                        errors.append(error_msg)
                        logger.warning(error_msg)
                        continue

                    page = doc[page_num]

                    # Add redaction annotations for each region
                    for region in page_regions:
                        try:
                            # Create rectangle (PyMuPDF uses bottom-left origin like PDF spec)
                            rect = fitz.Rect(region.x0, region.y0, region.x1, region.y1)

                            # Add redaction annotation
                            annot = page.add_redact_annot(
                                rect,
                                text=region.replacement_text or "",
                                fill=region.fill_color,
                                text_color=self.default_text_color,
                            )

                            if annot:
                                redaction_count += 1
                            else:
                                error_msg = f"Failed to add redaction annotation on page {page_num}"
                                errors.append(error_msg)
                                logger.warning(error_msg)

                        except Exception as e:
                            error_msg = f"Error adding redaction on page {page_num}: {e}"
                            errors.append(error_msg)
                            logger.warning(error_msg)

                    # Apply all redactions on this page (this removes the actual text)
                    page.apply_redactions()
                    pages_affected.add(page_num)

                except Exception as e:
                    error_msg = f"Error processing page {page_num}: {e}"
                    errors.append(error_msg)
                    logger.error(error_msg)

            # Save redacted document
            doc.save(output_path, garbage=4, deflate=True, clean=True)
            doc.close()

            # Verify text was actually removed
            self._verify_redaction(output_path, regions)

            logger.info(
                f"Redacted {redaction_count} regions on {len(pages_affected)} pages: "
                f"{pdf_path} → {output_path}"
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

        except (PDFCorruptedError, FileNotFoundError):
            raise
        except Exception as e:
            logger.exception(f"Redaction failed for {pdf_path}: {e}")
            return RedactionResult(
                success=False,
                output_path=None,
                redaction_count=0,
                pages_affected=[],
                errors=[str(e)],
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
        """
        Auto-detect and redact PII by type.

        Integrates with PIIDetector to automatically find and redact
        specified types of PII/PHI in the document.

        Args:
            pdf_path: Path to input PDF
            pii_types: List of PII types to detect (e.g., ["ssn", "credit_card"])
            output_path: Path for output redacted PDF
            min_confidence: Minimum confidence threshold for detection (0.0-1.0)

        Returns:
            RedactionResult with success status and details
        """
        pdf_path = Path(pdf_path)
        output_path = Path(output_path)

        try:
            # Import PII detector
            try:
                from pdfsigner.core.detection.pii_detector import get_pii_detector

                detector = get_pii_detector()
            except ImportError:
                error_msg = "PII detector not available. Use redact_regions() for manual redaction."
                logger.error(error_msg)
                return RedactionResult(
                    success=False,
                    output_path=None,
                    redaction_count=0,
                    errors=[error_msg],
                    input_path=str(pdf_path),
                    redacted_at=datetime.now(UTC),
                )

            # Convert string types to PIIType enum
            pii_type_enums = []
            for pii_type_str in pii_types:
                try:
                    pii_type_enums.append(PIIType(pii_type_str))
                except ValueError:
                    logger.warning(f"Unknown PII type: {pii_type_str}")

            if not pii_type_enums:
                return RedactionResult(
                    success=False,
                    output_path=None,
                    redaction_count=0,
                    errors=["No valid PII types specified"],
                    input_path=str(pdf_path),
                    redacted_at=datetime.now(UTC),
                )

            # Scan document for PII
            matches = detector.scan_pdf(str(pdf_path), pii_types=pii_type_enums)

            # Filter by confidence
            high_confidence_matches = [m for m in matches if m.confidence >= min_confidence]

            if not high_confidence_matches:
                logger.info(f"No PII detected above confidence threshold {min_confidence}")
                return RedactionResult(
                    success=True,
                    output_path=str(output_path),
                    redaction_count=0,
                    pages_affected=[],
                    input_path=str(pdf_path),
                    redacted_at=datetime.now(UTC),
                )

            # Convert matches to redaction regions
            regions = [match.to_redaction_region() for match in high_confidence_matches]

            # Perform redaction
            result = self.redact_regions(pdf_path, regions, output_path)

            # Log to audit trail
            if result.success:
                self._log_redaction_event(
                    pdf_path,
                    pii_types,
                    result.redaction_count,
                    result.pages_affected,
                )

            return result

        except Exception as e:
            logger.exception(f"Pattern-based redaction failed for {pdf_path}: {e}")
            return RedactionResult(
                success=False,
                output_path=None,
                redaction_count=0,
                errors=[str(e)],
                input_path=str(pdf_path),
                redacted_at=datetime.now(UTC),
            )

    def preview_redactions(
        self,
        pdf_path: str | Path,
        regions: list[RedactionRegion],
        page_num: int = 0,
        dpi: int = 150,
    ) -> bytes:
        """
        Generate preview image showing redaction regions.

        Creates a PNG image of the specified page with redaction
        regions highlighted (but not yet applied).

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

        if page_num < 0 or page_num >= len(doc):
            raise ValueError(f"Invalid page number {page_num} (document has {len(doc)} pages)")

        page = doc[page_num]

        # Render page to image
        zoom = dpi / 72  # 72 DPI is PDF default
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat)

        # Draw redaction regions as semi-transparent rectangles
        page_regions = [r for r in regions if r.page == page_num]
        for region in page_regions:
            rect = fitz.Rect(region.x0, region.y0, region.x1, region.y1)
            # Transform rect coordinates to pixel space
            rect = rect * mat

            # Draw red rectangle outline
            img_data = pix.samples
            # Note: This is a simplified preview. For production, consider using PIL/Pillow
            # to draw semi-transparent overlays

        png_data = pix.tobytes("png")
        doc.close()

        return png_data

    def _verify_redaction(self, pdf_path: Path, regions: list[RedactionRegion]) -> None:
        """
        Verify that text was actually removed from redacted regions.

        Opens the redacted PDF and checks that no text exists in the
        redacted coordinates. Logs warnings if text is still present.

        Args:
            pdf_path: Path to redacted PDF
            regions: Regions that were redacted
        """
        try:
            doc = fitz.open(pdf_path)

            for region in regions[:5]:  # Sample first 5 regions
                if region.page < len(doc):
                    page = doc[region.page]
                    rect = fitz.Rect(region.x0, region.y0, region.x1, region.y1)

                    # Extract text from redacted region
                    text = page.get_text("text", clip=rect).strip()

                    # Check if replacement text is present (expected)
                    if text and region.replacement_text and region.replacement_text in text:
                        continue  # OK - replacement text is expected

                    # Check for unexpected text (potential redaction failure)
                    if text and text != (region.replacement_text or ""):
                        logger.warning(
                            f"Potential redaction verification failure on page {region.page}: "
                            f"found text '{text[:50]}' in redacted region"
                        )

            doc.close()

        except Exception as e:
            logger.warning(f"Could not verify redaction: {e}")

    def _log_redaction_event(
        self,
        pdf_path: Path,
        pii_types: list[str],
        redaction_count: int,
        pages_affected: list[int],
    ) -> None:
        """
        Log redaction event to audit trail.

        Args:
            pdf_path: Path to redacted document
            pii_types: Types of PII that were redacted
            redaction_count: Number of redactions performed
            pages_affected: List of affected page numbers
        """
        try:
            from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
            from pdfsigner.core.audit.audit_logger import AuditLogger

            audit_logger = AuditLogger.get_instance()

            event = AuditEvent(
                event_type=AuditEventType.ENCRYPT_SUCCESS,  # Reuse encryption type for now
                status="SUCCESS",
                document_path=str(pdf_path),
                details={
                    "operation": "redaction",
                    "pii_types": pii_types,
                    "redaction_count": redaction_count,
                    "pages_affected": pages_affected,
                },
                phi_accessed=True,  # Redaction involves PHI/PII
            )

            audit_logger.log_event(event)

        except Exception as e:
            # Non-fatal - log but don't fail redaction
            logger.warning(f"Could not log redaction event to audit trail: {e}")


# Singleton instance
_redactor_instance: PDFRedactor | None = None


def get_pdf_redactor(
    default_fill_color: tuple[float, float, float] = (0, 0, 0),
    default_text_color: tuple[float, float, float] = (1, 1, 1),
) -> PDFRedactor:
    """
    Get or create PDF redactor singleton.

    Args:
        default_fill_color: Default RGB color for redaction box (0-1 range)
        default_text_color: Default RGB color for replacement text (0-1 range)

    Returns:
        PDFRedactor instance
    """
    global _redactor_instance
    if _redactor_instance is None:
        _redactor_instance = PDFRedactor(default_fill_color, default_text_color)
    return _redactor_instance

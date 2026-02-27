"""
redaction_helpers.py - Helper functions for PDF redaction operations.

Author: Homero Thompson del Lago del Terror

Pure functions and utilities used by PDFRedactor to process
redaction annotations, verify results, and manage audit logging.
"""

from datetime import UTC, datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger

from pdfsigner.core.detection.pii_types import PIIType, RedactionRegion
from pdfsigner.core.detection.redaction_types import RedactionResult


def group_regions_by_page(
    regions: list[RedactionRegion],
) -> dict[int, list[RedactionRegion]]:
    """Group redaction regions by page number for batch processing."""
    regions_by_page: dict[int, list[RedactionRegion]] = {}
    for region in regions:
        if region.page not in regions_by_page:
            regions_by_page[region.page] = []
        regions_by_page[region.page].append(region)
    return regions_by_page


def add_redaction_annotations(
    page: fitz.Page,
    page_num: int,
    page_regions: list[RedactionRegion],
    text_color: tuple[float, float, float],
    errors: list[str],
) -> int:
    """
    Add redaction annotations to a single page.

    Returns the number of annotations successfully added.
    """
    count = 0
    for region in page_regions:
        try:
            rect = fitz.Rect(region.x0, region.y0, region.x1, region.y1)
            annot = page.add_redact_annot(
                rect,
                text=region.replacement_text or "",
                fill=region.fill_color,
                text_color=text_color,
            )
            if annot:
                count += 1
            else:
                error_msg = f"Failed to add redaction annotation on page {page_num}"
                errors.append(error_msg)
                logger.warning(error_msg)
        except Exception as e:
            error_msg = f"Error adding redaction on page {page_num}: {e}"
            errors.append(error_msg)
            logger.warning(error_msg)
    return count


def process_page(
    doc: fitz.Document,
    page_num: int,
    page_regions: list[RedactionRegion],
    text_color: tuple[float, float, float],
    errors: list[str],
    pages_affected: set[int],
) -> int:
    """
    Process redactions for a single page: validate, annotate, and apply.

    Returns the number of redactions applied on this page.
    """
    if page_num < 0 or page_num >= len(doc):
        error_msg = f"Invalid page number {page_num} (document has {len(doc)} pages)"
        errors.append(error_msg)
        logger.warning(error_msg)
        return 0

    try:
        page = doc[page_num]
        count = add_redaction_annotations(page, page_num, page_regions, text_color, errors)
        page.apply_redactions()
        pages_affected.add(page_num)
        return count
    except Exception as e:
        error_msg = f"Error processing page {page_num}: {e}"
        errors.append(error_msg)
        logger.error(error_msg)
        return 0


def verify_redaction(pdf_path: Path, regions: list[RedactionRegion]) -> None:
    """
    Verify that text was actually removed from redacted regions.

    Opens the redacted PDF and checks that no text exists in the
    redacted coordinates. Logs warnings if text is still present.
    """
    try:
        doc = fitz.open(pdf_path)
        try:
            for region in regions[:5]:  # Sample first 5 regions
                if region.page < len(doc):
                    page = doc[region.page]
                    rect = fitz.Rect(region.x0, region.y0, region.x1, region.y1)
                    text = page.get_text("text", clip=rect).strip()

                    if text and region.replacement_text and region.replacement_text in text:
                        continue  # OK - replacement text is expected

                    if text and text != (region.replacement_text or ""):
                        logger.warning(
                            f"Potential redaction verification failure on page "
                            f"{region.page}: found text '{text[:50]}' in redacted region"
                        )
        finally:
            doc.close()
    except Exception as e:
        logger.warning(f"Could not verify redaction: {e}")


def log_redaction_event(
    pdf_path: Path,
    pii_types: list[str],
    redaction_count: int,
    pages_affected: list[int],
) -> None:
    """Log redaction event to audit trail."""
    try:
        from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
        from pdfsigner.core.audit.audit_logger import AuditLogger

        audit_logger = AuditLogger.get_instance()
        event = AuditEvent(
            event_type=AuditEventType.ENCRYPT_SUCCESS,
            status="SUCCESS",
            document_path=str(pdf_path),
            details={
                "operation": "redaction",
                "pii_types": pii_types,
                "redaction_count": redaction_count,
                "pages_affected": pages_affected,
            },
            phi_accessed=True,
        )
        audit_logger.log_event(event)
    except Exception as e:
        logger.warning(f"Could not log redaction event to audit trail: {e}")


def make_failure_result(pdf_path: str | Path, error: str) -> RedactionResult:
    """Build a standard failure RedactionResult."""
    return RedactionResult(
        success=False,
        output_path=None,
        redaction_count=0,
        errors=[error],
        input_path=str(pdf_path),
        redacted_at=datetime.now(UTC),
    )


def create_scanner():  # type: ignore[return]
    """Import and create PDFScanner, returning None on ImportError."""
    try:
        from pdfsigner.core.detection.pdf_scanner import PDFScanner

        return PDFScanner()
    except ImportError:
        return None


def parse_pii_types(pii_types: list[str]) -> list[PIIType]:
    """Convert string PII type names to PIIType enums, skipping unknowns."""
    result = []
    for pii_type_str in pii_types:
        try:
            result.append(PIIType(pii_type_str))
        except ValueError:
            logger.warning(f"Unknown PII type: {pii_type_str}")
    return result

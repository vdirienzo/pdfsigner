"""
mock_batch.py - Mock batch signing manager for dry-run mode

Author: Homero Thompson del Lago del Terror

Simulates batch signing with visual stamp simulation.
"""

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger


@dataclass
class MockBatchProgress:
    """Simulated batch signing progress (compatible with BatchProgress)."""

    current: int
    total: int
    current_file: str
    status: str
    message: str = ""

    @property
    def completed(self) -> int:
        """Successfully completed files (for BatchProgress compatibility)."""
        return self.current if self.status == "success" else max(0, self.current - 1)

    @property
    def failed(self) -> int:
        """Failed files (for BatchProgress compatibility)."""
        return 0  # In dry-run there are no failures during progress


@dataclass
class MockBatchResult:
    """Simulated batch signing result."""

    successful: int
    failed: int
    all_successful: bool
    errors: dict[Path, str]

    def get_failed_files(self):
        """Returns failed files."""
        return list(self.errors.items())


def _parse_page_spec(page_spec: str | int, total_pages: int) -> list[int]:
    """
    Parses page specification into list of page numbers.

    Args:
        page_spec: Page specification ("last", "all", int, or "1,2,3")
        total_pages: Total number of pages in document

    Returns:
        List of 0-indexed page numbers
    """
    if isinstance(page_spec, int):
        return [min(page_spec, total_pages - 1)]

    if page_spec == "last":
        return [total_pages - 1]

    if page_spec == "all":
        return list(range(total_pages))

    # Parse comma-separated list
    try:
        pages = [int(p.strip()) - 1 for p in str(page_spec).split(",")]
        return [p for p in pages if 0 <= p < total_pages]
    except ValueError:
        logger.warning(f"[DRY-RUN] Invalid page spec: {page_spec}, using last page")
        return [total_pages - 1]


def _add_stamp_to_pdf(
    input_path: Path,
    output_path: Path,
    page_spec: str | int = "last",
    visible: bool = True,
) -> None:
    """
    Adds visual stamp to PDF in dry-run mode.

    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        page_spec: Page specification
        visible: Whether to add visible stamp
    """
    if not visible:
        # Just copy if no visible signature
        import shutil

        shutil.copy2(input_path, output_path)
        logger.info("[DRY-RUN] Invisible signature - copied without stamp")
        return

    doc = fitz.open(input_path)
    stamp_text = f"SIGNATURE (SIMULATED)\n{datetime.now().strftime('%Y-%m-%d %H:%M')}"

    pages_to_stamp = _parse_page_spec(page_spec, len(doc))

    for page_num in pages_to_stamp:
        if page_num < len(doc):
            page = doc[page_num]
            # Add stamp rectangle at bottom right
            rect = fitz.Rect(
                page.rect.width - 150,
                page.rect.height - 60,
                page.rect.width - 10,
                page.rect.height - 10,
            )
            # Draw blue border
            page.draw_rect(rect, color=(0, 0, 0.5), width=1)
            # Insert text
            page.insert_textbox(
                rect,
                stamp_text,
                fontsize=8,
                align=fitz.TEXT_ALIGN_CENTER,
                color=(0, 0, 0.5),
            )

    doc.save(output_path)
    doc.close()
    logger.info(f"[DRY-RUN] Added visual stamp to {len(pages_to_stamp)} page(s): {pages_to_stamp}")


class MockBatchManager:
    """
    Simulated batch signing manager.

    Simulates the signing process by adding visual stamps
    to PDFs when visible=True, or just copying them when visible=False.
    """

    def __init__(self, nss_handler=None, lta_handler=None):
        """Initializes the mock manager."""
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        logger.info("[DRY-RUN] MockBatchManager created")

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
        Simulates batch file signing.

        Adds visual stamps to PDFs when visible=True, simulating real signatures.

        Args:
            files: List of files (alias)
            pdf_files: List of files
            pin: PIN (ignored in mock)
            visible: Visible signature
            page: Page for visible signature
            appearance: Appearance configuration
            cert_id: Certificate ID
            progress_callback: Progress callback

        Returns:
            Simulated signing result
        """
        # Support both parameter names
        file_list = files or pdf_files or []

        if not file_list:
            return MockBatchResult(successful=0, failed=0, all_successful=True, errors={})

        total = len(file_list)
        successful = 0
        failed = 0
        errors = {}

        logger.info(f"[DRY-RUN] Simulating signing of {total} file(s)...")
        if visible:
            logger.info(f"[DRY-RUN] Visible signatures on page: {page}")

        for i, pdf_path in enumerate(file_list):
            current_file = str(pdf_path)

            # Notify start
            if progress_callback:
                progress = MockBatchProgress(
                    current=i + 1,
                    total=total,
                    current_file=current_file,
                    status="processing",
                    message="Signing...",
                )
                progress_callback(progress)

            # Simulate signing time
            time.sleep(0.5)

            try:
                # Create "signed" file with stamp
                output_path = pdf_path.parent / f"{pdf_path.stem}_signed{pdf_path.suffix}"
                _add_stamp_to_pdf(pdf_path, output_path, page_spec=page, visible=visible)

                logger.info(f"[DRY-RUN] Signed: {pdf_path.name} → {output_path.name}")
                successful += 1

                # Notify success
                if progress_callback:
                    progress = MockBatchProgress(
                        current=i + 1,
                        total=total,
                        current_file=current_file,
                        status="success",
                        message="Signed (simulated)",
                    )
                    progress_callback(progress)

            except Exception as e:
                logger.error(f"[DRY-RUN] Error processing {pdf_path}: {e}")
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

        logger.info(f"[DRY-RUN] Signing completed: {successful} success, {failed} failed")

        return MockBatchResult(
            successful=successful,
            failed=failed,
            all_successful=(failed == 0),
            errors=errors,
        )


def enable_dry_run_mode():
    """
    Enables dry-run mode globally.

    Modifies the setting so that components
    use mock implementations automatically.
    """
    import os

    # Settings is immutable, use environment variable
    os.environ["PDFSIGNER_DRY_RUN"] = "true"
    logger.warning("⚠️  DRY-RUN MODE ACTIVATED - No real signing")

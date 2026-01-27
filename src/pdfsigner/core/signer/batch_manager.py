"""
batch_manager.py - Batch signing manager

Author: Homero Thompson del Lago del Terror

Orchestrates signing of multiple PDFs, handling
progress, partial errors, and reports.
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
    """Batch progress state."""

    total: int
    completed: int
    failed: int
    current_file: str | None

    @property
    def pending(self) -> int:
        """Pending files."""
        return self.total - self.completed - self.failed

    @property
    def percentage(self) -> float:
        """Completion percentage."""
        if self.total == 0:
            return 100.0
        return (self.completed + self.failed) / self.total * 100


@dataclass
class BatchResult:
    """Batch signing result."""

    total: int
    successful: int
    failed: int
    results: list[SigningResult] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def all_successful(self) -> bool:
        """True if all files were signed successfully."""
        return self.failed == 0

    @property
    def duration_seconds(self) -> float | None:
        """Total duration in seconds."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def get_failed_files(self) -> list[tuple[Path, str]]:
        """List of failed files with their errors."""
        return [(r.input_path, r.error or "Unknown error") for r in self.results if not r.success]

    def get_successful_files(self) -> list[Path]:
        """List of successfully signed files."""
        return [r.output_path for r in self.results if r.success and r.output_path]


# Type for progress callback
ProgressCallback = Callable[[BatchProgress], None]


class BatchManager:
    """
    Batch signing manager.

    Coordinates signing of multiple PDFs with:
    - Partial error handling (continues with other files)
    - Progress callbacks to update UI
    - Cancellation support
    """

    def __init__(
        self,
        nss_handler: NSSHandler,
        lta_handler: LTAHandler | None = None,
    ):
        """
        Initializes the batch manager.

        Args:
            nss_handler: Authenticated NSS handler
            lta_handler: LTA handler for timestamp
        """
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        self._cancelled = False
        self._signer: PDFSigner | None = None

    def _get_signer(self) -> PDFSigner:
        """Gets or creates the signer."""
        if self._signer is None:
            self._signer = PDFSigner(self.nss_handler, self.lta_handler)
        return self._signer

    def cancel(self) -> None:
        """Requests cancellation of the current batch."""
        self._cancelled = True
        logger.info("Cancellation requested")

    def reset(self) -> None:
        """Resets the cancellation state."""
        self._cancelled = False

    def sign_batch(
        self,
        pdf_files: list[Path],
        appearance: SignatureAppearance | None = None,
        cert_id: bytes | None = None,
        progress_callback: ProgressCallback | None = None,
        template_override: str | None = None,
        reason: str | None = None,
        location: str | None = None,
        contact_info: str | None = None,
    ) -> BatchResult:
        """
        Signs a batch of PDFs.

        Args:
            pdf_files: List of paths to PDFs
            appearance: Appearance configuration
            cert_id: Certificate ID to use
            progress_callback: Callback to update progress
            template_override: Template name to use instead of settings default
            reason: Signature reason (e.g., "I approve this document")
            location: Signature location (e.g., "Buenos Aires, Argentina")
            contact_info: Contact information (e.g., "email@company.com")

        Returns:
            Batch result with statistics and details
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
        logger.info(f"Starting signing of {total} file(s)")

        for i, pdf_path in enumerate(pdf_files):
            # Check for cancellation
            if self._cancelled:
                logger.info("Signing cancelled by user")
                break

            # Notify progress
            if progress_callback:
                progress = BatchProgress(
                    total=total,
                    completed=result.successful,
                    failed=result.failed,
                    current_file=pdf_path.name,
                )
                progress_callback(progress)

            # Sign file
            signing_result = signer.sign_pdf(
                input_path=pdf_path,
                appearance=appearance,
                cert_id=cert_id,
                template_override=template_override,
                reason=reason,
                location=location,
                contact_info=contact_info,
            )

            result.results.append(signing_result)

            if signing_result.success:
                result.successful += 1
            else:
                result.failed += 1
                logger.warning(f"Error in {pdf_path.name}: {signing_result.error}")

        result.finished_at = datetime.now()

        # Notify final progress
        if progress_callback:
            progress = BatchProgress(
                total=total,
                completed=result.successful,
                failed=result.failed,
                current_file=None,
            )
            progress_callback(progress)

        # Log summary
        duration = result.duration_seconds or 0
        logger.info(
            f"Batch completed: {result.successful}/{total} successful, "
            f"{result.failed} failed, {duration:.1f}s"
        )

        return result


def create_batch_manager(
    nss_handler: NSSHandler,
    lta_handler: LTAHandler | None = None,
) -> BatchManager:
    """
    Factory to create BatchManager.

    Args:
        nss_handler: Authenticated NSS handler
        lta_handler: Optional LTA handler

    Returns:
        Configured BatchManager
    """
    return BatchManager(nss_handler, lta_handler)

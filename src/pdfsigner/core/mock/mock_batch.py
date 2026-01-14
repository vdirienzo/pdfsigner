"""
mock_batch.py - Mock batch signing manager for dry-run mode

Author: Homero Thompson del Lago del Terror

Simulates batch signing with visual stamp simulation.
Uses stamp_simulator for visual stamp generation.
"""

import time
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf


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
        position: str = "bottom_right",
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
            position: Position preference (bottom_right, top_left, etc.)
            appearance: Appearance configuration (overrides visible/page/position)
            cert_id: Certificate ID
            progress_callback: Progress callback

        Returns:
            Simulated signing result
        """
        # Support both parameter names
        file_list = files or pdf_files or []

        if not file_list:
            return MockBatchResult(successful=0, failed=0, all_successful=True, errors={})

        # Extract settings from appearance if provided
        if appearance is not None:
            visible = getattr(appearance, "visible", visible)
            page = getattr(appearance, "page", page)
            pos_pref = getattr(appearance, "position_preference", None)
            if pos_pref is not None:
                position = pos_pref.value if hasattr(pos_pref, "value") else str(pos_pref)

        total = len(file_list)
        successful = 0
        failed = 0
        errors = {}

        logger.info(f"[DRY-RUN] Simulating signing of {total} file(s)...")
        if visible:
            logger.info(f"[DRY-RUN] Visible signatures on page: {page}, position: {position}")

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
                add_stamp_to_pdf(
                    pdf_path,
                    output_path,
                    page_spec=page,
                    visible=visible,
                    position=position,
                )

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

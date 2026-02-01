"""
Signing service for background PDF signing operations.

Manages signing jobs, coordinates with PDFSigner, and handles file lifecycle.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import magic
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.schemas.sign import SignRequest
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.pdf_signer import PDFSigner, SignatureAppearance
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFCorruptedError, PDFProtectedError


@dataclass
class SigningJob:
    """Represents a signing job in the system."""

    job_id: str
    status: Literal["pending", "processing", "completed", "failed"]
    filename: str
    input_path: Path
    output_path: Path | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None
    pades_level: str | None = None
    user_id: str | None = None  # Track which user owns this job


class SigningService:
    """
    Service for managing PDF signing operations.

    Handles job lifecycle, background signing, and file cleanup.
    Uses in-memory storage for MVP (replace with Redis/DB for production).
    """

    def __init__(self):
        """Initialize signing service with job storage."""
        self._jobs: dict[str, SigningJob] = {}
        self._settings = get_api_settings()

    def create_job(
        self,
        filename: str,
        input_path: Path,
        user_id: str,
    ) -> str:
        """
        Create a new signing job.

        Args:
            filename: Original filename
            input_path: Path to uploaded PDF
            user_id: User identifier who owns this job

        Returns:
            Job ID (UUID)
        """
        job_id = str(uuid.uuid4())
        output_path = self._generate_output_path(input_path)

        job = SigningJob(
            job_id=job_id,
            status="pending",
            filename=filename,
            input_path=input_path,
            output_path=output_path,
            user_id=user_id,
        )

        self._jobs[job_id] = job
        logger.info(f"Created signing job {job_id} for {filename}")
        return job_id

    def get_job(self, job_id: str) -> SigningJob | None:
        """
        Retrieve job by ID.

        Args:
            job_id: Job identifier

        Returns:
            SigningJob if found, None otherwise
        """
        return self._jobs.get(job_id)

    def verify_job_ownership(self, job_id: str, user_id: str) -> bool:
        """
        Verify user owns the job.

        Args:
            job_id: Job identifier
            user_id: User identifier

        Returns:
            True if user owns the job
        """
        job = self._jobs.get(job_id)
        if not job:
            return False
        return job.user_id == user_id

    async def sign_pdf_background(
        self,
        job_id: str,
        request: SignRequest,
        nss_handler: NSSHandler,
        lta_handler: LTAHandler | None = None,
    ) -> None:
        """
        Background task to sign PDF.

        Updates job status as it progresses. Handles errors gracefully.

        Args:
            job_id: Job identifier
            request: Signing parameters
            nss_handler: Authenticated NSS handler
            lta_handler: LTA handler for timestamping
        """
        job = self._jobs.get(job_id)
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        try:
            job.status = "processing"
            logger.info(f"Starting signing job {job_id}")

            # Create PDFSigner
            signer = PDFSigner(nss_handler=nss_handler, lta_handler=lta_handler)

            # Build appearance from request
            appearance = SignatureAppearance(
                visible=request.visible_signature,
                page=request.signature_page,
            )

            # Sign the PDF
            result = signer.sign_pdf(
                input_path=job.input_path,
                output_path=job.output_path,
                appearance=appearance,
                reason=request.reason,
                location=request.location,
                contact_info=request.contact_info,
                embed_ltv=request.embed_ltv,
            )

            if result.success:
                job.status = "completed"
                job.completed_at = datetime.now(UTC)
                job.output_path = result.output_path
                job.pades_level = self._determine_pades_level(request)
                logger.info(f"Job {job_id} completed successfully")
            else:
                job.status = "failed"
                job.completed_at = datetime.now(UTC)
                job.error = result.error or "Unknown signing error"
                logger.error(f"Job {job_id} failed: {job.error}")

        except (PDFCorruptedError, PDFProtectedError) as e:
            job.status = "failed"
            job.completed_at = datetime.now(UTC)
            job.error = str(e)
            logger.error(f"Job {job_id} failed with PDF error: {e}")

        except Exception as e:
            job.status = "failed"
            job.completed_at = datetime.now(UTC)
            job.error = f"Signing error: {str(e)}"
            logger.exception(f"Job {job_id} failed with unexpected error")

        finally:
            # Clean up input file (keep output for download)
            self._cleanup_input_file(job)

    def cleanup_job_files(self, job_id: str) -> None:
        """
        Clean up all files associated with a job.

        Args:
            job_id: Job identifier
        """
        job = self._jobs.get(job_id)
        if not job:
            return

        self._cleanup_input_file(job)
        self._cleanup_output_file(job)

    def cleanup_old_jobs(self, max_age_hours: int | None = None) -> int:
        """
        Clean up jobs older than max_age_hours.

        Args:
            max_age_hours: Maximum age in hours (default from settings)

        Returns:
            Number of jobs cleaned up
        """
        max_age = max_age_hours or self._settings.temp_file_retention_hours
        cutoff_time = datetime.now(UTC).timestamp() - (max_age * 3600)
        cleaned = 0

        job_ids_to_remove = []
        for job_id, job in self._jobs.items():
            if job.created_at.timestamp() < cutoff_time:
                self.cleanup_job_files(job_id)
                job_ids_to_remove.append(job_id)
                cleaned += 1

        for job_id in job_ids_to_remove:
            del self._jobs[job_id]

        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old signing jobs")

        return cleaned

    def _generate_output_path(self, input_path: Path) -> Path:
        """
        Generate output path for signed PDF.

        Args:
            input_path: Input PDF path

        Returns:
            Output path with _signed suffix
        """
        return input_path.with_stem(f"{input_path.stem}_signed")

    def _determine_pades_level(self, request: SignRequest) -> str:
        """
        Determine PAdES conformance level from request.

        Args:
            request: Signing request

        Returns:
            PAdES level string (B-B, B-T, B-LT, B-LTA)
        """
        # B-LTA: Archive timestamp (requires LTV)
        if request.add_archive_ts:
            return "B-LTA"

        # B-LT: Long-term validation with DSS
        if request.embed_ltv:
            return "B-LT"

        # B-T: Basic signature with timestamp
        if request.tsa_url:
            return "B-T"

        # B-B: Basic signature
        return "B-B"

    def _cleanup_input_file(self, job: SigningJob) -> None:
        """
        Remove input file if it exists.

        Args:
            job: Signing job
        """
        if job.input_path and job.input_path.exists():
            try:
                job.input_path.unlink()
                logger.debug(f"Cleaned up input file: {job.input_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up input file: {e}")

    def _cleanup_output_file(self, job: SigningJob) -> None:
        """
        Remove output file if it exists.

        Args:
            job: Signing job
        """
        if job.output_path and job.output_path.exists():
            try:
                job.output_path.unlink()
                logger.debug(f"Cleaned up output file: {job.output_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up output file: {e}")

    @staticmethod
    def validate_pdf_file(file_content: bytes, filename: str) -> None:
        """
        Validate uploaded file is a valid PDF.

        Uses python-magic for robust MIME type detection to prevent
        file extension spoofing attacks.

        Args:
            file_content: File content bytes
            filename: Original filename

        Raises:
            ValueError: If file is not a valid PDF
        """
        # Check file extension
        if not filename.lower().endswith(".pdf"):
            raise ValueError("File must have .pdf extension")

        # Check minimum size (empty PDFs are ~100 bytes)
        if len(file_content) < 100:
            raise ValueError("File is too small to be a valid PDF")

        # Check PDF magic bytes (basic check)
        if not file_content.startswith(b"%PDF-"):
            raise ValueError("File is not a valid PDF (invalid magic bytes)")

        # Validate MIME type using python-magic (deep inspection)
        try:
            mime_type = magic.from_buffer(file_content, mime=True)
            if mime_type != "application/pdf":
                raise ValueError(f"File is not a valid PDF (detected MIME type: {mime_type})")
        except Exception as e:
            # If magic fails, log warning but don't fail (fallback to basic check)
            logger.warning(f"python-magic validation failed: {e}")
            # Basic check already passed above, so we can continue


# Global service instance (singleton for MVP)
_signing_service: SigningService | None = None


def get_signing_service() -> SigningService:
    """Get signing service instance (singleton)."""
    global _signing_service
    if _signing_service is None:
        _signing_service = SigningService()
    return _signing_service

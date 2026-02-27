"""
Sign endpoints for PDF signing operations.

Provides REST API for asynchronous PDF signing with job tracking.
"""

import asyncio
import os
import tempfile
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.sign import SignJobStatus, SignRequest, SignResponse
from pdfsigner.api.services.signing_service import SigningService, get_signing_service
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/sign", tags=["signing"])


def get_nss_handler() -> NSSHandler:
    """
    Dependency to get authenticated NSS handler.

    In production, this would authenticate with actual token/PIN.
    For MVP, returns a handler configured from settings.

    Returns:
        Authenticated NSSHandler

    Raises:
        HTTPException: 500 if NSS handler initialization fails
    """
    from pdfsigner.config.settings import get_settings

    settings = get_settings()

    try:
        # In production, you'd pass actual PIN from secure storage
        # For now, using NSS handler without authentication (dry-run mode)
        handler = NSSHandler(nss_db_path=settings.nss_db_path)
        return handler
    except Exception as e:
        logger.error(f"Failed to initialize NSS handler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signing service unavailable (NSS initialization failed)",
        ) from e


def get_lta_handler() -> LTAHandler | None:
    """
    Dependency to get LTA handler for timestamping.

    Returns:
        LTAHandler if TSA is configured, None otherwise
    """
    from pdfsigner.core.signer.lta_handler import create_lta_handler_from_settings

    try:
        return create_lta_handler_from_settings()
    except Exception as e:
        logger.warning(f"Failed to initialize LTA handler: {e}")
        return None


@router.post("/", response_model=SignResponse)
async def sign_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="PDF file to sign"),
    reason: str | None = Form(None, max_length=500),
    location: str | None = Form(None, max_length=500),
    contact_info: str | None = Form(None, max_length=500),
    visible_signature: bool = False,
    signature_page: str = "last",
    tsa_url: str | None = Form(None, max_length=2048),
    embed_ltv: bool = True,
    add_archive_ts: bool = False,
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.SIGN)),
    signing_service: SigningService = Depends(get_signing_service),
    nss_handler: NSSHandler = Depends(get_nss_handler),
    lta_handler: LTAHandler | None = Depends(get_lta_handler),
) -> SignResponse:
    """
    Sign a PDF document asynchronously.

    Accepts a PDF file and signing parameters, creates a background job,
    and returns a job ID for tracking. Use GET /sign/{job_id}/status to
    check progress and GET /sign/{job_id}/download to retrieve the signed PDF.

    **Authentication:** Requires JWT token or API key

    **Example:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/sign" \\
         -H "X-API-Key: your-api-key" \\
         -F "file=@document.pdf" \\
         -F "reason=Approval" \\
         -F "location=New York, NY" \\
         -F "visible_signature=true"
    ```

    Args:
        background_tasks: FastAPI background tasks
        file: PDF file to sign (multipart/form-data)
        reason: Reason for signing (e.g., "I approve this document")
        location: Geographic location (e.g., "New York, NY")
        contact_info: Contact information (e.g., "email@company.com")
        visible_signature: Whether to add visible signature stamp
        signature_page: Page for signature (first/last/all/number)
        tsa_url: Custom TSA URL (uses default if not provided)
        embed_ltv: Embed Long-Term Validation data (DSS)
        add_archive_ts: Add archive timestamp for B-LTA level
        current_user: Authenticated user
        signing_service: Signing service instance
        nss_handler: NSS handler for token operations
        lta_handler: LTA handler for timestamping

    Returns:
        SignResponse with job_id and status

    Raises:
        HTTPException: 400 if file is invalid or too large
        HTTPException: 413 if file exceeds size limit
        HTTPException: 500 if signing service fails
    """
    settings = get_api_settings()

    # Validate file type
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    # Sanitize filename to prevent Path Traversal
    try:
        safe_filename_str = sanitize_filename(file.filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filename: {e}",
        ) from e

    if not safe_filename_str.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are accepted",
        )

    # Stream file to temp directory in chunks to avoid loading entire PDF in memory
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    temp_dir = settings.temp_dir
    temp_dir.mkdir(parents=True, exist_ok=True)

    temp_fd, temp_path_str = tempfile.mkstemp(
        suffix=".pdf",
        prefix=f"upload_{current_user.username}_",
        dir=str(temp_dir),
    )
    temp_path = Path(temp_path_str)

    try:
        total_size = 0
        with open(temp_fd, "wb") as f:
            while chunk := await file.read(8192):
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File size exceeds maximum ({settings.max_upload_size_mb}MB)",
                    )
                f.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        logger.debug(f"Saved uploaded file to {temp_path} ({total_size} bytes)")

    except HTTPException:
        os.unlink(temp_path_str)
        raise
    except Exception as e:
        os.unlink(temp_path_str)
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file",
        ) from e

    # Validate PDF content from temp file
    try:
        file_content = await asyncio.to_thread(temp_path.read_bytes)
        SigningService.validate_pdf_file(file_content, safe_filename_str)
        del file_content  # Free memory after validation
    except ValueError as e:
        os.unlink(temp_path_str)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    # Create signing request
    sign_request = SignRequest(
        reason=reason,
        location=location,
        contact_info=contact_info,
        visible_signature=visible_signature,
        signature_page=signature_page,
        tsa_url=tsa_url,
        embed_ltv=embed_ltv,
        add_archive_ts=add_archive_ts,
    )

    # Create job
    try:
        job_id = signing_service.create_job(
            filename=safe_filename_str,
            input_path=temp_path,
            user_id=current_user.username,
        )

        # Add background task
        background_tasks.add_task(
            signing_service.sign_pdf_background,
            job_id=job_id,
            request=sign_request,
            nss_handler=nss_handler,
            lta_handler=lta_handler,
        )

        logger.info(f"Created signing job {job_id} for user {current_user.username}")

        return SignResponse(
            job_id=job_id,
            status="pending",
            message="Signing job created successfully",
            download_url=None,
        )

    except Exception as e:
        logger.error(f"Failed to create signing job: {e}")
        # Clean up temp file on error
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create signing job",
        ) from e


@router.get("/{job_id}/status", response_model=SignJobStatus)
async def get_sign_status(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VIEW)),
    signing_service: SigningService = Depends(get_signing_service),
) -> SignJobStatus:
    """
    Get status of a signing job.

    Returns detailed information about a signing job including status,
    filename, timestamps, and download URL (when completed).

    **Authentication:** Requires JWT token or API key

    **Example:**
    ```bash
    curl -X GET "http://localhost:8000/api/v1/sign/{job_id}/status" \\
         -H "X-API-Key: your-api-key"
    ```

    Args:
        job_id: Job identifier (UUID)
        current_user: Authenticated user
        signing_service: Signing service instance

    Returns:
        SignJobStatus with detailed job information

    Raises:
        HTTPException: 404 if job not found
        HTTPException: 403 if user doesn't own the job
    """
    # Retrieve job
    job = signing_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    # Verify ownership
    if not signing_service.verify_job_ownership(job_id, current_user.username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this job",
        )

    # Build download URL if completed
    download_url = None
    if job.status == "completed" and job.output_path:
        download_url = f"/api/v1/sign/{job_id}/download"

    return SignJobStatus(
        job_id=job.job_id,
        status=job.status,
        filename=job.filename,
        created_at=job.created_at.isoformat(),
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        error=job.error,
        download_url=download_url,
        pades_level=job.pades_level,
    )


@router.get("/{job_id}/download")
async def download_signed_pdf(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VIEW)),
    signing_service: SigningService = Depends(get_signing_service),
) -> FileResponse:
    """
    Download signed PDF.

    Returns the signed PDF file for a completed signing job.
    After download, the file is retained according to retention policy.

    **Authentication:** Requires JWT token or API key

    **Example:**
    ```bash
    curl -X GET "http://localhost:8000/api/v1/sign/{job_id}/download" \\
         -H "X-API-Key: your-api-key" \\
         -o signed_document.pdf
    ```

    Args:
        job_id: Job identifier (UUID)
        current_user: Authenticated user
        signing_service: Signing service instance

    Returns:
        FileResponse with signed PDF

    Raises:
        HTTPException: 404 if job not found or not completed
        HTTPException: 403 if user doesn't own the job
        HTTPException: 410 if signed file no longer available
    """
    # Retrieve job
    job = signing_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    # Verify ownership
    if not signing_service.verify_job_ownership(job_id, current_user.username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this job",
        )

    # Check job status
    if job.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job is not completed (status: {job.status})",
        )

    # Check output file exists
    if not job.output_path or not job.output_path.exists():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Signed file is no longer available (may have expired)",
        )

    # Return file
    logger.info(f"User {current_user.username} downloading signed PDF for job {job_id}")

    return FileResponse(
        path=str(job.output_path),
        media_type="application/pdf",
        filename=job.filename.replace(".pdf", "_signed.pdf"),
    )


# Health check endpoint for signing service
@router.get("/health", include_in_schema=False)
async def signing_health() -> dict[str, str]:
    """
    Health check for signing service.

    Returns:
        Status information
    """
    return {"status": "healthy", "service": "signing"}

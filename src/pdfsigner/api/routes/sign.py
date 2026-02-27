"""
Sign endpoints for PDF signing operations.

Provides REST API for asynchronous PDF signing with job tracking.
"""

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

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.sign import SignJobStatus, SignRequest, SignResponse
from pdfsigner.api.services.signing_service import SigningService, get_signing_service
from pdfsigner.api.services.upload_handler import validate_and_save_upload
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/sign", tags=["signing"])


def get_nss_handler() -> NSSHandler:
    """Dependency to get authenticated NSS handler."""
    from pdfsigner.config.settings import get_settings

    settings = get_settings()
    try:
        handler = NSSHandler(nss_db_path=settings.nss_db_path)
        return handler
    except Exception as e:
        logger.error(f"Failed to initialize NSS handler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signing service unavailable (NSS initialization failed)",
        ) from e


def get_lta_handler() -> LTAHandler | None:
    """Dependency to get LTA handler for timestamping."""
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
    and returns a job ID for tracking.
    """
    # Validate and save uploaded file
    safe_filename, temp_path = await validate_and_save_upload(file, current_user.username)

    # Build signing request
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

    # Create job and schedule background signing
    try:
        job_id = signing_service.create_job(
            filename=safe_filename,
            input_path=temp_path,
            user_id=current_user.username,
        )

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
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create signing job",
        ) from e


def _get_job_or_404(
    signing_service: SigningService, job_id: str, username: str
) -> "SigningService":
    """Retrieve job and verify ownership, raising HTTP errors."""

    job = signing_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    if not signing_service.verify_job_ownership(job_id, username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this job",
        )

    return job


@router.get("/{job_id}/status", response_model=SignJobStatus)
async def get_sign_status(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VIEW)),
    signing_service: SigningService = Depends(get_signing_service),
) -> SignJobStatus:
    """Get status of a signing job."""
    job = _get_job_or_404(signing_service, job_id, current_user.username)

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
    """Download signed PDF for a completed signing job."""
    job = _get_job_or_404(signing_service, job_id, current_user.username)

    if job.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job is not completed (status: {job.status})",
        )

    if not job.output_path or not job.output_path.exists():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Signed file is no longer available (may have expired)",
        )

    logger.info(f"User {current_user.username} downloading signed PDF for job {job_id}")

    return FileResponse(
        path=str(job.output_path),
        media_type="application/pdf",
        filename=job.filename.replace(".pdf", "_signed.pdf"),
    )


@router.get("/health", include_in_schema=False)
async def signing_health() -> dict[str, str]:
    """Health check for signing service."""
    return {"status": "healthy", "service": "signing"}

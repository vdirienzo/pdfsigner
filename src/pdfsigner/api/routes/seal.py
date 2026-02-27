"""Seal endpoints for electronic seal operations (eIDAS Article 35-40).

Provides REST API for asynchronous PDF sealing with job tracking.
Electronic seals are for organizations (legal persons), not individuals.
"""

import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.seal import (
    OrganizationInfoSchema,
    SealJobStatus,
    SealResponse,
    SealValidationResponse,
)
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.eidas.seal_manager import (
    OrganizationInfo,
    SealAppearance,
    SealConfig,
    SealManager,
    SealType,
    get_seal_manager,
)
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/seal", tags=["sealing"])

# In-memory job storage (production would use database)
_seal_jobs: dict[str, dict] = {}
_seal_job_timestamps: dict[str, float] = {}
_seal_lock = threading.Lock()
_MAX_SEAL_JOBS = 1000
_SEAL_JOB_TTL_SECONDS = 86400  # 24 hours


def _cleanup_seal_jobs() -> None:
    """Remove expired seal job entries."""
    now = time.time()
    with _seal_lock:
        expired = [k for k, t in _seal_job_timestamps.items() if now - t > _SEAL_JOB_TTL_SECONDS]
        for k in expired:
            _seal_jobs.pop(k, None)
            _seal_job_timestamps.pop(k, None)


def _pydantic_to_org_info(schema: OrganizationInfoSchema) -> OrganizationInfo:
    """Convert Pydantic schema to dataclass.

    Args:
        schema: Pydantic organization info schema

    Returns:
        OrganizationInfo dataclass
    """
    return OrganizationInfo(
        name=schema.name,
        country=schema.country,
        organization_id=schema.organization_id,
        department=schema.department,
        address=schema.address,
        email=schema.email,
        website=schema.website,
    )


def _org_info_to_pydantic(org: OrganizationInfo) -> OrganizationInfoSchema:
    """Convert dataclass to Pydantic schema.

    Args:
        org: OrganizationInfo dataclass

    Returns:
        Pydantic organization info schema
    """
    # Default empty country to "XX" (unknown) to satisfy schema regex ^[A-Z]{2}$
    country = org.country.upper() if org.country and len(org.country) == 2 else "XX"
    return OrganizationInfoSchema(
        name=org.name or "Unknown",
        country=country,
        organization_id=org.organization_id,
        department=org.department,
        address=org.address,
        email=org.email,
        website=org.website,
    )


async def _process_seal_job(
    job_id: str, pdf_path: Path, seal_config: SealConfig, seal_manager: SealManager
) -> None:
    """Background task to process seal job.

    Args:
        job_id: Job identifier
        pdf_path: Path to PDF file
        seal_config: Seal configuration
        seal_manager: SealManager instance
    """
    try:
        logger.info(f"Processing seal job {job_id}")
        with _seal_lock:
            _seal_jobs[job_id]["status"] = "processing"

        # Create seal
        result = seal_manager.create_seal(pdf_path=pdf_path, config=seal_config, dry_run=False)

        if result.success:
            with _seal_lock:
                _seal_jobs[job_id].update(
                    {
                        "status": "completed",
                        "completed_at": datetime.now(UTC).isoformat(),
                        "output_path": str(result.output_path),
                        "signature_id": result.signature_id,
                        "download_url": f"/api/v1/seal/{job_id}/download",
                    }
                )
            logger.info(f"Seal job {job_id} completed successfully")
        else:
            with _seal_lock:
                _seal_jobs[job_id].update(
                    {
                        "status": "failed",
                        "completed_at": datetime.now(UTC).isoformat(),
                        "error": "; ".join(result.errors),
                    }
                )
            logger.error(f"Seal job {job_id} failed: {result.errors}")

    except Exception as e:
        logger.exception(f"Error processing seal job {job_id}: {e}")
        with _seal_lock:
            _seal_jobs[job_id].update(
                {
                    "status": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": str(e),
                }
            )


@router.post("/", response_model=SealResponse)
async def seal_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="PDF file to seal"),
    organization_name: str = "Acme Corporation",
    organization_country: str = "DE",
    organization_id: str = "",
    seal_type: str = "advanced",
    appearance: str = "stamp",
    reason: str = "Organization seal",
    location: str = "",
    page: int = 1,
    include_timestamp: bool = True,
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.SIGN)),
    seal_manager: SealManager = Depends(get_seal_manager),
) -> SealResponse:
    """Create electronic seal on PDF asynchronously.

    Accepts a PDF file and seal parameters, creates a background job,
    and returns a job ID for tracking. Use GET /seal/{job_id}/status to
    check progress and GET /seal/{job_id}/download to retrieve the sealed PDF.

    **Authentication:** Requires JWT token or API key

    **Example:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/seal" \\
         -H "X-API-Key: your-api-key" \\
         -F "file=@document.pdf" \\
         -F "organization_name=Acme Corp" \\
         -F "organization_country=DE" \\
         -F "seal_type=advanced" \\
         -F "appearance=stamp"
    ```

    Args:
        background_tasks: FastAPI background tasks
        file: PDF file to seal (multipart/form-data)
        organization_name: Organization legal name
        organization_country: ISO 3166-1 alpha-2 country code
        organization_id: Organization identifier (VAT, LEI, etc.)
        seal_type: Type of seal (basic, advanced, qualified)
        appearance: Visual appearance (invisible, stamp, banner, logo)
        reason: Reason for sealing
        location: Geographic location
        page: Page number for seal (1-indexed, -1 for last)
        include_timestamp: Include trusted timestamp
        current_user: Authenticated user
        seal_manager: SealManager instance

    Returns:
        SealResponse with job_id and status

    Raises:
        HTTPException: 400 if file is invalid or too large
        HTTPException: 413 if file exceeds size limit
    """
    settings = get_api_settings()

    # Validate file
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are supported",
        )

    # Sanitize filename to prevent Path Traversal
    try:
        safe_filename_str = sanitize_filename(file.filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filename: {e}",
        ) from e
    # Stream file to temp directory in chunks to avoid loading entire PDF in memory
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_api_seals"
    temp_dir.mkdir(exist_ok=True)

    job_id = f"seal_{uuid.uuid4().hex[:12]}"
    input_path = temp_dir / f"{job_id}_input.pdf"

    try:
        total_size = 0
        with open(input_path, "wb") as f:
            while chunk := await file.read(8192):
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File too large (max {settings.max_upload_size_mb}MB)",
                    )
                f.write(chunk)
    except HTTPException:
        if input_path.exists():
            input_path.unlink()
        raise

    # Create seal configuration
    org_info = OrganizationInfo(
        name=organization_name,
        country=organization_country.upper(),
        organization_id=organization_id,
    )

    try:
        seal_type_enum = SealType(seal_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid seal_type: {seal_type}. Must be one of: {[e.value for e in SealType]}",
        )

    try:
        appearance_enum = SealAppearance(appearance)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid appearance: {appearance}. "
            f"Must be one of: {[e.value for e in SealAppearance]}",
        )

    seal_config = SealConfig(
        organization=org_info,
        seal_type=seal_type_enum,
        appearance=appearance_enum,
        reason=reason,
        location=location,
        page=page,
        include_timestamp=include_timestamp,
        tsa_url=getattr(settings, "default_tsa_url", "") or "",
    )

    # Cleanup old entries before adding new ones
    _cleanup_seal_jobs()
    with _seal_lock:
        if len(_seal_jobs) >= _MAX_SEAL_JOBS:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Too many pending seal jobs. Please try again later.",
            )

        # Store job info
        _seal_job_timestamps[job_id] = time.time()
        _seal_jobs[job_id] = {
            "job_id": job_id,
            "user_id": current_user.id,
            "status": "pending",
            "filename": file.filename,
            "organization": organization_name,
            "seal_type": seal_type,
            "created_at": datetime.now(UTC).isoformat(),
            "input_path": str(input_path),
            "completed_at": None,
            "error": None,
            "download_url": None,
            "signature_id": None,
        }

    # Start background sealing task
    background_tasks.add_task(_process_seal_job, job_id, input_path, seal_config, seal_manager)

    logger.info(f"Seal job {job_id} created for {safe_filename_str}")

    return SealResponse(
        job_id=job_id,
        status="pending",
        organization=organization_name,
        seal_type=seal_type,
        message=f"Seal job created for {safe_filename_str}",
        download_url=f"/api/v1/seal/{job_id}/download",
    )


@router.get("/{job_id}/status", response_model=SealJobStatus)
async def get_seal_status(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
) -> SealJobStatus:
    """Get status of a sealing job.

    Args:
        job_id: Job identifier
        current_user: Authenticated user

    Returns:
        SealJobStatus with job details

    Raises:
        HTTPException: 404 if job not found
    """
    with _seal_lock:
        if job_id not in _seal_jobs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found",
            )

        if _seal_jobs[job_id].get("user_id") != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found",
            )

        job = _seal_jobs[job_id].copy()

    return SealJobStatus(
        job_id=job["job_id"],
        status=job["status"],
        filename=job["filename"],
        organization=job["organization"],
        seal_type=job["seal_type"],
        created_at=job["created_at"],
        completed_at=job["completed_at"],
        error=job["error"],
        download_url=job["download_url"],
        signature_id=job["signature_id"],
    )


@router.get("/{job_id}/download")
async def download_sealed_pdf(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
) -> FileResponse:
    """Download sealed PDF.

    Args:
        job_id: Job identifier
        current_user: Authenticated user

    Returns:
        FileResponse with sealed PDF

    Raises:
        HTTPException: 404 if job not found or not completed
        HTTPException: 400 if job failed
    """
    with _seal_lock:
        if job_id not in _seal_jobs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found",
            )

        if _seal_jobs[job_id].get("user_id") != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found",
            )

        job = _seal_jobs[job_id].copy()

    if job["status"] == "failed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Seal job failed: {job['error']}",
        )

    if job["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Seal job not completed yet (status: {job['status']})",
        )

    output_path = Path(job["output_path"])
    if not output_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sealed PDF file not found (may have been cleaned up)",
        )

    # Determine output filename
    original_name = job["filename"]
    sealed_name = original_name.replace(".pdf", "_sealed.pdf")

    return FileResponse(
        path=output_path,
        media_type="application/pdf",
        filename=sealed_name,
    )


@router.post("/validate", response_model=SealValidationResponse)
async def validate_seal(
    file: UploadFile = File(..., description="PDF file with seal to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    seal_manager: SealManager = Depends(get_seal_manager),
) -> SealValidationResponse:
    """Validate electronic seal on PDF.

    Checks certificate type, organization info, timestamp, and integrity.

    **Example:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/seal/validate" \\
         -H "X-API-Key: your-api-key" \\
         -F "file=@sealed_document.pdf"
    ```

    Args:
        file: PDF file with seal (multipart/form-data)
        current_user: Authenticated user
        seal_manager: SealManager instance

    Returns:
        SealValidationResponse with validation results

    Raises:
        HTTPException: 400 if file is invalid
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
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
            detail="Only PDF files are supported",
        )
    # Save uploaded file to temp directory
    temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_api_seals"
    temp_dir.mkdir(exist_ok=True)

    temp_path = temp_dir / f"validate_{uuid.uuid4().hex[:12]}.pdf"

    settings = get_api_settings()

    max_size = (
        settings.max_upload_size_mb * 1024 * 1024
        if hasattr(settings, "max_upload_size_mb")
        else 50 * 1024 * 1024
    )

    try:
        total_size = 0
        with open(temp_path, "wb") as f:
            while chunk := await file.read(8192):
                total_size += len(chunk)
                if total_size > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="File too large",
                    )
                f.write(chunk)
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise

    try:
        # Validate seal
        result = seal_manager.validate_seal(temp_path)

        return SealValidationResponse(
            valid=result.valid,
            seal_type=result.seal_type.value,
            organization=_org_info_to_pydantic(result.organization),
            sealed_at=result.sealed_at.isoformat(),
            certificate_valid=result.certificate_valid,
            timestamp_valid=result.timestamp_valid,
            integrity_intact=result.integrity_intact,
            issues=result.issues,
        )

    finally:
        # Cleanup temp file
        if temp_path.exists():
            temp_path.unlink()

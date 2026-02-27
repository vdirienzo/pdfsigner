"""Seal endpoints for electronic seal operations (eIDAS Article 35-40).

Provides REST API for asynchronous PDF sealing with job tracking.
Electronic seals are for organizations (legal persons), not individuals.
"""

import tempfile
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
from pdfsigner.api.schemas.seal import SealJobStatus, SealResponse, SealValidationResponse
from pdfsigner.api.services import seal_service
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.eidas.seal_manager import SealManager, get_seal_manager
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/seal", tags=["sealing"])


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
    """Create electronic seal on PDF asynchronously."""
    settings = get_api_settings()

    # Validate file
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are supported",
        )

    try:
        safe_filename_str = sanitize_filename(file.filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filename: {e}",
        ) from e

    # Stream file to temp directory
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_api_seals"
    temp_dir.mkdir(exist_ok=True)

    import uuid

    job_id_temp = f"seal_{uuid.uuid4().hex[:12]}"
    input_path = temp_dir / f"{job_id_temp}_input.pdf"

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

    # Parse enums
    try:
        seal_type_enum, appearance_enum = seal_service.parse_seal_enums(seal_type, appearance)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Build config
    seal_config = seal_service.build_seal_config(
        organization_name=organization_name,
        organization_country=organization_country,
        organization_id=organization_id,
        seal_type_enum=seal_type_enum,
        appearance_enum=appearance_enum,
        reason=reason,
        location=location,
        page=page,
        include_timestamp=include_timestamp,
        tsa_url=getattr(settings, "default_tsa_url", "") or "",
    )

    # Create job
    try:
        job_id = seal_service.create_seal_job(
            user_id=current_user.id,
            filename=file.filename,
            organization_name=organization_name,
            seal_type=seal_type,
            input_path=input_path,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    # Start background task
    background_tasks.add_task(
        seal_service.process_seal_job, job_id, input_path, seal_config, seal_manager
    )

    logger.info(f"Seal job {job_id} created for {safe_filename_str}")

    return seal_service.build_seal_response(job_id, organization_name, seal_type, safe_filename_str)


@router.get("/{job_id}/status", response_model=SealJobStatus)
async def get_seal_status(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
) -> SealJobStatus:
    """Get status of a sealing job."""
    try:
        job = seal_service.get_seal_job(job_id, current_user.id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    return seal_service.build_job_status_response(job)


@router.get("/{job_id}/download")
async def download_sealed_pdf(
    job_id: str,
    current_user: User = Depends(get_current_user_or_api_key),
) -> FileResponse:
    """Download sealed PDF."""
    try:
        job = seal_service.get_seal_job(job_id, current_user.id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    try:
        output_path, sealed_name = seal_service.get_download_info(job)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    return FileResponse(path=output_path, media_type="application/pdf", filename=sealed_name)


@router.post("/validate", response_model=SealValidationResponse)
async def validate_seal(
    file: UploadFile = File(..., description="PDF file with seal to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    seal_manager: SealManager = Depends(get_seal_manager),
) -> SealValidationResponse:
    """Validate electronic seal on PDF."""
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )

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

    # Save uploaded file
    temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_api_seals"
    temp_dir.mkdir(exist_ok=True)

    import uuid

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
        result = seal_manager.validate_seal(temp_path)

        return SealValidationResponse(
            valid=result.valid,
            seal_type=result.seal_type.value,
            organization=seal_service.org_info_to_pydantic(result.organization),
            sealed_at=result.sealed_at.isoformat(),
            certificate_valid=result.certificate_valid,
            timestamp_valid=result.timestamp_valid,
            integrity_intact=result.integrity_intact,
            issues=result.issues,
        )
    finally:
        if temp_path.exists():
            temp_path.unlink()


__all__ = ["router"]

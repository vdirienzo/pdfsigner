"""
Validation routes for PDF signature verification.

Provides endpoints for:
- Single PDF validation
- Batch PDF validation
- eIDAS qualification validation
"""

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from loguru import logger

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.validate import BatchValidateResponse, ValidateResponse
from pdfsigner.api.services.validation_service import ValidationService
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/validate", tags=["validation"])


def get_validation_service() -> ValidationService:
    """Get validation service instance."""
    return ValidationService()


async def save_upload_to_temp(upload_file: UploadFile) -> Path:
    """Save uploaded file to temporary location.

    Args:
        upload_file: FastAPI UploadFile object

    Returns:
        Path to saved temporary file

    Raises:
        HTTPException: 400 if file is empty or invalid
    """
    if not upload_file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )

    try:
        safe_filename_str = sanitize_filename(upload_file.filename)
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

    temp_file = tempfile.NamedTemporaryFile(
        delete=False, suffix=".pdf", prefix="pdfsigner_validate_"
    )
    temp_path = Path(temp_file.name)

    try:
        content = await upload_file.read()

        if not content:
            temp_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        temp_file.write(content)
        temp_file.close()

        logger.debug(f"Saved upload '{safe_filename_str}' to {temp_path}")
        return temp_path

    except HTTPException:
        raise
    except Exception as e:
        temp_path.unlink(missing_ok=True)
        logger.error(f"Error saving upload: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File upload failed",
        ) from e


def cleanup_temp_files(temp_paths: list[Path]) -> None:
    """Clean up temporary files."""
    for temp_path in temp_paths:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup {temp_path}: {e}")


@router.post(
    "/",
    response_model=ValidateResponse,
    summary="Validate single PDF",
    description="Validate digital signatures in a PDF document.",
)
async def validate_document(
    file: UploadFile = File(..., description="PDF file to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
    service: ValidationService = Depends(get_validation_service),
) -> ValidateResponse:
    """Validate signatures in a single PDF document."""
    temp_path: Path | None = None

    try:
        temp_path = await save_upload_to_temp(file)

        logger.info(f"User '{current_user.username}' validating: {file.filename}")
        response = service.validate_single(temp_path)
        response.filename = file.filename or "unknown.pdf"

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating PDF: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Validation failed",
        ) from e
    finally:
        if temp_path:
            cleanup_temp_files([temp_path])


@router.post(
    "/batch",
    response_model=BatchValidateResponse,
    summary="Validate multiple PDFs",
    description="Validate digital signatures in multiple PDF documents (max 50).",
)
async def validate_batch(
    files: list[UploadFile] = File(..., description="PDF files to validate (max 50)"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
    service: ValidationService = Depends(get_validation_service),
) -> BatchValidateResponse:
    """Validate signatures in multiple PDF documents."""
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided",
        )

    max_batch_size = 50
    if len(files) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Maximum {max_batch_size} files allowed per batch",
        )

    logger.info(f"User '{current_user.username}' batch validating {len(files)} PDFs")

    temp_paths: list[Path] = []

    try:
        for upload_file in files:
            try:
                temp_path = await save_upload_to_temp(upload_file)
                temp_paths.append(temp_path)
            except HTTPException as e:
                logger.warning(f"Skipping invalid file '{upload_file.filename}': {e.detail}")
                continue

        batch_response = service.validate_batch(temp_paths)

        for i, upload_file in enumerate(files):
            if i < len(batch_response.results):
                batch_response.results[i].filename = upload_file.filename or "unknown.pdf"

        return batch_response
    finally:
        if temp_paths:
            cleanup_temp_files(temp_paths)


@router.post(
    "/eidas",
    response_model=dict,
    summary="Validate PDF with eIDAS report",
    description="Validate PDF signatures with eIDAS qualification detection (ETSI TS 119 102-2).",
)
async def validate_eidas(
    file: UploadFile = File(..., description="PDF file to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
    service: ValidationService = Depends(get_validation_service),
) -> dict:
    """Validate PDF signatures with eIDAS qualification detection."""
    temp_path: Path | None = None

    try:
        temp_path = await save_upload_to_temp(file)

        logger.info(f"User '{current_user.username}' eIDAS validating: {file.filename}")

        report = service.validate_eidas(temp_path)
        report["document"]["filename"] = file.filename or "unknown.pdf"

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"eIDAS validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="eIDAS validation failed",
        ) from e
    finally:
        if temp_path:
            cleanup_temp_files([temp_path])


__all__ = ["router"]

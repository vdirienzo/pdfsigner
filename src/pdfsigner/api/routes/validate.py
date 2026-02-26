"""
Validation routes for PDF signature verification.

Provides endpoints for:
- Single PDF validation
- Batch PDF validation
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


# --- Dependency Injection ---


def get_validation_service() -> ValidationService:
    """
    Get validation service instance.

    Returns:
        ValidationService instance
    """
    return ValidationService()


# --- Helper Functions ---


async def save_upload_to_temp(upload_file: UploadFile) -> Path:
    """
    Save uploaded file to temporary location.

    Args:
        upload_file: FastAPI UploadFile object

    Returns:
        Path to saved temporary file

    Raises:
        HTTPException: 400 if file is empty or invalid
    """
    # Validate file
    if not upload_file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )

    # Sanitize filename to prevent Path Traversal
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

    # Create temporary file with .pdf extension
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".pdf",
        prefix="pdfsigner_validate_",
    )
    temp_path = Path(temp_file.name)

    try:
        # Write uploaded content to temp file
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
        # Clean up on error
        temp_path.unlink(missing_ok=True)
        logger.error(f"Error saving upload: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File upload failed",
        ) from e


def cleanup_temp_files(temp_paths: list[Path]) -> None:
    """
    Clean up temporary files.

    Args:
        temp_paths: List of temporary file paths to delete
    """
    for temp_path in temp_paths:
        try:
            temp_path.unlink(missing_ok=True)
            logger.debug(f"Cleaned up temp file: {temp_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanup {temp_path}: {e}")


# --- Routes ---


@router.post(
    "/",
    response_model=ValidateResponse,
    summary="Validate single PDF",
    description="""
    Validate digital signatures in a PDF document.

    Returns detailed information about:
    - Signature validity (cryptographic integrity)
    - Signer information (name, email, certificate)
    - Timestamp information (if present)
    - PAdES compliance level (B-B, B-T, B-LT, B-LTA)
    - LTV information (DSS, OCSP, CRL, archive timestamps)
    - Certificate chain validation
    - Revocation status (if enabled in settings)

    **Authentication:** Requires JWT token or API key.
    """,
    responses={
        200: {
            "description": "Validation successful",
            "content": {
                "application/json": {
                    "example": {
                        "filename": "signed_document.pdf",
                        "is_signed": True,
                        "is_valid": True,
                        "signature_count": 1,
                        "signatures": [
                            {
                                "signer_name": "John Doe",
                                "signer_email": "john@example.com",
                                "signing_time": "2024-01-15T10:30:00Z",
                                "is_valid": True,
                                "has_timestamp": True,
                                "pades_level": "B-LT",
                            }
                        ],
                        "ltv_info": {
                            "has_dss": True,
                            "has_ocsp": True,
                            "has_crl": False,
                            "has_archive_timestamp": False,
                            "archive_timestamp_count": 0,
                        },
                        "pades_level": "B-LT",
                        "errors": [],
                    }
                }
            },
        },
        400: {"description": "Invalid file or file not provided"},
        401: {"description": "Authentication required"},
        500: {"description": "Internal server error"},
    },
)
async def validate_document(
    file: UploadFile = File(..., description="PDF file to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
    service: ValidationService = Depends(get_validation_service),
) -> ValidateResponse:
    """
    Validate signatures in a single PDF document.

    Args:
        file: Uploaded PDF file to validate
        current_user: Authenticated user (from JWT or API key)
        service: Validation service instance

    Returns:
        ValidateResponse with validation results

    Raises:
        HTTPException: 400 if file is invalid, 500 if validation fails
    """
    temp_path: Path | None = None

    try:
        # Save uploaded file to temporary location
        temp_path = await save_upload_to_temp(file)

        # Validate PDF
        logger.info(f"User '{current_user.username}' validating: {file.filename}")
        response = service.validate_single(temp_path)

        # Update filename in response (use original upload name)
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
        # Always clean up temporary file
        if temp_path:
            cleanup_temp_files([temp_path])


@router.post(
    "/batch",
    response_model=BatchValidateResponse,
    summary="Validate multiple PDFs",
    description="""
    Validate digital signatures in multiple PDF documents.

    Processes each PDF independently and returns aggregated results.
    Failed validations are included in results with error details.

    **Authentication:** Requires JWT token or API key.

    **Limitations:**
    - Maximum 50 files per batch (configurable)
    - Each file processed sequentially
    - Partial failures still return results for successful validations
    """,
    responses={
        200: {
            "description": "Batch validation completed",
            "content": {
                "application/json": {
                    "example": {
                        "total": 3,
                        "valid": 2,
                        "invalid": 1,
                        "results": [
                            {
                                "filename": "doc1.pdf",
                                "is_signed": True,
                                "is_valid": True,
                                "signature_count": 1,
                            },
                            {
                                "filename": "doc2.pdf",
                                "is_signed": True,
                                "is_valid": True,
                                "signature_count": 1,
                            },
                            {
                                "filename": "doc3.pdf",
                                "is_signed": False,
                                "is_valid": False,
                                "signature_count": 0,
                                "errors": ["No signatures found"],
                            },
                        ],
                    }
                }
            },
        },
        400: {"description": "Invalid files or no files provided"},
        401: {"description": "Authentication required"},
        413: {"description": "Too many files in batch"},
    },
)
async def validate_batch(
    files: list[UploadFile] = File(..., description="PDF files to validate (max 50)"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
    service: ValidationService = Depends(get_validation_service),
) -> BatchValidateResponse:
    """
    Validate signatures in multiple PDF documents.

    Args:
        files: List of uploaded PDF files to validate
        current_user: Authenticated user (from JWT or API key)
        service: Validation service instance

    Returns:
        BatchValidateResponse with aggregated results

    Raises:
        HTTPException: 400 if no files provided, 413 if too many files
    """
    # Validate batch size
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
        # Save all uploaded files to temporary locations
        for upload_file in files:
            try:
                temp_path = await save_upload_to_temp(upload_file)
                temp_paths.append(temp_path)
            except HTTPException as e:
                # Continue with other files, log error
                logger.warning(f"Skipping invalid file '{upload_file.filename}': {e.detail}")
                continue

        # Validate all PDFs
        batch_response = service.validate_batch(temp_paths)

        # Update filenames in response (use original upload names)
        for i, upload_file in enumerate(files):
            if i < len(batch_response.results):
                batch_response.results[i].filename = upload_file.filename or "unknown.pdf"

        return batch_response

    finally:
        # Always clean up all temporary files
        if temp_paths:
            cleanup_temp_files(temp_paths)


@router.post(
    "/eidas",
    response_model=dict,
    summary="Validate PDF with eIDAS report",
    description="""
    Validate PDF signatures with eIDAS qualification detection.

    Returns a structured validation report per ETSI TS 119 102-2
    including eIDAS qualification level (QES/AdES-QC/AdES/Basic),
    algorithm strength assessment, and revocation freshness.

    Report fields include:
    - **MainIndication**: TOTAL_PASSED, TOTAL_FAILED, INDETERMINATE
    - **SubIndication**: Detailed failure reason (FORMAT_FAILURE, REVOKED, etc.)
    - **SignatureQuality**: QES, AdES-QC, AdES, Basic
    - **AlgorithmAssessment**: SOGIS strength (strong/acceptable/legacy/weak)
    - **RevocationStatus**: OCSP/CRL result with CIR 2025/1945 freshness check
    - **TrustServiceProvider**: Qualified TSP info from EUTL

    **Authentication:** Requires JWT token or API key.
    """,
    responses={
        200: {
            "description": "eIDAS validation report generated",
            "content": {
                "application/json": {
                    "example": {
                        "report_version": "1.0",
                        "standard": "ETSI TS 119 102-2 V1.4.1",
                        "overall": {
                            "main_indication": "TOTAL-PASSED",
                            "sub_indication": None,
                            "eidas_level": "QES",
                        },
                    }
                }
            },
        },
        400: {"description": "Invalid file or file not provided"},
        401: {"description": "Authentication required"},
        500: {"description": "Internal server error"},
    },
)
async def validate_eidas(
    file: UploadFile = File(..., description="PDF file to validate"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
) -> dict:
    """
    Validate PDF signatures with eIDAS qualification detection.

    Generates a structured validation report per ETSI TS 119 102-2
    including eIDAS qualification level (QES/AdES-QC/AdES/Basic),
    algorithm strength assessment, and revocation freshness.

    Args:
        file: Uploaded PDF file to validate
        current_user: Authenticated user (from JWT or API key)

    Returns:
        eIDAS validation report dictionary

    Raises:
        HTTPException: 400 if file is invalid, 500 if validation fails
    """
    from pdfsigner.core.validator.pdf_validator import PDFValidator
    from pdfsigner.core.validator.validation_report import generate_eidas_report

    temp_path: Path | None = None

    try:
        temp_path = await save_upload_to_temp(file)

        logger.info(f"User '{current_user.username}' eIDAS validating: {file.filename}")

        validator = PDFValidator()
        validation_result = validator.validate(temp_path)

        report = generate_eidas_report(validation_result, temp_path)

        # Use original filename in report
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


# --- Public Exports ---

__all__ = ["router"]

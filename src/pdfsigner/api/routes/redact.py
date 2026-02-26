"""
Redact endpoints for PDF redaction operations.

Provides REST API for automatic PII/PHI redaction from PDF documents.
"""

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import Response
from loguru import logger

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.redact import (
    PreviewRequest,
    RedactByPatternRequest,
    RedactionResponse,
    RedactRegionsRequest,
)
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.detection.pii_types import RedactionRegion
from pdfsigner.core.detection.redactor import RedactionResult, get_pdf_redactor
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/redact", tags=["redaction"])


def _convert_result_to_response(
    result: RedactionResult, download_url: str | None = None
) -> RedactionResponse:
    """Convert RedactionResult to API RedactionResponse."""
    message = None
    if result.success:
        if result.redaction_count == 0:
            message = "No PII detected or redacted"
        else:
            message = (
                f"Successfully redacted {result.redaction_count} regions "
                f"on {len(result.pages_affected)} pages"
            )
    else:
        message = f"Redaction failed: {', '.join(result.errors)}"

    return RedactionResponse(
        success=result.success,
        output_path=result.output_path,
        redaction_count=result.redaction_count,
        pages_affected=result.pages_affected,
        errors=result.errors,
        download_url=download_url,
        message=message,
    )


@router.post("/regions", response_model=RedactionResponse)
async def redact_regions(
    request: RedactRegionsRequest,
    file: UploadFile = File(..., description="PDF file to redact"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.SIGN)),  # Reuse SIGN permission
) -> RedactionResponse:
    """
    Redact specific regions in a PDF by coordinates.

    Accepts a PDF file and a list of rectangular regions to redact.
    Performs true redaction (removes underlying text permanently).

    **Authentication:** Requires JWT token or API key

    **Permissions:** Requires SIGN permission

    **Example:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/redact/regions" \\
         -H "X-API-Key: your-api-key" \\
         -F "file=@document.pdf" \\
         -F 'request={"regions":[{"page":0,"x0":100,"y0":200,"x1":300,"y1":220}]}'
    ```

    Returns:
        RedactionResponse with success status and download URL
    """
    # Validate file type
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
    # Create temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)

        # Save uploaded file
        input_path = temp_dir_path / safe_filename_str
        with open(input_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Determine output path (sanitize to prevent path traversal)
        raw_output_name = request.output_filename or f"{input_path.stem}_redacted.pdf"
        output_filename = sanitize_filename(raw_output_name)
        output_path = temp_dir_path / output_filename

        try:
            # Convert schema regions to RedactionRegion objects
            regions = [
                RedactionRegion(
                    page=r.page,
                    x0=r.x0,
                    y0=r.y0,
                    x1=r.x1,
                    y1=r.y1,
                    fill_color=r.fill_color,
                    replacement_text=r.replacement_text,
                )
                for r in request.regions
            ]

            # Perform redaction
            redactor = get_pdf_redactor()
            result = redactor.redact_regions(input_path, regions, output_path)

            if not result.success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Redaction failed: {', '.join(result.errors)}",
                )

            # Return response with file download info
            # Note: In production, you'd store the file and return a download URL
            # For now, return the path info
            download_url = f"/api/v1/redact/download/{output_filename}"

            return _convert_result_to_response(result, download_url)

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Redaction failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Redaction failed",
            ) from e


@router.post("/auto", response_model=RedactionResponse)
async def redact_by_pattern(
    request: RedactByPatternRequest,
    file: UploadFile = File(..., description="PDF file to redact"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.SIGN)),
) -> RedactionResponse:
    """
    Auto-detect and redact PII by type.

    Automatically detects and redacts specified types of PII/PHI in the document
    using the PII detection engine. Supports SSN, credit card, email, phone, etc.

    **Authentication:** Requires JWT token or API key

    **Permissions:** Requires SIGN permission

    **Example:**
    ```bash
    curl -X POST "http://localhost:8000/api/v1/redact/auto" \\
         -H "X-API-Key: your-api-key" \\
         -F "file=@document.pdf" \\
         -F 'request={"pii_types":["ssn","credit_card"],"min_confidence":0.7}'
    ```

    Returns:
        RedactionResponse with success status and statistics
    """
    # Validate file type
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
    # Create temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)

        # Save uploaded file
        input_path = temp_dir_path / safe_filename_str
        with open(input_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Determine output path (sanitize to prevent path traversal)
        raw_output_name = request.output_filename or f"{input_path.stem}_redacted.pdf"
        output_filename = sanitize_filename(raw_output_name)
        output_path = temp_dir_path / output_filename

        try:
            # Perform pattern-based redaction
            redactor = get_pdf_redactor()
            result = redactor.redact_by_pattern(
                input_path,
                pii_types=request.pii_types,
                output_path=output_path,
                min_confidence=request.min_confidence,
            )

            if not result.success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Redaction failed: {', '.join(result.errors)}",
                )

            # Return response
            download_url = f"/api/v1/redact/download/{output_filename}"

            return _convert_result_to_response(result, download_url)

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Pattern-based redaction failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Redaction failed",
            ) from e


@router.post("/preview", response_class=Response)
async def preview_redactions(
    request: PreviewRequest,
    file: UploadFile = File(..., description="PDF file to preview"),
    current_user: User = Depends(get_current_user_or_api_key),
    _perm: None = Depends(check_permission(Permission.SIGN)),
) -> Response:
    """
    Preview redactions without applying them.

    Generates a PNG image showing the specified page with redaction
    regions highlighted. Does not modify the PDF.

    **Authentication:** Requires JWT token or API key

    **Permissions:** Requires SIGN permission

    Returns:
        PNG image data
    """
    # Validate file type
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
    # Create temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)

        # Save uploaded file
        input_path = temp_dir_path / safe_filename_str
        with open(input_path, "wb") as f:
            content = await file.read()
            f.write(content)

        try:
            # Convert schema regions to RedactionRegion objects
            regions = [
                RedactionRegion(
                    page=r.page,
                    x0=r.x0,
                    y0=r.y0,
                    x1=r.x1,
                    y1=r.y1,
                    fill_color=r.fill_color,
                    replacement_text=r.replacement_text,
                )
                for r in request.regions
            ]

            # Generate preview
            redactor = get_pdf_redactor()
            png_data = redactor.preview_redactions(
                input_path, regions, page_num=request.page, dpi=request.dpi
            )

            return Response(content=png_data, media_type="image/png")

        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
        except Exception as e:
            logger.exception(f"Preview generation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Preview generation failed",
            ) from e

"""
PHI/PII scanning routes for PDF documents.

Provides endpoint for detecting Protected Health Information (PHI)
and Personally Identifiable Information (PII) in PDF documents
per HIPAA §164.514 de-identification requirements.
"""

import tempfile
import time
from pathlib import Path
from typing import Annotated

import fitz
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from loguru import logger

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.phi import PIIMatchResponse, PIIScanResponse
from pdfsigner.api.utils import sanitize_filename
from pdfsigner.core.audit import AuditEventType, get_audit_logger
from pdfsigner.core.detection import PDFScanner, get_pii_detector
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/phi", tags=["phi"])


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
        prefix="pdfsigner_phi_",
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
            detail=f"Failed to save uploaded file: {str(e)}",
        ) from e


def cleanup_temp_file(temp_path: Path) -> None:
    """
    Clean up temporary file.

    Args:
        temp_path: Temporary file path to delete
    """
    try:
        temp_path.unlink(missing_ok=True)
        logger.debug(f"Cleaned up temp file: {temp_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup {temp_path}: {e}")


# --- Routes ---


@router.post(
    "/scan",
    response_model=PIIScanResponse,
    summary="Scan PDF for PHI/PII",
    description="""
    Scan uploaded PDF document for Protected Health Information (PHI)
    and Personally Identifiable Information (PII).

    **Detects:**
    - Social Security Numbers (SSN)
    - Credit Card Numbers (with Luhn validation)
    - Email Addresses
    - Phone Numbers (various formats)
    - Dates of Birth (with context)
    - Medical Record Numbers (MRN)
    - Health Plan IDs
    - ICD-10 Diagnosis Codes
    - Prescription Information

    **Returns:**
    - Detection status (has_pii)
    - Risk score (0.0-1.0)
    - Count of matches by PII type
    - Redacted values for security
    - Confidence scores for each match (0.0-1.0)
    - Scan performance metrics

    **Authentication:** Requires JWT token or API key.

    **Privacy Note:** All PII values are redacted in the response to prevent
    exposure of sensitive data.
    """,
    responses={
        200: {
            "description": "Scan completed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "filename": "patient_record.pdf",
                        "has_pii": True,
                        "total_matches": 5,
                        "risk_score": 0.85,
                        "by_type": {
                            "ssn": 1,
                            "phone": 2,
                            "email": 2,
                        },
                        "matches": [
                            {
                                "pii_type": "ssn",
                                "pii_type_display": "Social Security Number",
                                "redacted_value": "***-**-6789",
                                "confidence": 0.95,
                                "start_pos": 100,
                                "end_pos": 111,
                                "page": 0,
                                "bbox": [100.0, 200.0, 250.0, 220.0],
                                "context": "...SSN: 123-45-6789...",
                            }
                        ],
                        "scan_time_ms": 123.45,
                        "pages_scanned": 3,
                        "error": None,
                    }
                }
            },
        },
        400: {"description": "Invalid file or file not provided"},
        401: {"description": "Authentication required"},
        500: {"description": "Internal server error"},
    },
)
async def scan_for_phi(
    file: UploadFile = File(..., description="PDF file to scan for PHI/PII"),
    current_user: Annotated[User, Depends(get_current_user_or_api_key)] = None,
    _perm: None = Depends(check_permission(Permission.VALIDATE)),
) -> PIIScanResponse:
    """
    Scan PDF document for Protected Health Information and PII.

    Args:
        file: Uploaded PDF file to scan
        current_user: Authenticated user (from JWT or API key)

    Returns:
        PIIScanResponse with detection results (redacted values)

    Raises:
        HTTPException: 400 if file is invalid, 500 if scan fails
    """
    temp_path: Path | None = None
    audit_logger = get_audit_logger()

    try:
        # Save uploaded file to temporary location
        temp_path = await save_upload_to_temp(file)

        # Scan PDF for PII
        logger.info(f"User '{current_user.username}' scanning for PII: {file.filename}")

        start_time = time.perf_counter()

        scanner = PDFScanner()
        matches = scanner.scan_pdf(str(temp_path))

        # Calculate risk score
        detector = get_pii_detector()
        risk_score = detector.get_risk_score(matches)

        # Count pages
        doc = fitz.open(temp_path)
        pages_scanned = len(doc)
        doc.close()

        # Calculate by_type counts
        by_type: dict[str, int] = {}
        for match in matches:
            pii_type = match.pii_type.value
            by_type[pii_type] = by_type.get(pii_type, 0) + 1

        scan_time_ms = (time.perf_counter() - start_time) * 1000

        # Convert to response model
        match_responses = [
            PIIMatchResponse(
                pii_type=match.pii_type.value,
                pii_type_display=match.pii_type.display_name,
                redacted_value=match.redacted_value,
                confidence=match.confidence,
                start_pos=match.start_pos,
                end_pos=match.end_pos,
                page=match.page,
                bbox=list(match.bbox) if match.bbox else None,
                context=match.context,
            )
            for match in matches
        ]

        response = PIIScanResponse(
            filename=file.filename or "unknown.pdf",
            has_pii=len(matches) > 0,
            total_matches=len(matches),
            risk_score=risk_score,
            by_type=by_type,
            matches=match_responses,
            scan_time_ms=scan_time_ms,
            pages_scanned=pages_scanned,
            error=None,
        )

        # Log audit event
        audit_logger.log_event(
            event_type=AuditEventType.PHI_DETECTED
            if response.has_pii
            else AuditEventType.DOCUMENT_VALIDATED,
            user_id=current_user.username,
            details={
                "filename": file.filename or "unknown.pdf",
                "has_pii": response.has_pii,
                "total_matches": response.total_matches,
                "risk_score": risk_score,
                "pii_types": list(by_type.keys()),
                "scan_time_ms": scan_time_ms,
            },
        )

        logger.info(
            f"PII scan complete for '{file.filename}': "
            f"{response.total_matches} matches, risk={risk_score:.2f}, "
            f"time={scan_time_ms:.1f}ms"
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning PDF for PII: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PII scan failed: {str(e)}",
        ) from e

    finally:
        # Always clean up temporary file
        if temp_path:
            cleanup_temp_file(temp_path)


# --- Public Exports ---

__all__ = ["router"]

"""
evidence.py - SOC 2 evidence collection routes

REST API endpoints for SOC 2 Type II evidence collection and reporting.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.evidence import (
    EvidenceCollectionResponse,
    EvidenceItemResponse,
    EvidenceRequest,
    SOC2ExportResponse,
    SOC2ReportRequest,
    SOC2ReportResponse,
)
from pdfsigner.api.services import evidence_service
from pdfsigner.core.rbac.authorization import check_permission
from pdfsigner.core.rbac.permissions import Permission

router = APIRouter(prefix="/api/v1/compliance/evidence", tags=["evidence", "soc2"])


@router.post(
    "/collect",
    response_model=EvidenceCollectionResponse,
    summary="Collect SOC 2 evidence",
    description="Trigger SOC 2 evidence collection for a specified period.",
)
async def collect_evidence(
    request: EvidenceRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> EvidenceCollectionResponse:
    """Collect evidence for SOC 2 compliance."""
    if request.period_end <= request.period_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_end must be after period_start",
        )

    try:
        return evidence_service.collect_evidence(
            request.period_start, request.period_end, current_user.username
        )
    except Exception as e:
        logger.error(f"Failed to collect evidence: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Evidence collection failed",
        ) from e


@router.get(
    "/",
    response_model=list[EvidenceItemResponse],
    summary="List collected evidence",
    description="List all evidence items collected in the current session.",
)
async def list_evidence(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> list[EvidenceItemResponse]:
    """List collected evidence."""
    return []


@router.get(
    "/{evidence_id}",
    response_model=EvidenceItemResponse,
    summary="Get specific evidence",
    description="Retrieve a specific evidence item by ID.",
)
async def get_evidence(
    evidence_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> EvidenceItemResponse:
    """Get specific evidence item."""
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Evidence not found: {evidence_id}",
    )


@router.post(
    "/soc2/report",
    response_model=SOC2ReportResponse,
    summary="Generate SOC 2 report",
    description="Generate a SOC 2 Type II compliance report for the specified period.",
)
async def generate_soc2_report(
    request: SOC2ReportRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> SOC2ReportResponse:
    """Generate SOC 2 report."""
    if request.period_end <= request.period_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_end must be after period_start",
        )

    try:
        return evidence_service.generate_soc2_report(
            request.period_start, request.period_end, current_user.username
        )
    except Exception as e:
        logger.error(f"Failed to generate SOC 2 report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed",
        ) from e


@router.get(
    "/soc2/export",
    response_model=SOC2ExportResponse,
    summary="Export SOC 2 report as ZIP",
    description="Export a complete SOC 2 evidence package as a ZIP file.",
)
async def export_soc2_report(
    period_start: str,
    period_end: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> SOC2ExportResponse:
    """Export SOC 2 report as ZIP."""
    try:
        return evidence_service.export_soc2_package(period_start, period_end, current_user.username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to export SOC 2 report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Export failed",
        ) from e


@router.get(
    "/export/{filename}",
    summary="Download exported report",
    description="Download a previously exported SOC 2 report ZIP file.",
)
async def download_export(
    filename: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> FileResponse:
    """Download exported report."""
    try:
        export_path = evidence_service.get_export_path(filename)
    except (LookupError, FileNotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    return FileResponse(path=str(export_path), media_type="application/zip", filename=filename)


__all__ = ["router"]

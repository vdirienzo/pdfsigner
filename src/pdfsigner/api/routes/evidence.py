"""
evidence.py - SOC 2 evidence collection routes

REST API endpoints for SOC 2 Type II evidence collection and reporting.
"""

import hashlib
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.evidence import (
    ControlAssessmentResponse,
    EvidenceCollectionResponse,
    EvidenceItemResponse,
    EvidenceRequest,
    SOC2ExportResponse,
    SOC2ReportRequest,
    SOC2ReportResponse,
)
from pdfsigner.core.compliance import generate_report, get_evidence_collector
from pdfsigner.core.rbac.authorization import check_permission
from pdfsigner.core.rbac.permissions import Permission

router = APIRouter(prefix="/api/v1/compliance/evidence", tags=["evidence", "soc2"])

# Store generated exports temporarily (in production, use proper storage)
_generated_exports: dict[str, Path] = {}


@router.post(
    "/collect",
    response_model=EvidenceCollectionResponse,
    summary="Collect SOC 2 evidence",
    description="""
    Trigger SOC 2 evidence collection for a specified period.

    Collects evidence from multiple sources:
    - Access logs (CC6.1)
    - Audit logs (CC7.2)
    - Configuration snapshots (CC5)
    - User access reviews (CC6.3)
    - Security incidents (CC9)

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def collect_evidence(
    request: EvidenceRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> EvidenceCollectionResponse:
    """
    Collect evidence for SOC 2 compliance.

    Args:
        request: Evidence collection request with date range
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Collection of evidence items

    Raises:
        HTTPException: 400 if date range is invalid
        HTTPException: 500 if collection fails
    """
    # Validate date range
    if request.period_end <= request.period_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_end must be after period_start",
        )

    try:
        collector = get_evidence_collector()
        logger.info(
            f"Collecting evidence from {request.period_start} to {request.period_end} "
            f"(requested by {current_user.username})"
        )

        collection = collector.collect_all_evidence(request.period_start, request.period_end)

        # Convert to response format
        evidence_items = [
            EvidenceItemResponse(
                id=item.id,
                category=item.category.value,
                evidence_type=item.evidence_type.value,
                title=item.title,
                description=item.description,
                collected_at=item.collected_at,
                period_start=item.period_start,
                period_end=item.period_end,
                file_path=item.file_path,
                checksum=item.checksum,
            )
            for item in collection.evidence_items
        ]

        return EvidenceCollectionResponse(
            evidence_items=evidence_items,
            summary=collection.summary,
            period_start=collection.period_start,
            period_end=collection.period_end,
            collected_at=collection.collected_at,
        )

    except Exception as e:
        logger.error(f"Failed to collect evidence: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence collection failed: {str(e)}",
        )


@router.get(
    "/",
    response_model=list[EvidenceItemResponse],
    summary="List collected evidence",
    description="""
    List all evidence items collected in the current session.

    Note: This endpoint returns evidence from the current session only.
    For persistent storage, use the export endpoint.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def list_evidence(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> list[EvidenceItemResponse]:
    """
    List collected evidence.

    Args:
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        List of evidence items
    """
    # In a real implementation, this would query a database
    # For now, return empty list (evidence is collected on-demand)
    return []


@router.get(
    "/{evidence_id}",
    response_model=EvidenceItemResponse,
    summary="Get specific evidence",
    description="""
    Retrieve a specific evidence item by ID.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def get_evidence(
    evidence_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> EvidenceItemResponse:
    """
    Get specific evidence item.

    Args:
        evidence_id: Evidence ID
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Evidence item

    Raises:
        HTTPException: 404 if evidence not found
    """
    # In a real implementation, this would query a database
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Evidence not found: {evidence_id}",
    )


@router.post(
    "/soc2/report",
    response_model=SOC2ReportResponse,
    summary="Generate SOC 2 report",
    description="""
    Generate a SOC 2 Type II compliance report for the specified period.

    The report includes:
    - Control assessments (CC5-CC9)
    - Implementation status
    - Evidence mapping
    - Executive summary
    - Recommendations

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def generate_soc2_report(
    request: SOC2ReportRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> SOC2ReportResponse:
    """
    Generate SOC 2 report.

    Args:
        request: Report generation request
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        SOC 2 compliance report

    Raises:
        HTTPException: 400 if date range is invalid
        HTTPException: 500 if report generation fails
    """
    # Validate date range
    if request.period_end <= request.period_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_end must be after period_start",
        )

    try:
        # Collect evidence
        collector = get_evidence_collector()
        logger.info(
            f"Generating SOC 2 report from {request.period_start} to {request.period_end} "
            f"(requested by {current_user.username})"
        )

        collection = collector.collect_all_evidence(request.period_start, request.period_end)

        # Generate report
        report = generate_report(
            evidence_list=collection.evidence_items,
            period_start=request.period_start,
            period_end=request.period_end,
        )

        # Convert to response format
        controls_response = [
            ControlAssessmentResponse(
                control_id=ctrl.control_id,
                control_name=ctrl.control_name,
                category=ctrl.category.value,
                status=ctrl.status.value,
                description=ctrl.description,
                implementation=ctrl.implementation,
                evidence_ids=ctrl.evidence_ids,
                gaps=ctrl.gaps,
                notes=ctrl.notes,
            )
            for ctrl in report.controls
        ]

        return SOC2ReportResponse(
            period_start=report.period_start,
            period_end=report.period_end,
            generated_at=report.generated_at,
            controls=controls_response,
            summary=report.summary,
            recommendations=report.recommendations,
        )

    except Exception as e:
        logger.error(f"Failed to generate SOC 2 report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )


@router.get(
    "/soc2/export",
    response_model=SOC2ExportResponse,
    summary="Export SOC 2 report as ZIP",
    description="""
    Export a complete SOC 2 evidence package as a ZIP file.

    The ZIP file includes:
    - SOC 2 report (PDF and Markdown)
    - Evidence files (JSON)
    - Control matrix (CSV)
    - Audit logs (CSV)

    Query parameters:
    - period_start: Start date (ISO 8601)
    - period_end: End date (ISO 8601)

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def export_soc2_report(
    period_start: str,
    period_end: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> SOC2ExportResponse:
    """
    Export SOC 2 report as ZIP.

    Args:
        period_start: Period start (ISO 8601 string)
        period_end: Period end (ISO 8601 string)
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Export metadata with download URL

    Raises:
        HTTPException: 400 if dates are invalid
        HTTPException: 500 if export fails
    """
    from datetime import UTC, datetime

    try:
        # Parse dates
        start_dt = datetime.fromisoformat(period_start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(period_end.replace("Z", "+00:00"))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid date format: {e}",
        )

    if end_dt <= start_dt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_end must be after period_start",
        )

    try:
        # Collect evidence and generate report
        collector = get_evidence_collector()
        collection = collector.collect_all_evidence(start_dt, end_dt)
        report = generate_report(collection.evidence_items, start_dt, end_dt)

        # Create ZIP file
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"soc2_report_{timestamp}.zip"
        temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_exports"
        temp_dir.mkdir(parents=True, exist_ok=True)
        zip_path = temp_dir / filename

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Add report as Markdown
            report_md = report.export_to_markdown()
            zipf.writestr("soc2_report.md", report_md)

            # Add report as JSON
            report_json = json.dumps(report.to_dict(), indent=2)
            zipf.writestr("soc2_report.json", report_json)

            # Add evidence collection
            evidence_json = json.dumps(collection.to_dict(), indent=2)
            zipf.writestr("evidence_collection.json", evidence_json)

            # Add README
            readme = f"""# SOC 2 Type II Evidence Package

Period: {start_dt.date()} to {end_dt.date()}
Generated: {datetime.now(UTC).isoformat()}
Generated by: {current_user.username}

## Contents

- soc2_report.md: Report in Markdown format
- soc2_report.json: Report in JSON format
- evidence_collection.json: Complete evidence collection

## Summary

Total Controls: {report.summary.get("total_controls", 0)}
Implemented: {report.summary.get("implemented", 0)}
Partial: {report.summary.get("partial", 0)}
Coverage: {report.summary.get("coverage_percentage", 0):.1f}%
"""
            zipf.writestr("README.md", readme)

        # Calculate checksum
        with open(zip_path, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()

        # Store for download
        _generated_exports[filename] = zip_path

        return SOC2ExportResponse(
            filename=filename,
            size_bytes=zip_path.stat().st_size,
            generated_at=datetime.now(UTC),
            checksum=checksum,
            download_url=f"/api/v1/compliance/evidence/export/{filename}",
        )

    except Exception as e:
        logger.error(f"Failed to export SOC 2 report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {str(e)}",
        )


@router.get(
    "/export/{filename}",
    summary="Download exported report",
    description="""
    Download a previously exported SOC 2 report ZIP file.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def download_export(
    filename: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> FileResponse:
    """
    Download exported report.

    Args:
        filename: Export filename
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        File response with ZIP content

    Raises:
        HTTPException: 404 if file not found
    """
    if filename not in _generated_exports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Export not found: {filename}",
        )

    export_path = _generated_exports[filename]

    if not export_path.exists():
        # Clean up stale entry
        del _generated_exports[filename]
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Export file not found: {filename}",
        )

    return FileResponse(
        path=str(export_path),
        media_type="application/zip",
        filename=filename,
    )


__all__ = ["router"]

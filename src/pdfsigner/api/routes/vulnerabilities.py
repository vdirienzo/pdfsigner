"""
Vulnerability management routes.

Endpoints for:
- Triggering vulnerability scans
- Listing and filtering vulnerabilities
- Updating vulnerability status
- Generating reports
- Exporting data

NIST: RA-5 - Vulnerability scanning and management
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.vulnerabilities import (
    ScanRequest,
    ScanResponse,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityReport,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from pdfsigner.api.services import vulnerability_service
from pdfsigner.core.rbac import Permission, check_permission

router = APIRouter(prefix="/api/v1/security", tags=["security"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Trigger vulnerability scan",
    description="Trigger a vulnerability scan (admin only).",
)
async def trigger_scan(
    scan_request: ScanRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> ScanResponse:
    """Trigger vulnerability scan (admin only)."""
    logger.info(f"User {current_user.username} triggered {scan_request.scan_type} scan")

    # Determine scan path with path traversal protection
    allowed_base = Path.cwd().resolve()
    if scan_request.path:
        scan_path = Path(scan_request.path).resolve()
        if not scan_path.is_relative_to(allowed_base):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan path must be within the project directory",
            )
    else:
        scan_path = allowed_base / "src"

    count, import_stats = vulnerability_service.run_scan(scan_path, scan_request.auto_import)

    return ScanResponse(
        scan_type=scan_request.scan_type,
        vulnerabilities_found=count,
        imported=scan_request.auto_import,
        import_stats=import_stats,
    )


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities",
    description="List vulnerabilities with optional filters.",
)
async def list_vulnerabilities(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    severity_filter: str | None = Query(None, alias="severity", description="Filter by severity"),
    source_filter: str | None = Query(None, alias="source", description="Filter by source"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> VulnerabilityListResponse:
    """List vulnerabilities with optional filters."""
    try:
        status_enum, severity_enum, source_enum = vulnerability_service.parse_vuln_filters(
            status_filter, severity_filter, source_filter
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    vulns, total = vulnerability_service.list_vulnerabilities_for_user(
        username=current_user.username,
        role=current_user.role,
        status_filter=status_enum,
        severity_filter=severity_enum,
        source_filter=source_enum,
        limit=limit,
        offset=offset,
    )

    return VulnerabilityListResponse(
        vulnerabilities=[vulnerability_service.vuln_to_response(v) for v in vulns],
        total=total,
    )


@router.get(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Get vulnerability by ID",
    description="Get detailed information about a specific vulnerability.",
)
async def get_vulnerability(
    vuln_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> VulnerabilityResponse:
    """Get vulnerability by ID."""
    try:
        vuln = vulnerability_service.get_vulnerability_by_id(
            vuln_id, current_user.username, current_user.role
        )
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    return vulnerability_service.vuln_to_response(vuln)


@router.post(
    "/vulnerabilities",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create vulnerability manually",
    description="Create a vulnerability manually (admin only).",
)
async def create_vulnerability(
    vuln_create: VulnerabilityCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> VulnerabilityResponse:
    """Create vulnerability manually (admin only)."""
    saved_vuln = vulnerability_service.create_vulnerability(
        title=vuln_create.title,
        description=vuln_create.description,
        severity=vuln_create.severity,
        file_path=vuln_create.file_path,
        line_number=vuln_create.line_number,
        cwe_id=vuln_create.cwe_id,
        cvss_score=vuln_create.cvss_score,
        assignee=vuln_create.assignee,
        remediation=vuln_create.remediation,
    )

    logger.info(f"User {current_user.username} created vulnerability {saved_vuln.id}")
    return vulnerability_service.vuln_to_response(saved_vuln)


@router.patch(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Update vulnerability",
    description="Update vulnerability status, assignee, or notes.",
)
async def update_vulnerability(
    vuln_id: str,
    vuln_update: VulnerabilityUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> VulnerabilityResponse:
    """Update vulnerability status/assignee."""
    try:
        updated_vuln = vulnerability_service.update_vulnerability(
            vuln_id=vuln_id,
            username=current_user.username,
            role=current_user.role,
            new_status=vuln_update.status,
            assignee=vuln_update.assignee,
            notes=vuln_update.notes,
        )
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    logger.info(f"User {current_user.username} updated vulnerability {vuln_id}")
    return vulnerability_service.vuln_to_response(updated_vuln)


@router.get(
    "/vulnerabilities/report",
    response_model=VulnerabilityReport,
    summary="Get vulnerability report",
    description="Get vulnerability summary report with statistics.",
)
async def get_vulnerability_report(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> VulnerabilityReport:
    """Get vulnerability summary report."""
    report = vulnerability_service.generate_report()
    logger.debug(f"Generated vulnerability report for user {current_user.username}")
    return VulnerabilityReport(**report)


@router.get(
    "/vulnerabilities/export/csv",
    response_class=PlainTextResponse,
    summary="Export vulnerabilities to CSV",
    description="Export vulnerabilities to CSV format (admin/auditor only).",
)
async def export_vulnerabilities_csv(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
    severity_filter: str | None = Query(None, alias="severity", description="Filter by severity"),
) -> PlainTextResponse:
    """Export vulnerabilities to CSV (admin/auditor only)."""
    try:
        csv_content = vulnerability_service.export_csv(severity_filter)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    logger.info(f"User {current_user.username} exported vulnerabilities to CSV")
    return PlainTextResponse(content=csv_content, media_type="text/csv")


@router.post(
    "/vulnerabilities/import",
    response_model=dict,
    summary="Import scan results",
    description="Import vulnerability scan results (admin only).",
)
async def import_vulnerabilities(
    vulnerabilities: list[VulnerabilityCreate],
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> dict:
    """Import vulnerability scan results (admin only)."""
    vuln_data = [
        {
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "cwe_id": v.cwe_id,
            "cvss_score": v.cvss_score,
            "assignee": v.assignee,
            "remediation": v.remediation,
        }
        for v in vulnerabilities
    ]

    stats = vulnerability_service.import_vulnerabilities(vuln_data)

    logger.info(f"User {current_user.username} imported {len(vulnerabilities)} vulnerabilities")

    return {"message": "Import completed successfully", "statistics": stats}


__all__ = ["router"]

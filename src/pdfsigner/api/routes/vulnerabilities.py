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
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.security import (
    Vulnerability,
    VulnSeverity,
    VulnSource,
    VulnStatus,
    get_vuln_reporter,
    get_vuln_repository,
    get_vuln_tracker,
    run_all_scans,
)

router = APIRouter(prefix="/api/v1/security", tags=["security"])


# --- Helper Functions ---


def _vuln_to_response(vuln: Vulnerability) -> VulnerabilityResponse:
    """Convert Vulnerability model to VulnerabilityResponse schema."""
    return VulnerabilityResponse(
        id=vuln.id,
        title=vuln.title,
        description=vuln.description,
        severity=vuln.severity.value,
        status=vuln.status.value,
        source=vuln.source.value,
        file_path=vuln.file_path,
        line_number=vuln.line_number,
        cwe_id=vuln.cwe_id,
        cvss_score=vuln.cvss_score,
        discovered_at=vuln.discovered_at,
        resolved_at=vuln.resolved_at,
        assignee=vuln.assignee,
        remediation=vuln.remediation,
    )


# --- Routes ---


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Trigger vulnerability scan",
    description="""
    Trigger a vulnerability scan (admin only).

    **Requires:** Admin role

    **Scan types:**
    - all: Run all available scanners
    - semgrep: SAST code scanning
    - pip_audit: Dependency vulnerability scanning

    Results are automatically imported to the vulnerability tracker.
    """,
)
async def trigger_scan(
    scan_request: ScanRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> ScanResponse:
    """
    Trigger vulnerability scan (admin only).

    Args:
        scan_request: Scan configuration
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Scan results with import statistics
    """
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

    # Run scan
    vulnerabilities = run_all_scans(code_path=scan_path)

    # Import results if requested
    import_stats = None
    if scan_request.auto_import:
        tracker = get_vuln_tracker()
        import_stats = tracker.import_scan_results(vulnerabilities)

    return ScanResponse(
        scan_type=scan_request.scan_type,
        vulnerabilities_found=len(vulnerabilities),
        imported=scan_request.auto_import,
        import_stats=import_stats,
    )


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities",
    description="""
    List vulnerabilities with optional filters.

    **Filters:**
    - status: open, in_progress, resolved, accepted, false_positive
    - severity: info, low, medium, high, critical
    - source: semgrep, pip_audit, manual, pentest
    - limit: max results (default 100)
    - offset: pagination offset (default 0)

    **Permissions:**
    - Admin/Auditor: can view all vulnerabilities
    - Other users: can view vulnerabilities assigned to them
    """,
)
async def list_vulnerabilities(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    severity_filter: str | None = Query(None, alias="severity", description="Filter by severity"),
    source_filter: str | None = Query(None, alias="source", description="Filter by source"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> VulnerabilityListResponse:
    """
    List vulnerabilities with optional filters.

    Args:
        current_user: Authenticated user
        status_filter: Optional status filter
        severity_filter: Optional severity filter
        source_filter: Optional source filter
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        List of vulnerabilities and total count
    """
    # Parse filters
    status_enum = None
    if status_filter:
        try:
            status_enum = VulnStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}",
            )

    severity_enum = None
    if severity_filter:
        try:
            severity_enum = VulnSeverity(severity_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity_filter}",
            )

    source_enum = None
    if source_filter:
        try:
            source_enum = VulnSource(source_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid source: {source_filter}",
            )

    # Query vulnerabilities
    repo = get_vuln_repository()

    from pdfsigner.core.users import UserRole

    is_privileged = current_user.role in {UserRole.ADMIN, UserRole.AUDITOR}

    if is_privileged:
        vulnerabilities = repo.list_vulnerabilities(
            status=status_enum,
            severity=severity_enum,
            source=source_enum,
            limit=limit,
            offset=offset,
        )
        total = len(vulnerabilities)
    else:
        # For non-admin users, fetch all matching results without pagination
        # and filter by assignee before applying pagination
        all_vulns = repo.list_vulnerabilities(
            status=status_enum,
            severity=severity_enum,
            source=source_enum,
            limit=10000,
            offset=0,
        )
        user_vulns = [v for v in all_vulns if v.assignee == current_user.username]
        total = len(user_vulns)
        vulnerabilities = user_vulns[offset : offset + limit]

    logger.debug(f"Listed {len(vulnerabilities)} vulnerabilities for user {current_user.username}")

    return VulnerabilityListResponse(
        vulnerabilities=[_vuln_to_response(v) for v in vulnerabilities],
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
    """
    Get vulnerability by ID.

    Args:
        vuln_id: Vulnerability ID
        current_user: Authenticated user

    Returns:
        Vulnerability details

    Raises:
        HTTPException: 404 if vulnerability not found
        HTTPException: 403 if user cannot access this vulnerability
    """
    repo = get_vuln_repository()
    vuln = repo.get_vulnerability(vuln_id)

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability not found: {vuln_id}",
        )

    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.role not in {UserRole.ADMIN, UserRole.AUDITOR}:
        if vuln.assignee != current_user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only view vulnerabilities assigned to you",
            )

    return _vuln_to_response(vuln)


@router.post(
    "/vulnerabilities",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create vulnerability manually",
    description="""
    Create a vulnerability manually (admin only).

    Useful for recording vulnerabilities discovered through:
    - Penetration testing
    - Manual code review
    - External security reports
    """,
)
async def create_vulnerability(
    vuln_create: VulnerabilityCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> VulnerabilityResponse:
    """
    Create vulnerability manually (admin only).

    Args:
        vuln_create: Vulnerability data
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Created vulnerability
    """
    # Create vulnerability
    vuln = Vulnerability(
        title=vuln_create.title,
        description=vuln_create.description,
        severity=VulnSeverity(vuln_create.severity),
        source=VulnSource.MANUAL,
        file_path=vuln_create.file_path,
        line_number=vuln_create.line_number,
        cwe_id=vuln_create.cwe_id,
        cvss_score=vuln_create.cvss_score,
        assignee=vuln_create.assignee,
        remediation=vuln_create.remediation,
    )

    # Save
    tracker = get_vuln_tracker()
    saved_vuln = tracker.add_vulnerability(vuln)

    logger.info(f"User {current_user.username} created vulnerability {saved_vuln.id}")

    return _vuln_to_response(saved_vuln)


@router.patch(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Update vulnerability",
    description="""
    Update vulnerability status, assignee, or notes.

    **Updatable fields:**
    - status
    - assignee
    - notes (added to audit trail)

    Status changes are tracked in the vulnerability's history.
    """,
)
async def update_vulnerability(
    vuln_id: str,
    vuln_update: VulnerabilityUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> VulnerabilityResponse:
    """
    Update vulnerability status/assignee.

    Args:
        vuln_id: Vulnerability ID
        vuln_update: Update fields
        current_user: Authenticated user

    Returns:
        Updated vulnerability

    Raises:
        HTTPException: 404 if vulnerability not found
        HTTPException: 403 if user cannot update this vulnerability
    """
    # Check if vulnerability exists
    repo = get_vuln_repository()
    vuln = repo.get_vulnerability(vuln_id)

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability not found: {vuln_id}",
        )

    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.role not in {UserRole.ADMIN, UserRole.AUDITOR}:
        if vuln.assignee != current_user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update vulnerabilities assigned to you",
            )

    # Update status
    tracker = get_vuln_tracker()
    if vuln_update.status:
        new_status = VulnStatus(vuln_update.status)
        tracker.update_status(
            vuln_id,
            new_status,
            notes=vuln_update.notes,
            assignee=vuln_update.assignee,
        )
    elif vuln_update.assignee:
        tracker.assign_vulnerability(vuln_id, vuln_update.assignee)

    # Get updated vulnerability
    updated_vuln = repo.get_vulnerability(vuln_id)

    if not updated_vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    logger.info(f"User {current_user.username} updated vulnerability {vuln_id}")

    return _vuln_to_response(updated_vuln)


@router.get(
    "/vulnerabilities/report",
    response_model=VulnerabilityReport,
    summary="Get vulnerability report",
    description="""
    Get vulnerability summary report with statistics.

    Includes:
    - Total vulnerability counts
    - Breakdown by severity and status
    - Open high/critical vulnerabilities
    - Overdue vulnerabilities (30+ days)
    - Overall risk score (0-100)
    """,
)
async def get_vulnerability_report(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> VulnerabilityReport:
    """
    Get vulnerability summary report.

    Args:
        current_user: Authenticated user

    Returns:
        Vulnerability report with statistics
    """
    reporter = get_vuln_reporter()
    report = reporter.generate_summary_report()

    logger.debug(f"Generated vulnerability report for user {current_user.username}")

    return VulnerabilityReport(**report)


@router.get(
    "/vulnerabilities/export/csv",
    response_class=PlainTextResponse,
    summary="Export vulnerabilities to CSV",
    description="""
    Export vulnerabilities to CSV format (admin/auditor only).

    CSV includes:
    - ID, Title, Severity, Status, Source
    - File path, Line number
    - CWE, CVSS score
    - Discovery/resolution dates
    - Days open, Assignee
    """,
)
async def export_vulnerabilities_csv(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
    severity_filter: str | None = Query(None, alias="severity", description="Filter by severity"),
) -> PlainTextResponse:
    """
    Export vulnerabilities to CSV (admin/auditor only).

    Args:
        current_user: Authenticated user
        _perm: Permission check dependency
        severity_filter: Optional severity filter

    Returns:
        CSV file content
    """
    # Parse severity filter
    severity_enum = None
    if severity_filter:
        try:
            severity_enum = VulnSeverity(severity_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity_filter}",
            )

    # Export to CSV
    reporter = get_vuln_reporter()
    csv_content = reporter.export_to_csv(severity=severity_enum)

    logger.info(f"User {current_user.username} exported vulnerabilities to CSV")

    return PlainTextResponse(content=csv_content, media_type="text/csv")


@router.post(
    "/vulnerabilities/import",
    response_model=dict,
    summary="Import scan results",
    description="""
    Import vulnerability scan results (admin only).

    Accepts list of vulnerabilities and:
    - Deduplicates against existing vulnerabilities
    - Updates severity if changed
    - Reopens previously closed vulnerabilities if found again
    - Tracks import statistics
    """,
)
async def import_vulnerabilities(
    vulnerabilities: list[VulnerabilityCreate],
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> dict:
    """
    Import vulnerability scan results (admin only).

    Args:
        vulnerabilities: List of vulnerabilities to import
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Import statistics
    """
    # Convert to Vulnerability objects
    vuln_objects = []
    for v in vulnerabilities:
        vuln = Vulnerability(
            title=v.title,
            description=v.description,
            severity=VulnSeverity(v.severity),
            source=VulnSource.MANUAL,
            file_path=v.file_path,
            line_number=v.line_number,
            cwe_id=v.cwe_id,
            cvss_score=v.cvss_score,
            assignee=v.assignee,
            remediation=v.remediation,
        )
        vuln_objects.append(vuln)

    # Import
    tracker = get_vuln_tracker()
    stats = tracker.import_scan_results(vuln_objects)

    logger.info(f"User {current_user.username} imported {len(vulnerabilities)} vulnerabilities")

    return {
        "message": "Import completed successfully",
        "statistics": stats,
    }


# --- Public Exports ---

__all__ = ["router"]

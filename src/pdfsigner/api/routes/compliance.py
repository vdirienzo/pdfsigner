"""
Compliance monitoring routes.

Provides endpoints for monitoring HIPAA compliance status and generating reports.
"""

import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.compliance import (
    AvailableStandardsResponse,
    ComplianceCheckResponse,
    ComplianceReportResponse,
    GeneratedReportResponse,
    ReportGenerationRequest,
)
from pdfsigner.core.rbac.authorization import check_permission
from pdfsigner.core.rbac.permissions import Permission

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

# Store generated reports temporarily (in production, use proper storage)
_generated_reports: dict[str, Path] = {}


@router.get(
    "/status",
    response_model=ComplianceReportResponse,
    summary="Get HIPAA compliance status",
    description="""
    Get current HIPAA compliance status for all implemented controls.

    Checks the following HIPAA requirements:
    - §164.312(a)(2)(iv) - Encryption and decryption
    - §164.312(b) - Audit controls with integrity protection
    - §164.312(a)(1) - Access control (RBAC)
    - §164.312(a)(2)(iii) - Automatic logoff
    - §164.310(d)(1) - Secure deletion of temporary files
    - §164.514 - PHI detection
    - §164.312(a)(2)(ii) - Emergency access procedure

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def get_compliance_status(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> ComplianceReportResponse:
    """
    Get current HIPAA compliance status.

    Args:
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Compliance report with status of all checks
    """
    from pdfsigner.core.compliance import get_compliance_checker

    checker = get_compliance_checker()
    report = checker.check_all()

    return ComplianceReportResponse(
        checks=[ComplianceCheckResponse(**c.to_dict()) for c in report.checks],
        overall_status=report.overall_status.value,
        compliant_count=report.compliant_count,
        warning_count=report.warning_count,
        non_compliant_count=report.non_compliant_count,
        is_hipaa_compliant=report.is_hipaa_compliant,
        generated_at=report.generated_at,
    )


@router.post(
    "/check",
    response_model=ComplianceReportResponse,
    summary="Run compliance check",
    description="""
    Perform a fresh compliance check and return the results.

    This is equivalent to GET /status but explicitly triggers a new check.
    Useful for automation and scheduled assessments.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def run_compliance_check(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> ComplianceReportResponse:
    """
    Run compliance check.

    Args:
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Fresh compliance report
    """
    from pdfsigner.core.compliance import get_compliance_checker

    checker = get_compliance_checker()
    report = checker.check_all()

    return ComplianceReportResponse(
        checks=[ComplianceCheckResponse(**c.to_dict()) for c in report.checks],
        overall_status=report.overall_status.value,
        compliant_count=report.compliant_count,
        warning_count=report.warning_count,
        non_compliant_count=report.non_compliant_count,
        is_hipaa_compliant=report.is_hipaa_compliant,
        generated_at=report.generated_at,
    )


@router.post(
    "/report",
    response_model=GeneratedReportResponse,
    summary="Generate compliance report",
    description="""
    Generate a compliance report in the specified format (PDF, JSON, CSV, or CEF).

    Supported formats:
    - **PDF**: Professional report with executive summary and charts
    - **JSON**: Full structured data for programmatic access
    - **CSV**: Controls matrix for spreadsheet analysis
    - **CEF**: Common Event Format for SIEM integration

    The generated report is stored temporarily and can be downloaded using the
    returned download_url.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def generate_compliance_report(
    request: ReportGenerationRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> GeneratedReportResponse:
    """
    Generate compliance report.

    Args:
        request: Report generation request with format and options
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        Generated report metadata with download URL

    Raises:
        HTTPException: 400 if format is invalid
        HTTPException: 500 if report generation fails
    """
    from datetime import datetime

    from pdfsigner.core.compliance.report_generator import (
        ReportConfig,
        ReportFormat,
        get_report_generator,
    )

    try:
        # Parse format
        report_format = ReportFormat(request.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {request.format}. Must be one of: pdf, json, csv, cef",
        )

    # Create config
    config = ReportConfig(
        format=report_format,
        standards=request.standards,
        include_evidence=request.include_evidence,
        include_recommendations=request.include_recommendations,
        executive_summary=request.executive_summary,
    )

    # Generate report
    try:
        generator = get_report_generator()

        # Create temp file for report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_id = f"{timestamp}_{report_format.value}"
        temp_dir = Path(tempfile.gettempdir()) / "pdfsigner_reports"
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Determine file extension
        extensions = {
            ReportFormat.PDF: "pdf",
            ReportFormat.JSON: "json",
            ReportFormat.CSV: "csv",
            ReportFormat.CEF: "cef",
        }
        ext = extensions.get(report_format, "txt")
        output_path = temp_dir / f"{report_id}.{ext}"

        # Generate
        report_metadata = generator.generate(config, output_path)

        # Store for download
        _generated_reports[report_id] = report_metadata.path

        return GeneratedReportResponse(
            report_id=report_id,
            format=report_format.value,
            size_bytes=report_metadata.size_bytes,
            generated_at=report_metadata.generated_at,
            checksum=report_metadata.checksum,
            download_url=f"/api/v1/compliance/report/{report_id}",
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}",
        )


@router.get(
    "/report/{report_id}",
    summary="Download compliance report",
    description="""
    Download a previously generated compliance report.

    The report must have been generated using POST /compliance/report within
    the current session. Reports are stored temporarily and may be cleaned up
    after the session ends.

    Requires AUDIT_VIEW permission (auditor role or higher).
    """,
)
async def download_compliance_report(
    report_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> FileResponse:
    """
    Download compliance report.

    Args:
        report_id: Report ID from generate_compliance_report
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        File response with report content

    Raises:
        HTTPException: 404 if report not found
    """
    if report_id not in _generated_reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found: {report_id}",
        )

    report_path = _generated_reports[report_id]

    if not report_path.exists():
        # Clean up stale entry
        del _generated_reports[report_id]
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file not found: {report_id}",
        )

    # Determine media type
    media_types = {
        ".pdf": "application/pdf",
        ".json": "application/json",
        ".csv": "text/csv",
        ".cef": "text/plain",
    }
    media_type = media_types.get(report_path.suffix, "application/octet-stream")

    return FileResponse(
        path=str(report_path),
        media_type=media_type,
        filename=report_path.name,
    )


@router.get(
    "/standards",
    response_model=AvailableStandardsResponse,
    summary="List available standards",
    description="""
    Get list of available compliance standards that can be assessed.

    Currently supports:
    - HIPAA: Health Insurance Portability and Accountability Act
    - eIDAS: Electronic Identification, Authentication and Trust Services (EU 910/2014)

    Future standards may include:
    - NIST 800-53: Security and Privacy Controls
    - GDPR: General Data Protection Regulation
    """,
)
async def list_available_standards(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> AvailableStandardsResponse:
    """
    List available compliance standards.

    Args:
        current_user: Authenticated user (from JWT or API key)
        _perm: Permission check dependency (AUDIT_VIEW required)

    Returns:
        List of available standards
    """
    return AvailableStandardsResponse(standards=["HIPAA", "eIDAS"])


__all__ = ["router"]

"""
Evidence collection service for SOC 2 compliance.

Business logic for evidence collection, SOC 2 report generation,
and evidence package export.
"""

import hashlib
import json
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.api.schemas.evidence import (
    ControlAssessmentResponse,
    EvidenceCollectionResponse,
    EvidenceItemResponse,
    SOC2ExportResponse,
    SOC2ReportResponse,
)
from pdfsigner.core.compliance import generate_report, get_evidence_collector

# Store generated exports temporarily (in production, use proper storage)
_generated_exports: dict[str, Path] = {}
_export_timestamps: dict[str, float] = {}
_MAX_EXPORTS = 1000
_EXPORT_TTL_SECONDS = 86400  # 24 hours


def cleanup_old_exports() -> None:
    """Remove expired export entries."""
    now = time.time()
    expired = [k for k, t in _export_timestamps.items() if now - t > _EXPORT_TTL_SECONDS]
    for k in expired:
        _generated_exports.pop(k, None)
        _export_timestamps.pop(k, None)


def collect_evidence(
    period_start: datetime, period_end: datetime, username: str
) -> EvidenceCollectionResponse:
    """Collect SOC 2 evidence for a specified period.

    Args:
        period_start: Start of the evidence period
        period_end: End of the evidence period
        username: Username requesting the collection

    Returns:
        EvidenceCollectionResponse with collected items

    Raises:
        RuntimeError: If collection fails
    """
    collector = get_evidence_collector()
    logger.info(
        f"Collecting evidence from {period_start} to {period_end} (requested by {username})"
    )

    collection = collector.collect_all_evidence(period_start, period_end)

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


def generate_soc2_report(
    period_start: datetime, period_end: datetime, username: str
) -> SOC2ReportResponse:
    """Generate a SOC 2 Type II compliance report.

    Args:
        period_start: Start of the report period
        period_end: End of the report period
        username: Username requesting the report

    Returns:
        SOC2ReportResponse with report data

    Raises:
        RuntimeError: If report generation fails
    """
    collector = get_evidence_collector()
    logger.info(
        f"Generating SOC 2 report from {period_start} to {period_end} (requested by {username})"
    )

    collection = collector.collect_all_evidence(period_start, period_end)
    report = generate_report(
        evidence_list=collection.evidence_items,
        period_start=period_start,
        period_end=period_end,
    )

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


def export_soc2_package(period_start: str, period_end: str, username: str) -> SOC2ExportResponse:
    """Export SOC 2 evidence package as ZIP.

    Args:
        period_start: Period start (ISO 8601 string)
        period_end: Period end (ISO 8601 string)
        username: Username requesting the export

    Returns:
        SOC2ExportResponse with download info

    Raises:
        ValueError: If date format is invalid or range is wrong
        RuntimeError: If export fails
    """
    # Parse dates
    start_dt = datetime.fromisoformat(period_start.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(period_end.replace("Z", "+00:00"))

    if end_dt <= start_dt:
        raise ValueError("period_end must be after period_start")

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
        report_md = report.export_to_markdown()
        zipf.writestr("soc2_report.md", report_md)

        report_json = json.dumps(report.to_dict(), indent=2)
        zipf.writestr("soc2_report.json", report_json)

        evidence_json = json.dumps(collection.to_dict(), indent=2)
        zipf.writestr("evidence_collection.json", evidence_json)

        readme = f"""# SOC 2 Type II Evidence Package

Period: {start_dt.date()} to {end_dt.date()}
Generated: {datetime.now(UTC).isoformat()}
Generated by: {username}

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
    cleanup_old_exports()
    _export_timestamps[filename] = time.time()
    _generated_exports[filename] = zip_path

    return SOC2ExportResponse(
        filename=filename,
        size_bytes=zip_path.stat().st_size,
        generated_at=datetime.now(UTC),
        checksum=checksum,
        download_url=f"/api/v1/compliance/evidence/export/{filename}",
    )


def get_export_path(filename: str) -> Path:
    """Get path to an exported file.

    Args:
        filename: Export filename

    Returns:
        Path to the export file

    Raises:
        LookupError: If export not found
        FileNotFoundError: If file was deleted
    """
    if filename not in _generated_exports:
        raise LookupError(f"Export not found: {filename}")

    export_path = _generated_exports[filename]

    if not export_path.exists():
        del _generated_exports[filename]
        raise FileNotFoundError(f"Export file not found: {filename}")

    return export_path


__all__ = [
    "cleanup_old_exports",
    "collect_evidence",
    "export_soc2_package",
    "generate_soc2_report",
    "get_export_path",
]

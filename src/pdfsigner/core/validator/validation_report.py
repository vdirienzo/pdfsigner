"""
validation_report.py - eIDAS signature validation report generator

Generates structured validation reports inspired by ETSI TS 119 102-2 V1.4.1.
Reports are produced in JSON format suitable for API responses and auditing.

Standards referenced:
- ETSI TS 119 102-2 V1.4.1 (Signature Validation Report)
- ETSI EN 319 102-1 V1.4.1 (Validation procedures - MainIndication/SubIndication)
- CIR (EU) 2025/1945 (Revocation freshness: 24h max)
- SOGIS v1.3 (Algorithm strength classification)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pdfsigner.core.validator.eidas_validator import ValidationStatus
from pdfsigner.core.validator.pdf_validator import ValidationResult
from pdfsigner.core.validator.validation_report_builders import build_signature_report
from pdfsigner.core.validator.validation_report_types import SubIndication

# Re-export for backward compatibility
__all__ = [
    "SubIndication",
    "generate_eidas_report",
    "generate_eidas_report_json",
]


# --- Overall report helpers ---


def _determine_overall_indication(
    validation_result: ValidationResult,
    signature_reports: list[dict[str, Any]],
) -> tuple[str, str | None]:
    """Determine overall document indication and sub-indication.

    Args:
        validation_result: Result from PDFValidator.validate()
        signature_reports: List of per-signature report dicts

    Returns:
        Tuple of (main_indication, sub_indication)
    """
    if not validation_result.is_signed:
        return ValidationStatus.INDETERMINATE.value, SubIndication.SIGNED_DATA_NOT_FOUND.value

    if validation_result.all_valid:
        has_revocation_issue = any(
            sig.revocation_status == "revoked" for sig in validation_result.signatures
        )
        if has_revocation_issue:
            return ValidationStatus.TOTAL_FAILED.value, SubIndication.REVOKED.value
        return ValidationStatus.TOTAL_PASSED.value, None

    # Find first failing sub-indication
    overall_sub = None
    for report in signature_reports:
        if report["main_indication"] != ValidationStatus.TOTAL_PASSED.value:
            overall_sub = report["sub_indication"]
            break
    return ValidationStatus.TOTAL_FAILED.value, overall_sub


def _determine_highest_quality(signature_reports: list[dict[str, Any]]) -> str:
    """Determine highest eIDAS qualification level across signatures.

    Args:
        signature_reports: List of per-signature report dicts

    Returns:
        Highest quality string: "QES", "AdES-QC", "AdES", or "Basic"
    """
    quality_hierarchy = {"QES": 3, "AdES-QC": 2, "AdES": 1, "Basic": 0}
    highest_quality = "Basic"
    for report in signature_reports:
        quality = report.get("signature_quality", "Basic")
        if quality_hierarchy.get(quality, 0) > quality_hierarchy.get(highest_quality, 0):
            highest_quality = quality
    return highest_quality


def _collect_report_issues(
    validation_result: ValidationResult,
    signature_reports: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Collect and deduplicate issues and recommendations from all signatures.

    Args:
        validation_result: Result from PDFValidator.validate()
        signature_reports: List of per-signature report dicts

    Returns:
        Tuple of (all_issues, unique_recommendations)
    """
    all_issues: list[str] = []
    all_recommendations: list[str] = []

    if validation_result.error:
        all_issues.append(validation_result.error)

    for report in signature_reports:
        all_issues.extend(report.get("issues", []))
        all_recommendations.extend(report.get("recommendations", []))

    # Deduplicate recommendations preserving order
    seen: set[str] = set()
    unique_recommendations: list[str] = []
    for rec in all_recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)

    return all_issues, unique_recommendations


# --- Public API ---


def generate_eidas_report(
    validation_result: ValidationResult,
    pdf_path: Path | str,
) -> dict[str, Any]:
    """Generate a structured eIDAS validation report.

    Produces a JSON-serializable report inspired by ETSI TS 119 102-2
    containing MainIndication, SubIndication, algorithm assessment,
    revocation freshness, and eIDAS qualification level for each signature.

    Args:
        validation_result: Result from PDFValidator.validate()
        pdf_path: Path to the validated PDF

    Returns:
        Dictionary with full eIDAS validation report
    """
    pdf_path = Path(pdf_path)
    now = datetime.now(UTC)

    signature_reports = [build_signature_report(sig) for sig in validation_result.signatures]
    overall_indication, overall_sub = _determine_overall_indication(
        validation_result, signature_reports
    )
    highest_quality = _determine_highest_quality(signature_reports)
    all_issues, unique_recommendations = _collect_report_issues(
        validation_result, signature_reports
    )

    return {
        "report_version": "1.0",
        "standard": "ETSI TS 119 102-2 V1.4.1",
        "validation_time": now.isoformat(),
        "document": {
            "filename": pdf_path.name,
            "path": str(pdf_path),
            "is_signed": validation_result.is_signed,
            "signature_count": validation_result.signature_count,
        },
        "overall": {
            "main_indication": overall_indication,
            "sub_indication": overall_sub,
            "eidas_level": highest_quality,
        },
        "signatures": signature_reports,
        "issues": all_issues,
        "recommendations": unique_recommendations,
    }


def generate_eidas_report_json(
    validation_result: ValidationResult,
    pdf_path: Path | str,
    indent: int = 2,
) -> str:
    """Generate eIDAS validation report as formatted JSON string.

    Args:
        validation_result: Result from PDFValidator.validate()
        pdf_path: Path to the validated PDF
        indent: JSON indentation level (default: 2)

    Returns:
        Formatted JSON string of the eIDAS report
    """
    report = generate_eidas_report(validation_result, pdf_path)
    return json.dumps(report, indent=indent, ensure_ascii=False, default=str)

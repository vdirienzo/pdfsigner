"""
soc2_export.py - SOC 2 report markdown export functions

Extracted from soc2_report.py to keep modules under 400 lines.
Contains Markdown section builders and control definition builders.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pdfsigner.core.compliance.evidence_types import Evidence, EvidenceCategory
from pdfsigner.core.compliance.soc2_types import ControlAssessment, ControlStatus

if TYPE_CHECKING:
    from pdfsigner.core.compliance.soc2_report import SOC2Report


# ============================================================================
# Markdown section builders
# ============================================================================

_STATUS_ICONS = {
    "implemented": "\u2705",
    "partial": "\u26a0\ufe0f",
    "not_implemented": "\u274c",
    "not_applicable": "\u2796",
}


def build_md_header(report: SOC2Report) -> list[str]:
    """Build the Markdown header with title and period info."""
    return [
        "# SOC 2 Type II Compliance Report",
        "",
        f"**Period:** {report.period_start.date()} to {report.period_end.date()}",
        f"**Generated:** {report.generated_at.isoformat()}",
        "",
        "## Executive Summary",
        "",
    ]


def build_md_summary(report: SOC2Report, lines: list[str]) -> None:
    """Append executive summary statistics to lines."""
    if not report.summary:
        return
    lines.append(f"- **Total Controls:** {report.summary.get('total_controls', 0)}")
    lines.append(f"- **Implemented:** {report.summary.get('implemented', 0)}")
    lines.append(f"- **Partial:** {report.summary.get('partial', 0)}")
    lines.append(f"- **Not Implemented:** {report.summary.get('not_implemented', 0)}")
    lines.append(f"- **Coverage:** {report.summary.get('coverage_percentage', 0):.1f}%")
    lines.append("")


def build_md_control_detail(control: ControlAssessment, lines: list[str]) -> None:
    """Append a single control's Markdown block to lines."""
    icon = _STATUS_ICONS.get(control.status.value, "")
    lines.append(f"#### {icon} {control.control_id}: {control.control_name}")
    lines.append("")
    lines.append(f"**Status:** {control.status.value}")
    lines.append("")
    lines.append(f"**Description:** {control.description}")
    lines.append("")
    lines.append(f"**Implementation:** {control.implementation}")
    lines.append("")

    if control.evidence_ids:
        evidence_preview = ", ".join(control.evidence_ids[:3])
        lines.append(f"**Evidence:** {len(control.evidence_ids)} item(s) - {evidence_preview}")
        lines.append("")

    if control.gaps:
        lines.append("**Gaps:**")
        for gap in control.gaps:
            lines.append(f"- {gap}")
        lines.append("")

    if control.notes:
        lines.append(f"**Notes:** {control.notes}")
        lines.append("")


def build_md_controls(report: SOC2Report, lines: list[str]) -> None:
    """Append all controls assessment section grouped by category."""
    lines.append("## Controls Assessment")
    lines.append("")

    for category in EvidenceCategory:
        controls = report.get_controls_by_category(category)
        if not controls:
            continue
        lines.append(f"### {category.value.upper()}")
        lines.append("")
        for control in controls:
            build_md_control_detail(control, lines)


def build_md_recommendations(report: SOC2Report, lines: list[str]) -> None:
    """Append recommendations section."""
    if not report.recommendations:
        return
    lines.append("## Recommendations")
    lines.append("")
    for i, rec in enumerate(report.recommendations, 1):
        lines.append(f"{i}. {rec}")
    lines.append("")


def build_md_evidence_summary(report: SOC2Report, lines: list[str]) -> None:
    """Append evidence summary section."""
    lines.append("## Evidence Summary")
    lines.append("")
    lines.append(f"Total evidence items collected: {len(report.evidence)}")
    lines.append("")

    by_category: dict[str, int] = {}
    for evidence in report.evidence:
        cat = evidence.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    lines.append("Evidence by category:")
    for cat, count in sorted(by_category.items()):
        lines.append(f"- {cat}: {count} item(s)")
    lines.append("")


# ============================================================================
# Report generation: control definitions
# ============================================================================


def build_evidence_index(
    evidence_list: list[Evidence],
) -> dict[EvidenceCategory, list[str]]:
    """Build evidence index keyed by category."""
    evidence_by_category: dict[EvidenceCategory, list[str]] = {}
    for evidence in evidence_list:
        if evidence.category not in evidence_by_category:
            evidence_by_category[evidence.category] = []
        evidence_by_category[evidence.category].append(evidence.id)
    return evidence_by_category


def calculate_summary(
    controls: list[ControlAssessment],
    evidence_count: int,
) -> dict[str, Any]:
    """Calculate summary statistics from control assessments."""
    status_counts = {
        ControlStatus.IMPLEMENTED: 0,
        ControlStatus.PARTIAL: 0,
        ControlStatus.NOT_IMPLEMENTED: 0,
        ControlStatus.NOT_APPLICABLE: 0,
    }
    for control in controls:
        status_counts[control.status] += 1

    total = len(controls)
    implemented = status_counts[ControlStatus.IMPLEMENTED]
    partial = status_counts[ControlStatus.PARTIAL]
    coverage = ((implemented + partial * 0.5) / total * 100) if total > 0 else 0

    return {
        "total_controls": total,
        "implemented": implemented,
        "partial": partial,
        "not_implemented": status_counts[ControlStatus.NOT_IMPLEMENTED],
        "not_applicable": status_counts[ControlStatus.NOT_APPLICABLE],
        "coverage_percentage": coverage,
        "total_evidence": evidence_count,
    }


def generate_recommendations(
    controls: list[ControlAssessment],
    summary: dict[str, Any],
    evidence_count: int,
) -> list[str]:
    """Generate recommendations based on control gaps and evidence."""
    recommendations: list[str] = []

    for control in controls:
        if control.status == ControlStatus.PARTIAL and control.gaps:
            for gap in control.gaps:
                recommendations.append(f"{control.control_id}: {gap}")

    not_impl = summary.get("not_implemented", 0)
    if not_impl > 0:
        recommendations.append(f"Implement {not_impl} missing control(s)")

    if evidence_count < 5:
        recommendations.append(
            "Increase evidence collection frequency to improve audit trail coverage"
        )

    return recommendations

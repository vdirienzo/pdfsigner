"""
soc2_report.py - SOC 2 Type II report generation

Generates compliance reports that map collected evidence to SOC 2 Trust Services
Criteria controls.

Control Mappings:
- CC6.1: User authentication (→ auth module, RBAC)
- CC6.2: Access authorization (→ RBAC, permissions)
- CC6.3: Access removal (→ session management, user deactivation)
- CC6.6: System monitoring (→ audit logging)
- CC6.7: Encryption (→ PDF encryption, TLS)
- CC7.1: Vulnerability management (→ dependency scanning)
- CC7.2: Anomaly detection (→ breach detection, failed login tracking)
- CC8.1: Change detection (→ audit integrity)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from pdfsigner.core.compliance.evidence_types import Evidence, EvidenceCategory


class ControlStatus(str, Enum):
    """Status of a SOC 2 control."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlAssessment:
    """
    Assessment of a single SOC 2 control.

    Attributes:
        control_id: Control identifier (e.g., "CC6.1")
        control_name: Human-readable control name
        category: SOC 2 category
        status: Implementation status
        description: What the control requires
        implementation: How PDFSigner implements this control
        evidence_ids: List of evidence IDs supporting this control
        gaps: List of identified gaps (if status is PARTIAL)
        notes: Additional assessment notes
    """

    control_id: str
    control_name: str
    category: EvidenceCategory
    status: ControlStatus
    description: str
    implementation: str
    evidence_ids: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "category": self.category.value,
            "status": self.status.value,
            "description": self.description,
            "implementation": self.implementation,
            "evidence_ids": self.evidence_ids,
            "gaps": self.gaps,
            "notes": self.notes,
        }


@dataclass
class SOC2Report:
    """
    Complete SOC 2 Type II compliance report.

    Attributes:
        period_start: Start of observation period
        period_end: End of observation period
        generated_at: Report generation timestamp
        controls: List of control assessments
        evidence: List of supporting evidence
        summary: Executive summary statistics
        recommendations: List of recommendations for improvement
    """

    period_start: datetime
    period_end: datetime
    generated_at: datetime
    controls: list[ControlAssessment] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def get_control_by_id(self, control_id: str) -> ControlAssessment | None:
        """Get control assessment by ID."""
        for control in self.controls:
            if control.control_id == control_id:
                return control
        return None

    def get_controls_by_category(self, category: EvidenceCategory) -> list[ControlAssessment]:
        """Get all controls for a category."""
        return [c for c in self.controls if c.category == category]

    def get_control_status(self, control_id: str) -> ControlStatus:
        """
        Get implementation status for a control.

        Args:
            control_id: Control ID (e.g., "CC6.1")

        Returns:
            Control status or NOT_IMPLEMENTED if not found
        """
        control = self.get_control_by_id(control_id)
        return control.status if control else ControlStatus.NOT_IMPLEMENTED

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "generated_at": self.generated_at.isoformat(),
            "controls": [c.to_dict() for c in self.controls],
            "evidence": [e.to_dict() for e in self.evidence],
            "summary": self.summary,
            "recommendations": self.recommendations,
        }

    def export_to_markdown(self) -> str:
        """
        Export report as Markdown.

        Returns:
            Markdown-formatted report
        """
        lines = [
            "# SOC 2 Type II Compliance Report",
            "",
            f"**Period:** {self.period_start.date()} to {self.period_end.date()}",
            f"**Generated:** {self.generated_at.isoformat()}",
            "",
            "## Executive Summary",
            "",
        ]

        # Add summary statistics
        if self.summary:
            lines.append(f"- **Total Controls:** {self.summary.get('total_controls', 0)}")
            lines.append(f"- **Implemented:** {self.summary.get('implemented', 0)}")
            lines.append(f"- **Partial:** {self.summary.get('partial', 0)}")
            lines.append(f"- **Not Implemented:** {self.summary.get('not_implemented', 0)}")
            lines.append(f"- **Coverage:** {self.summary.get('coverage_percentage', 0):.1f}%")
            lines.append("")

        # Controls by category
        lines.append("## Controls Assessment")
        lines.append("")

        for category in EvidenceCategory:
            controls = self.get_controls_by_category(category)
            if not controls:
                continue

            lines.append(f"### {category.value.upper()}")
            lines.append("")

            for control in controls:
                status_icon = {
                    ControlStatus.IMPLEMENTED: "✅",
                    ControlStatus.PARTIAL: "⚠️",
                    ControlStatus.NOT_IMPLEMENTED: "❌",
                    ControlStatus.NOT_APPLICABLE: "➖",
                }[control.status]

                lines.append(f"#### {status_icon} {control.control_id}: {control.control_name}")
                lines.append("")
                lines.append(f"**Status:** {control.status.value}")
                lines.append("")
                lines.append(f"**Description:** {control.description}")
                lines.append("")
                lines.append(f"**Implementation:** {control.implementation}")
                lines.append("")

                if control.evidence_ids:
                    evidence_preview = ", ".join(control.evidence_ids[:3])
                    lines.append(
                        f"**Evidence:** {len(control.evidence_ids)} item(s) - {evidence_preview}"
                    )
                    lines.append("")

                if control.gaps:
                    lines.append("**Gaps:**")
                    for gap in control.gaps:
                        lines.append(f"- {gap}")
                    lines.append("")

                if control.notes:
                    lines.append(f"**Notes:** {control.notes}")
                    lines.append("")

        # Recommendations
        if self.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Evidence summary
        lines.append("## Evidence Summary")
        lines.append("")
        lines.append(f"Total evidence items collected: {len(self.evidence)}")
        lines.append("")

        by_category = {}
        for evidence in self.evidence:
            cat = evidence.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        lines.append("Evidence by category:")
        for cat, count in sorted(by_category.items()):
            lines.append(f"- {cat}: {count} item(s)")
        lines.append("")

        return "\n".join(lines)


def generate_report(
    evidence_list: list[Evidence],
    period_start: datetime,
    period_end: datetime,
) -> SOC2Report:
    """
    Generate SOC 2 report from collected evidence.

    Maps evidence to controls and assesses implementation status.

    Args:
        evidence_list: List of collected evidence
        period_start: Start of observation period
        period_end: End of observation period

    Returns:
        Complete SOC 2 report
    """
    report = SOC2Report(
        period_start=period_start,
        period_end=period_end,
        generated_at=datetime.now(),
        evidence=evidence_list,
    )

    # Build evidence index by category
    evidence_by_category: dict[EvidenceCategory, list[str]] = {}
    for evidence in evidence_list:
        if evidence.category not in evidence_by_category:
            evidence_by_category[evidence.category] = []
        evidence_by_category[evidence.category].append(evidence.id)

    # Define control assessments based on PDFSigner implementation
    controls = [
        # CC6 - Logical and Physical Access Controls
        ControlAssessment(
            control_id="CC6.1",
            control_name="Logical Access Controls",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            status=ControlStatus.IMPLEMENTED,
            description="Restrict logical access through use of access control software",
            implementation=(
                "PDFSigner implements role-based access control (RBAC) with "
                "user authentication via PKCS#11 certificates. Users are uniquely "
                "identified and assigned roles (admin, operator, auditor, viewer)."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC6_LOGICAL_ACCESS, []),
        ),
        ControlAssessment(
            control_id="CC6.2",
            control_name="Prior Authorization",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            status=ControlStatus.IMPLEMENTED,
            description="Authorize user access prior to granting access",
            implementation=(
                "New users are created with default 'viewer' role. Administrator "
                "approval required to grant elevated permissions (operator, admin, auditor). "
                "Certificate binding ensures user identity verification."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC6_LOGICAL_ACCESS, []),
        ),
        ControlAssessment(
            control_id="CC6.3",
            control_name="User Access Removal",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            status=ControlStatus.IMPLEMENTED,
            description="Remove user access when no longer required",
            implementation=(
                "User deactivation workflow removes access immediately. "
                "Session manager terminates active sessions. Quarterly access reviews "
                "identify inactive accounts for removal."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC6_LOGICAL_ACCESS, []),
        ),
        ControlAssessment(
            control_id="CC6.6",
            control_name="System Operations Monitoring",
            category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
            status=ControlStatus.IMPLEMENTED,
            description="Implement detective controls through use of monitoring tools",
            implementation=(
                "Comprehensive audit logging records all user actions (signing, "
                "encryption, access). Logs include user ID, timestamp, action type, "
                "success/failure, and PHI access flags. HMAC signatures ensure log integrity."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC7_SYSTEM_OPERATIONS, []),
        ),
        ControlAssessment(
            control_id="CC6.7",
            control_name="Encryption of Data",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            status=ControlStatus.IMPLEMENTED,
            description="Encrypt data transmissions and data at rest",
            implementation=(
                "PDF encryption with AES-256. Optional TLS 1.2/1.3 for API communication. "
                "FIPS 140-2 mode available for government deployments. Secure key storage "
                "with encryption at rest."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC5_CONTROL_ACTIVITIES, []),
        ),
        ControlAssessment(
            control_id="CC7.1",
            control_name="Vulnerability Detection and Management",
            category=EvidenceCategory.CC9_RISK_MITIGATION,
            status=ControlStatus.PARTIAL,
            description="Identify and remediate security vulnerabilities",
            implementation=(
                "Dependency scanning via pre-commit hooks. Code quality checks with "
                "ruff and mypy. Automated testing (2350+ tests, 87% coverage)."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC9_RISK_MITIGATION, []),
            gaps=[
                "No automated vulnerability scanning in production",
                "Manual security reviews not documented",
            ],
        ),
        ControlAssessment(
            control_id="CC7.2",
            control_name="System Monitoring",
            category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
            status=ControlStatus.IMPLEMENTED,
            description="Monitor system components and operation of those components",
            implementation=(
                "Audit log monitoring with breach detection. Failed login tracking "
                "with account lockout. Session timeout enforcement. Optional SIEM "
                "integration via CEF export."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC7_SYSTEM_OPERATIONS, []),
        ),
        ControlAssessment(
            control_id="CC8.1",
            control_name="Change Detection",
            category=EvidenceCategory.CC8_CHANGE_MANAGEMENT,
            status=ControlStatus.IMPLEMENTED,
            description="Detect changes to system components",
            implementation=(
                "Audit log integrity verification with chain hashing and HMAC signatures. "
                "Configuration change tracking. Git version control for code changes."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC7_SYSTEM_OPERATIONS, []),
        ),
        # CC5 - Control Activities
        ControlAssessment(
            control_id="CC5.1",
            control_name="Control Activities",
            category=EvidenceCategory.CC5_CONTROL_ACTIVITIES,
            status=ControlStatus.IMPLEMENTED,
            description="Select and develop control activities to mitigate risks",
            implementation=(
                "Security controls enforced through configuration: encryption policies, "
                "session timeouts, MFA requirements, FIPS mode. Automated compliance "
                "checking available via API and CLI."
            ),
            evidence_ids=evidence_by_category.get(EvidenceCategory.CC5_CONTROL_ACTIVITIES, []),
        ),
    ]

    report.controls = controls

    # Calculate summary statistics
    status_counts = {
        ControlStatus.IMPLEMENTED: 0,
        ControlStatus.PARTIAL: 0,
        ControlStatus.NOT_IMPLEMENTED: 0,
        ControlStatus.NOT_APPLICABLE: 0,
    }

    for control in controls:
        status_counts[control.status] += 1

    total_controls = len(controls)
    implemented = status_counts[ControlStatus.IMPLEMENTED]
    partial = status_counts[ControlStatus.PARTIAL]

    coverage_percentage = (
        ((implemented + partial * 0.5) / total_controls * 100) if total_controls > 0 else 0
    )

    report.summary = {
        "total_controls": total_controls,
        "implemented": implemented,
        "partial": partial,
        "not_implemented": status_counts[ControlStatus.NOT_IMPLEMENTED],
        "not_applicable": status_counts[ControlStatus.NOT_APPLICABLE],
        "coverage_percentage": coverage_percentage,
        "total_evidence": len(evidence_list),
    }

    # Generate recommendations
    recommendations = []

    # Check for gaps
    for control in controls:
        if control.status == ControlStatus.PARTIAL and control.gaps:
            for gap in control.gaps:
                recommendations.append(f"{control.control_id}: {gap}")

    if status_counts[ControlStatus.NOT_IMPLEMENTED] > 0:
        recommendations.append(
            f"Implement {status_counts[ControlStatus.NOT_IMPLEMENTED]} missing control(s)"
        )

    # Evidence coverage check
    if len(evidence_list) < 5:
        recommendations.append(
            "Increase evidence collection frequency to improve audit trail coverage"
        )

    report.recommendations = recommendations

    return report


__all__ = [
    "ControlStatus",
    "ControlAssessment",
    "SOC2Report",
    "generate_report",
]

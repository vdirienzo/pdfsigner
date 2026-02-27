"""
soc2_report.py - SOC 2 Type II report generation

Generates compliance reports mapping evidence to SOC 2 Trust Services Criteria.
Markdown export and summary helpers delegated to soc2_export.py.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pdfsigner.core.compliance.evidence_types import Evidence, EvidenceCategory
from pdfsigner.core.compliance.soc2_export import (
    build_evidence_index,
    build_md_controls,
    build_md_evidence_summary,
    build_md_header,
    build_md_recommendations,
    build_md_summary,
    calculate_summary,
    generate_recommendations,
)
from pdfsigner.core.compliance.soc2_types import ControlAssessment, ControlStatus


@dataclass
class SOC2Report:
    """Complete SOC 2 Type II compliance report."""

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
        """Get implementation status for a control."""
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
        """Export report as Markdown."""

        lines = build_md_header(self)
        build_md_summary(self, lines)
        build_md_controls(self, lines)
        build_md_recommendations(self, lines)
        build_md_evidence_summary(self, lines)
        return "\n".join(lines)


# ============================================================================
# Control definition builders
# ============================================================================


def _build_cc6_rbac_controls(cc6_ids: list[str]) -> list[ControlAssessment]:
    """Build CC6.1-CC6.3 RBAC access control assessments."""
    return [
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
            evidence_ids=cc6_ids,
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
            evidence_ids=cc6_ids,
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
            evidence_ids=cc6_ids,
        ),
    ]


def _build_cc6_encryption_control(cc5_ids: list[str]) -> ControlAssessment:
    """Build CC6.7 encryption control assessment."""
    return ControlAssessment(
        control_id="CC6.7",
        control_name="Encryption of Data",
        category=EvidenceCategory.CC6_LOGICAL_ACCESS,
        status=ControlStatus.IMPLEMENTED,
        description="Encrypt data transmissions and data at rest",
        implementation=(
            "PDF encryption with AES-256. Optional TLS 1.2/1.3 for API. "
            "FIPS 140-2 mode for government deployments."
        ),
        evidence_ids=cc5_ids,
    )


def _build_monitoring_and_vuln_controls(
    idx: dict[EvidenceCategory, list[str]],
) -> list[ControlAssessment]:
    """Build CC6.6, CC7.1, CC7.2 monitoring and vulnerability controls."""
    cc7_ids = idx.get(EvidenceCategory.CC7_SYSTEM_OPERATIONS, [])
    return [
        ControlAssessment(
            control_id="CC6.6",
            control_name="System Operations Monitoring",
            category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
            status=ControlStatus.IMPLEMENTED,
            description="Implement detective controls through use of monitoring tools",
            implementation=(
                "Comprehensive audit logging records all user actions. "
                "Logs include user ID, timestamp, action type, "
                "success/failure, and PHI access flags."
            ),
            evidence_ids=cc7_ids,
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
            evidence_ids=idx.get(EvidenceCategory.CC9_RISK_MITIGATION, []),
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
                "with account lockout. Session timeout enforcement."
            ),
            evidence_ids=cc7_ids,
        ),
    ]


def _build_change_and_control_activities(
    idx: dict[EvidenceCategory, list[str]],
) -> list[ControlAssessment]:
    """Build CC8.1 change detection and CC5.1 control activities."""
    cc7_ids = idx.get(EvidenceCategory.CC7_SYSTEM_OPERATIONS, [])
    return [
        ControlAssessment(
            control_id="CC8.1",
            control_name="Change Detection",
            category=EvidenceCategory.CC8_CHANGE_MANAGEMENT,
            status=ControlStatus.IMPLEMENTED,
            description="Detect changes to system components",
            implementation=(
                "Audit log integrity with chain hashing and HMAC. "
                "Configuration change tracking. Git version control."
            ),
            evidence_ids=cc7_ids,
        ),
        ControlAssessment(
            control_id="CC5.1",
            control_name="Control Activities",
            category=EvidenceCategory.CC5_CONTROL_ACTIVITIES,
            status=ControlStatus.IMPLEMENTED,
            description="Select and develop control activities to mitigate risks",
            implementation=(
                "Security controls enforced through configuration: encryption policies, "
                "session timeouts, MFA requirements, FIPS mode."
            ),
            evidence_ids=idx.get(EvidenceCategory.CC5_CONTROL_ACTIVITIES, []),
        ),
    ]


def generate_report(
    evidence_list: list[Evidence],
    period_start: datetime,
    period_end: datetime,
) -> SOC2Report:
    """Generate SOC 2 report from collected evidence."""

    report = SOC2Report(
        period_start=period_start,
        period_end=period_end,
        generated_at=datetime.now(UTC),
        evidence=evidence_list,
    )

    idx = build_evidence_index(evidence_list)
    cc6_ids = idx.get(EvidenceCategory.CC6_LOGICAL_ACCESS, [])
    cc5_ids = idx.get(EvidenceCategory.CC5_CONTROL_ACTIVITIES, [])

    report.controls = (
        _build_cc6_rbac_controls(cc6_ids)
        + [_build_cc6_encryption_control(cc5_ids)]
        + _build_monitoring_and_vuln_controls(idx)
        + _build_change_and_control_activities(idx)
    )

    report.summary = calculate_summary(report.controls, len(evidence_list))
    report.recommendations = generate_recommendations(
        report.controls, report.summary, len(evidence_list)
    )

    return report


__all__ = [
    "ControlStatus",
    "ControlAssessment",
    "SOC2Report",
    "generate_report",
]

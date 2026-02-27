"""
risk_assessment.py - SOC 2 CC3: Risk Assessment checks

Verifies risk assessment processes including:
- Risk identification and threat modeling
- Risk analysis and vulnerability assessment
- Risk mitigation strategies
- Continuous risk monitoring
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.controls import ControlStatus


@dataclass
class RiskAssessmentCheckResult:
    """Result of a risk assessment control check."""

    control_id: str
    status: ControlStatus
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


def _make_error_result(
    control_id: str, error: Exception, recommendation: str
) -> RiskAssessmentCheckResult:
    """Build a FAILED result from an exception."""
    return RiskAssessmentCheckResult(
        control_id=control_id,
        status=ControlStatus.FAILED,
        findings=[f"Check failed: {str(error)}"],
        evidence={},
        recommendations=[recommendation],
    )


class RiskAssessmentChecker:
    """
    Check CC3 Risk Assessment controls.

    Verifies risk identification, analysis, mitigation,
    and ongoing monitoring processes.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize risk assessment checker.

        Args:
            project_root: Project root directory (defaults to PDFSigner root)
        """
        self.project_root = project_root or self._detect_project_root()

    def _detect_project_root(self) -> Path:
        """Detect project root by looking for pyproject.toml."""
        current = Path(__file__).resolve()
        for parent in [current] + list(current.parents):
            if (parent / "pyproject.toml").exists():
                return parent
        return Path.cwd()

    # ------------------------------------------------------------------
    # CC3.1 - Risk Identification
    # ------------------------------------------------------------------

    def _find_security_md(
        self,
        findings: list[str],
        evidence: dict[str, Any],
    ) -> bool:
        """Locate SECURITY.md and analyse threat content. Returns True if found."""
        security_md_paths = [
            self.project_root / "docs" / "SECURITY.md",
            self.project_root / "SECURITY.md",
        ]

        for security_md_path in security_md_paths:
            if security_md_path.exists():
                evidence["security_md_path"] = str(security_md_path)
                content = security_md_path.read_text()
                has_threat_section = any(
                    keyword in content.lower() for keyword in ["threat", "risk", "vulnerability"]
                )
                evidence["has_threat_section"] = has_threat_section

                if has_threat_section:
                    findings.append("SECURITY.md documents known risks")
                else:
                    findings.append("SECURITY.md exists but lacks threat analysis")
                return True

        findings.append("SECURITY.md not found")
        return False

    def _check_threat_model_docs(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check for threat model and incident response plan."""
        threat_docs = [
            self.project_root / "docs" / "security" / "threat-model.md",
            self.project_root / "docs" / "SECURITY_AUDIT_REPORT.md",
        ]

        threat_doc_found = False
        for threat_doc in threat_docs:
            if threat_doc.exists():
                threat_doc_found = True
                evidence["threat_model_path"] = str(threat_doc)
                findings.append(f"Threat model documented in {threat_doc.name}")
                break

        status = ControlStatus.PASSED if threat_doc_found else ControlStatus.PARTIAL
        if not threat_doc_found:
            recommendations.append("Create formal threat model in docs/security/threat-model.md")

        # Check for incident response plan
        irp_path = self.project_root / "docs" / "security" / "incident-response-plan.md"
        if irp_path.exists():
            findings.append("Incident response plan documented")
            evidence["incident_response_plan"] = True
        else:
            evidence["incident_response_plan"] = False
            if status == ControlStatus.PASSED:
                status = ControlStatus.PARTIAL
            recommendations.append("Document incident response procedures")

        return status

    def check_risk_identification(self) -> RiskAssessmentCheckResult:
        """CC3.1 - Verify threat model exists."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            if not self._find_security_md(findings, evidence):
                return RiskAssessmentCheckResult(
                    control_id="CC3.1",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Create SECURITY.md with threat model and risk assessment"],
                )

            status = self._check_threat_model_docs(findings, evidence, recommendations)
            return RiskAssessmentCheckResult(
                control_id="CC3.1",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk identification: {e}")
            return _make_error_result("CC3.1", e, "Review threat model documentation")

    # ------------------------------------------------------------------
    # CC3.2 - Risk Analysis
    # ------------------------------------------------------------------

    def _check_preventive_controls(
        self,
        findings: list[str],
        evidence: dict[str, Any],
    ) -> None:
        """Check pre-commit hooks and CI security scanning."""
        from pdfsigner.core.compliance.risk_helpers import check_preventive_controls

        check_preventive_controls(self.project_root, findings, evidence)

    def _check_audit_and_coverage(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check audit reports and test coverage configuration."""
        from pdfsigner.core.compliance.risk_helpers import check_audit_and_coverage

        return check_audit_and_coverage(self.project_root, findings, evidence, recommendations)

    def check_risk_analysis(self) -> RiskAssessmentCheckResult:
        """CC3.2 - Verify vulnerability analysis."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            self._check_preventive_controls(findings, evidence)
            status = self._check_audit_and_coverage(findings, evidence, recommendations)

            return RiskAssessmentCheckResult(
                control_id="CC3.2",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk analysis: {e}")
            return _make_error_result("CC3.2", e, "Implement vulnerability tracking system")

    # ------------------------------------------------------------------
    # CC3.3 - Risk Mitigation
    # ------------------------------------------------------------------

    def _check_sla_documentation(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check for SLA definitions in security docs."""
        from pdfsigner.core.compliance.risk_helpers import check_sla_documentation

        return check_sla_documentation(self.project_root, findings, evidence, recommendations)

    def _check_change_management_and_changelog(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
        current_status: ControlStatus,
    ) -> ControlStatus:
        """Check change management docs and security fixes in changelog."""
        from pdfsigner.core.compliance.risk_helpers import check_change_management_and_changelog

        return check_change_management_and_changelog(
            self.project_root, findings, evidence, recommendations, current_status
        )

    def check_risk_mitigation(self) -> RiskAssessmentCheckResult:
        """CC3.3 - Verify remediation tracking."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            status = self._check_sla_documentation(findings, evidence, recommendations)
            status = self._check_change_management_and_changelog(
                findings, evidence, recommendations, status
            )

            return RiskAssessmentCheckResult(
                control_id="CC3.3",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk mitigation: {e}")
            return _make_error_result("CC3.3", e, "Document remediation tracking procedures")

    # ------------------------------------------------------------------
    # CC3.4 - Risk Monitoring
    # ------------------------------------------------------------------

    def _check_breach_detection(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check for breach detection system components."""
        from pdfsigner.core.compliance.risk_helpers import check_breach_detection

        return check_breach_detection(self.project_root, findings, evidence, recommendations)

    def _check_compliance_checker_available(
        self,
        findings: list[str],
        evidence: dict[str, Any],
    ) -> None:
        """Check for compliance checker module."""
        compliance_module_path = self.project_root / "src" / "pdfsigner" / "core" / "compliance"
        if compliance_module_path.exists():
            checker_path = compliance_module_path / "checker.py"
            if checker_path.exists():
                findings.append("Compliance checker available for periodic audits")
                evidence["compliance_checker"] = True
            else:
                evidence["compliance_checker"] = False
        else:
            evidence["compliance_checker"] = False

        findings.append("Continuous monitoring should be configured at deployment level")
        evidence["deployment_monitoring_note"] = (
            "Configure periodic compliance checks and breach detection scans"
        )

    def check_risk_monitoring(self) -> RiskAssessmentCheckResult:
        """CC3.4 - Verify continuous risk monitoring."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            status = self._check_breach_detection(findings, evidence, recommendations)
            self._check_compliance_checker_available(findings, evidence)

            return RiskAssessmentCheckResult(
                control_id="CC3.4",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk monitoring: {e}")
            return _make_error_result("CC3.4", e, "Implement continuous risk monitoring")

    # ------------------------------------------------------------------
    # Run all
    # ------------------------------------------------------------------

    def run_all_checks(self) -> list[RiskAssessmentCheckResult]:
        """
        Run all CC3 risk assessment checks.

        Returns:
            List of check results
        """
        return [
            self.check_risk_identification(),
            self.check_risk_analysis(),
            self.check_risk_mitigation(),
            self.check_risk_monitoring(),
        ]


# Singleton instance
_risk_assessment_checker: RiskAssessmentChecker | None = None


def get_risk_assessment_checker(
    project_root: Path | None = None,
) -> RiskAssessmentChecker:
    """
    Get singleton risk assessment checker instance.

    Args:
        project_root: Project root directory (optional)

    Returns:
        RiskAssessmentChecker instance
    """
    global _risk_assessment_checker

    if _risk_assessment_checker is None:
        _risk_assessment_checker = RiskAssessmentChecker(project_root)

    return _risk_assessment_checker

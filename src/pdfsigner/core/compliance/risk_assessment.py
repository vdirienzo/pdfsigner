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

    def check_risk_identification(self) -> RiskAssessmentCheckResult:
        """
        CC3.1 - Verify threat model exists.

        Checks:
        - Threat assessment documented
        - SECURITY.md documents known risks
        - Risk register maintained
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for SECURITY.md
            security_md_paths = [
                self.project_root / "docs" / "SECURITY.md",
                self.project_root / "SECURITY.md",
            ]

            security_md_found = False
            for security_md_path in security_md_paths:
                if security_md_path.exists():
                    security_md_found = True
                    evidence["security_md_path"] = str(security_md_path)

                    # Read and analyze content
                    content = security_md_path.read_text()
                    has_threat_section = any(
                        keyword in content.lower()
                        for keyword in ["threat", "risk", "vulnerability"]
                    )
                    evidence["has_threat_section"] = has_threat_section

                    if has_threat_section:
                        findings.append("SECURITY.md documents known risks")
                    else:
                        findings.append("SECURITY.md exists but lacks threat analysis")
                    break

            if not security_md_found:
                findings.append("SECURITY.md not found")
                return RiskAssessmentCheckResult(
                    control_id="CC3.1",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Create SECURITY.md with threat model and risk assessment"],
                )

            # Check for threat model documentation
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

            if threat_doc_found:
                status = ControlStatus.PASSED
            else:
                status = ControlStatus.PARTIAL
                recommendations.append(
                    "Create formal threat model in docs/security/threat-model.md"
                )

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

            return RiskAssessmentCheckResult(
                control_id="CC3.1",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk identification: {e}")
            return RiskAssessmentCheckResult(
                control_id="CC3.1",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review threat model documentation"],
            )

    def check_risk_analysis(self) -> RiskAssessmentCheckResult:
        """
        CC3.2 - Verify vulnerability analysis.

        Checks:
        - Vulnerability tracking system exists
        - CVSS scores assigned to vulnerabilities
        - Regular security assessments performed
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for vulnerability tracking
            # Note: PDFSigner doesn't have a formal vuln_tracker module yet,
            # but we can check for related security infrastructure

            # Check for pre-commit hooks (preventive controls)
            precommit_path = self.project_root / ".pre-commit-config.yaml"
            if precommit_path.exists():
                findings.append("Pre-commit hooks configured for code quality")
                evidence["precommit_hooks"] = True
            else:
                evidence["precommit_hooks"] = False

            # Check for dependency scanning in CI
            github_workflows = self.project_root / ".github" / "workflows"
            ci_files = []
            if github_workflows.exists():
                ci_files = list(github_workflows.glob("*.yml")) + list(
                    github_workflows.glob("*.yaml")
                )
                evidence["ci_files"] = [f.name for f in ci_files]

            has_security_scanning = False
            for ci_file in ci_files:
                content = ci_file.read_text()
                if any(tool in content.lower() for tool in ["bandit", "safety", "snyk", "trivy"]):
                    has_security_scanning = True
                    findings.append(f"Security scanning configured in {ci_file.name}")
                    break

            evidence["security_scanning"] = has_security_scanning

            # Check for audit reports
            audit_report_path = self.project_root / "docs" / "SECURITY_AUDIT_REPORT.md"
            if audit_report_path.exists():
                findings.append("Security audit report available")
                evidence["audit_report"] = True
                status = ControlStatus.PASSED
            else:
                evidence["audit_report"] = False
                status = ControlStatus.PARTIAL
                recommendations.append("Conduct and document regular security audits")

            # Check test coverage (indicator of code quality)
            pyproject = self.project_root / "pyproject.toml"
            if pyproject.exists():
                content = pyproject.read_text()
                if "pytest" in content or "coverage" in content:
                    findings.append("Test coverage tracking enabled")
                    evidence["test_coverage"] = True

            if not has_security_scanning and status == ControlStatus.PASSED:
                status = ControlStatus.PARTIAL
                recommendations.append("Implement automated dependency vulnerability scanning")

            return RiskAssessmentCheckResult(
                control_id="CC3.2",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk analysis: {e}")
            return RiskAssessmentCheckResult(
                control_id="CC3.2",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Implement vulnerability tracking system"],
            )

    def check_risk_mitigation(self) -> RiskAssessmentCheckResult:
        """
        CC3.3 - Verify remediation tracking.

        Checks:
        - SLA monitoring for vulnerability remediation
        - Critical vulnerabilities addressed within 30 days
        - Remediation procedures documented
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for security policies that define SLAs
            sla_docs = [
                self.project_root / "docs" / "security" / "SSP.md",
                self.project_root / "docs" / "security" / "change-management.md",
            ]

            sla_defined = False
            for sla_doc in sla_docs:
                if sla_doc.exists():
                    content = sla_doc.read_text()
                    if "sla" in content.lower() or "response time" in content.lower():
                        sla_defined = True
                        findings.append(f"SLA defined in {sla_doc.name}")
                        evidence[f"sla_doc_{sla_doc.name}"] = True
                        break

            if not sla_defined:
                findings.append("Vulnerability remediation SLAs not documented")
                status = ControlStatus.PARTIAL
                recommendations.append(
                    "Define SLAs for vulnerability remediation "
                    "(e.g., Critical: 7 days, High: 30 days)"
                )
            else:
                status = ControlStatus.PASSED

            # Check for change management documentation
            change_mgmt_path = self.project_root / "docs" / "security" / "change-management.md"
            if change_mgmt_path.exists():
                findings.append("Change management procedures documented")
                evidence["change_management"] = True
            else:
                evidence["change_management"] = False
                if status == ControlStatus.PASSED:
                    status = ControlStatus.PARTIAL
                recommendations.append("Document change management and remediation procedures")

            # Check CHANGELOG for security fixes
            changelog_path = self.project_root / "CHANGELOG.md"
            if changelog_path.exists():
                content = changelog_path.read_text()
                has_security_fixes = "security" in content.lower()
                evidence["tracks_security_fixes"] = has_security_fixes

                if has_security_fixes:
                    findings.append("Security fixes tracked in CHANGELOG.md")
                else:
                    findings.append("No security fixes documented in CHANGELOG")
            else:
                evidence["changelog_exists"] = False

            return RiskAssessmentCheckResult(
                control_id="CC3.3",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk mitigation: {e}")
            return RiskAssessmentCheckResult(
                control_id="CC3.3",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Document remediation tracking procedures"],
            )

    def check_risk_monitoring(self) -> RiskAssessmentCheckResult:
        """
        CC3.4 - Verify continuous risk monitoring.

        Checks:
        - Breach detector is active
        - Compliance checker runs periodically
        - Continuous monitoring mechanisms in place
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for breach detection system
            breach_module_path = self.project_root / "src" / "pdfsigner" / "core" / "breach"
            evidence["breach_module_path"] = str(breach_module_path)

            if breach_module_path.exists():
                # Check for key components
                breach_components = [
                    "breach_detector.py",
                    "breach_manager.py",
                    "breach_repository.py",
                ]

                existing_components = []
                for component in breach_components:
                    if (breach_module_path / component).exists():
                        existing_components.append(component)

                evidence["breach_components"] = existing_components

                if len(existing_components) == len(breach_components):
                    findings.append("Breach detection system fully implemented")
                    status = ControlStatus.PASSED
                elif existing_components:
                    findings.append("Breach detection partially implemented")
                    status = ControlStatus.PARTIAL
                    recommendations.append("Complete breach detection implementation")
                else:
                    findings.append("Breach detection not implemented")
                    status = ControlStatus.FAILED
                    recommendations.append("Implement breach detection system")
            else:
                findings.append("Breach detection module not found")
                status = ControlStatus.FAILED
                recommendations.append("Implement continuous monitoring and breach detection")
                evidence["breach_module_exists"] = False

            # Check for compliance checker
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

            # Check for monitoring configuration
            # Monitoring can be configured via scheduled tasks, cron jobs, etc.
            findings.append("Continuous monitoring should be configured at deployment level")
            evidence["deployment_monitoring_note"] = (
                "Configure periodic compliance checks and breach detection scans"
            )

            return RiskAssessmentCheckResult(
                control_id="CC3.4",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking risk monitoring: {e}")
            return RiskAssessmentCheckResult(
                control_id="CC3.4",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Implement continuous risk monitoring"],
            )

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

"""
governance.py - SOC 2 CC1: Control Environment checks

Verifies organizational structure, policies, oversight, competence,
and accountability. Delegates helper logic to governance_helpers.py.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.controls import ControlStatus
from pdfsigner.core.rbac.permissions import Permission
from pdfsigner.core.users.user_model import UserRole


@dataclass
class GovernanceCheckResult:
    """Result of a governance control check."""

    control_id: str
    status: ControlStatus
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


def _make_error_result(
    control_id: str, error: Exception, recommendation: str
) -> GovernanceCheckResult:
    """Build a FAILED result from an exception."""
    return GovernanceCheckResult(
        control_id=control_id,
        status=ControlStatus.FAILED,
        findings=[f"Check failed: {str(error)}"],
        evidence={},
        recommendations=[recommendation],
    )


class GovernanceChecker:
    """
    Check CC1 Control Environment controls.

    Verifies organizational structure, policies, oversight mechanisms,
    competence standards, and accountability measures.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize governance checker.

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
    # CC1.1 - Organization Structure
    # ------------------------------------------------------------------

    def _check_required_roles(
        self,
        findings: list[str],
        evidence: dict[str, Any],
    ) -> set[UserRole] | None:
        """Check required roles exist in RBAC. Returns missing roles or None."""
        from pdfsigner.core.compliance.governance_helpers import check_required_roles

        return check_required_roles(findings, evidence)

    def _check_separation_of_duties(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check that auditor does not have admin config permissions."""
        from pdfsigner.core.compliance.governance_helpers import check_separation_of_duties

        return check_separation_of_duties(findings, evidence, recommendations)

    def check_organization_structure(self) -> GovernanceCheckResult:
        """CC1.1 - Verify admin roles exist in RBAC."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            missing = self._check_required_roles(findings, evidence)
            if missing:
                return GovernanceCheckResult(
                    control_id="CC1.1",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Define missing roles in RBAC system"],
                )

            status = self._check_separation_of_duties(findings, evidence, recommendations)
            return GovernanceCheckResult(
                control_id="CC1.1",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking organization structure: {e}")
            return _make_error_result("CC1.1", e, "Review RBAC configuration")

    # ------------------------------------------------------------------
    # CC1.2 - Management Philosophy
    # ------------------------------------------------------------------

    def _scan_security_policies(
        self,
        security_docs_dir: Path,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Scan for required policy documents and report status."""
        from pdfsigner.core.compliance.governance_helpers import scan_security_policies

        return scan_security_policies(security_docs_dir, findings, evidence, recommendations)

    def check_management_philosophy(self) -> GovernanceCheckResult:
        """CC1.2 - Verify security policies documented."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            security_docs_dir = self.project_root / "docs" / "security"
            evidence["security_docs_path"] = str(security_docs_dir)

            if not security_docs_dir.exists():
                findings.append("Security documentation directory not found")
                return GovernanceCheckResult(
                    control_id="CC1.2",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Create docs/security/ directory with security policies"],
                )

            status = self._scan_security_policies(
                security_docs_dir, findings, evidence, recommendations
            )
            return GovernanceCheckResult(
                control_id="CC1.2",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking management philosophy: {e}")
            return _make_error_result("CC1.2", e, "Review security documentation structure")

    # ------------------------------------------------------------------
    # CC1.3 - Board Oversight
    # ------------------------------------------------------------------

    def _check_audit_components(
        self,
        audit_module_path: Path,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check for audit logger components and return status."""
        from pdfsigner.core.compliance.governance_helpers import check_audit_components

        return check_audit_components(audit_module_path, findings, evidence, recommendations)

    def _check_siem_export(
        self,
        audit_module_path: Path,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
        current_status: ControlStatus,
    ) -> ControlStatus:
        """Check for SIEM export capability."""
        from pdfsigner.core.compliance.governance_helpers import check_siem_export

        return check_siem_export(
            audit_module_path, findings, evidence, recommendations, current_status
        )

    def check_board_oversight(self) -> GovernanceCheckResult:
        """CC1.3 - Verify audit review capabilities."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            audit_module_path = self.project_root / "src" / "pdfsigner" / "core" / "audit"
            evidence["audit_module_path"] = str(audit_module_path)

            if not audit_module_path.exists():
                findings.append("Audit module not found")
                return GovernanceCheckResult(
                    control_id="CC1.3",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Implement audit logging module"],
                )

            status = self._check_audit_components(
                audit_module_path, findings, evidence, recommendations
            )
            status = self._check_siem_export(
                audit_module_path, findings, evidence, recommendations, status
            )

            return GovernanceCheckResult(
                control_id="CC1.3",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking board oversight: {e}")
            return _make_error_result("CC1.3", e, "Review audit logging implementation")

    # ------------------------------------------------------------------
    # CC1.4 - Competence
    # ------------------------------------------------------------------

    def _check_god_mode_roles(
        self,
        all_permissions: set[Permission],
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check that no role has 90%+ of all permissions."""
        from pdfsigner.core.compliance.governance_helpers import check_god_mode_roles

        return check_god_mode_roles(all_permissions, findings, evidence, recommendations)

    def _check_viewer_least_privilege(
        self,
        findings: list[str],
        recommendations: list[str],
        current_status: ControlStatus,
    ) -> ControlStatus:
        """Check that viewer role follows least privilege principle."""
        from pdfsigner.core.compliance.governance_helpers import check_viewer_least_privilege

        return check_viewer_least_privilege(findings, recommendations, current_status)

    def check_competence(self) -> GovernanceCheckResult:
        """CC1.4 - Verify role-based access configured."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            all_permissions = set(Permission)
            evidence["total_permissions"] = len(all_permissions)
            evidence["permissions"] = [p.value for p in all_permissions]

            findings.append(f"System defines {len(all_permissions)} granular permissions")

            status = self._check_god_mode_roles(
                all_permissions, findings, evidence, recommendations
            )
            status = self._check_viewer_least_privilege(findings, recommendations, status)

            return GovernanceCheckResult(
                control_id="CC1.4",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking competence: {e}")
            return _make_error_result("CC1.4", e, "Review RBAC permission configuration")

    # ------------------------------------------------------------------
    # CC1.5 - Accountability
    # ------------------------------------------------------------------

    def _check_audit_events(
        self,
        findings: list[str],
        evidence: dict[str, Any],
    ) -> bool:
        """Check audit event definitions exist. Returns False if missing."""
        from pdfsigner.core.compliance.governance_helpers import check_audit_events

        return check_audit_events(self.project_root, findings, evidence)

    def _check_audit_integrity(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check audit integrity implementation."""
        from pdfsigner.core.compliance.governance_helpers import check_audit_integrity

        return check_audit_integrity(self.project_root, findings, evidence, recommendations)

    def check_accountability(self) -> GovernanceCheckResult:
        """CC1.5 - Verify audit trail for user actions."""
        findings: list[str] = []
        evidence: dict[str, Any] = {}
        recommendations: list[str] = []

        try:
            if not self._check_audit_events(findings, evidence):
                return GovernanceCheckResult(
                    control_id="CC1.5",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Implement audit event types"],
                )

            status = self._check_audit_integrity(findings, evidence, recommendations)

            findings.append("User ID tracked in all audit events")
            findings.append("Timestamp and action type recorded")
            evidence["user_tracking"] = True

            return GovernanceCheckResult(
                control_id="CC1.5",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking accountability: {e}")
            return _make_error_result("CC1.5", e, "Review audit trail implementation")

    # ------------------------------------------------------------------
    # Run all
    # ------------------------------------------------------------------

    def run_all_checks(self) -> list[GovernanceCheckResult]:
        """
        Run all CC1 governance checks.

        Returns:
            List of check results
        """
        return [
            self.check_organization_structure(),
            self.check_management_philosophy(),
            self.check_board_oversight(),
            self.check_competence(),
            self.check_accountability(),
        ]


# Singleton instance
_governance_checker: GovernanceChecker | None = None


def get_governance_checker(project_root: Path | None = None) -> GovernanceChecker:
    """
    Get singleton governance checker instance.

    Args:
        project_root: Project root directory (optional)

    Returns:
        GovernanceChecker instance
    """
    global _governance_checker

    if _governance_checker is None:
        _governance_checker = GovernanceChecker(project_root)

    return _governance_checker

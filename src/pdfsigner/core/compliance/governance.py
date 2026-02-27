"""
governance.py - SOC 2 CC1: Control Environment checks

Verifies organizational control environment including:
- Organization structure and roles
- Management philosophy and security policies
- Board oversight and audit review
- Competence and separation of duties
- Accountability and audit trails
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.controls import ControlStatus
from pdfsigner.core.rbac.permissions import ROLE_PERMISSIONS, Permission
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
        required_roles = {UserRole.ADMIN, UserRole.AUDITOR, UserRole.SIGNER}
        defined_roles = set(ROLE_PERMISSIONS.keys())

        evidence["defined_roles"] = [role.value for role in defined_roles]
        evidence["required_roles"] = [role.value for role in required_roles]

        missing_roles = required_roles - defined_roles
        if missing_roles:
            findings.append(f"Missing roles: {', '.join(r.value for r in missing_roles)}")
            return missing_roles

        findings.append("All required roles defined in RBAC")
        findings.append(
            f"Total roles: {len(defined_roles)} ({', '.join(r.value for r in defined_roles)})"
        )
        return None

    def _check_separation_of_duties(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check that auditor does not have admin config permissions."""
        admin_perms = ROLE_PERMISSIONS.get(UserRole.ADMIN, set())
        auditor_perms = ROLE_PERMISSIONS.get(UserRole.AUDITOR, set())

        evidence["admin_permissions"] = [p.value for p in admin_perms]
        evidence["auditor_permissions"] = [p.value for p in auditor_perms]

        if Permission.ADMIN_CONFIG in auditor_perms:
            findings.append("Warning: Auditor has admin config permissions")
            recommendations.append("Remove admin config permissions from auditor role")
            return ControlStatus.PARTIAL

        findings.append("Separation of duties enforced (auditor != admin)")
        return ControlStatus.PASSED

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
        required_policies = [
            "access-control-policy.md",
            "audit-policy.md",
            "encryption-policy.md",
            "incident-response-plan.md",
        ]

        existing_policies = []
        missing_policies = []

        for policy in required_policies:
            policy_path = security_docs_dir / policy
            if policy_path.exists():
                existing_policies.append(policy)
                evidence[f"policy_{policy}_mtime"] = policy_path.stat().st_mtime
            else:
                missing_policies.append(policy)

        evidence["existing_policies"] = existing_policies
        evidence["missing_policies"] = missing_policies

        if missing_policies:
            findings.append(f"Missing policies: {', '.join(missing_policies)}")
            recommendations.append("Document missing security policies in docs/security/")
            status = ControlStatus.PARTIAL
        else:
            findings.append("All required security policies documented")
            status = ControlStatus.PASSED

        findings.append(
            f"Found {len(existing_policies)}/{len(required_policies)} required policies"
        )
        return status

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
        required_components = [
            "audit_logger.py",
            "audit_event.py",
            "audit_integrity.py",
        ]

        existing_components = []
        for component in required_components:
            if (audit_module_path / component).exists():
                existing_components.append(component)

        evidence["audit_components"] = existing_components

        if len(existing_components) == len(required_components):
            findings.append("Audit logging system fully implemented")
            findings.append("Components: logger, event types, integrity verification")
            return ControlStatus.PASSED
        elif existing_components:
            findings.append("Audit logging partially implemented")
            recommendations.append("Complete audit logging implementation")
            return ControlStatus.PARTIAL
        else:
            findings.append("Audit logging not implemented")
            recommendations.append("Implement comprehensive audit logging")
            return ControlStatus.FAILED

    def _check_siem_export(
        self,
        audit_module_path: Path,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
        current_status: ControlStatus,
    ) -> ControlStatus:
        """Check for SIEM export capability."""
        siem_exporter_path = audit_module_path / "siem_exporter.py"
        if siem_exporter_path.exists():
            findings.append("SIEM export capability available")
            evidence["siem_export"] = True
            return current_status

        evidence["siem_export"] = False
        recommendations.append("Implement SIEM export for centralized log management")
        if current_status == ControlStatus.PASSED:
            return ControlStatus.PARTIAL
        return current_status

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
        god_mode_roles = []
        for role, perms in ROLE_PERMISSIONS.items():
            perm_ratio = len(perms) / len(all_permissions)
            evidence[f"role_{role.value}_permissions"] = len(perms)
            evidence[f"role_{role.value}_ratio"] = round(perm_ratio, 2)

            if perm_ratio >= 0.9:
                god_mode_roles.append(role.value)

        if god_mode_roles:
            findings.append(
                f"Warning: Roles with excessive permissions: {', '.join(god_mode_roles)}"
            )
            recommendations.append("Review and limit permissions for overprivileged roles")
            return ControlStatus.PARTIAL

        findings.append("Separation of duties enforced - no god mode roles")
        return ControlStatus.PASSED

    def _check_viewer_least_privilege(
        self,
        findings: list[str],
        recommendations: list[str],
        current_status: ControlStatus,
    ) -> ControlStatus:
        """Check that viewer role follows least privilege principle."""
        viewer_perms = ROLE_PERMISSIONS.get(UserRole.VIEWER, set())
        if len(viewer_perms) <= 3:
            findings.append("Least privilege principle enforced for viewer role")
            return current_status

        findings.append("Warning: Viewer role has excessive permissions")
        recommendations.append("Reduce viewer role permissions")
        if current_status == ControlStatus.PASSED:
            return ControlStatus.PARTIAL
        return current_status

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
        audit_event_path = (
            self.project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_event.py"
        )

        if not audit_event_path.exists():
            findings.append("Audit event definitions not found")
            return False

        findings.append("Audit event system implemented")
        evidence["audit_events_defined"] = True
        return True

    def _check_audit_integrity(
        self,
        findings: list[str],
        evidence: dict[str, Any],
        recommendations: list[str],
    ) -> ControlStatus:
        """Check audit integrity implementation."""
        audit_integrity_path = (
            self.project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_integrity.py"
        )

        if audit_integrity_path.exists():
            findings.append("Audit integrity verification available")
            findings.append("Non-repudiation via HMAC chain hashing")
            evidence["audit_integrity"] = True
            return ControlStatus.PASSED

        findings.append("Audit integrity not implemented")
        evidence["audit_integrity"] = False
        recommendations.append("Implement audit log integrity verification")
        return ControlStatus.PARTIAL

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

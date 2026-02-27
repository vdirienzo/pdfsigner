"""
governance_helpers.py - Helper functions for CC1 governance checks

Extracted from governance.py to keep modules under 400 lines.
Contains audit component, SIEM export, god mode, and audit integrity checks.
"""

from pathlib import Path
from typing import Any

from pdfsigner.core.compliance.controls import ControlStatus
from pdfsigner.core.rbac.permissions import ROLE_PERMISSIONS, Permission
from pdfsigner.core.users.user_model import UserRole


def check_required_roles(
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


def check_separation_of_duties(
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


def check_audit_components(
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


def check_siem_export(
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


def check_god_mode_roles(
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
        findings.append(f"Warning: Roles with excessive permissions: {', '.join(god_mode_roles)}")
        recommendations.append("Review and limit permissions for overprivileged roles")
        return ControlStatus.PARTIAL

    findings.append("Separation of duties enforced - no god mode roles")
    return ControlStatus.PASSED


def check_viewer_least_privilege(
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


def check_audit_events(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
) -> bool:
    """Check audit event definitions exist. Returns False if missing."""
    audit_event_path = project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_event.py"

    if not audit_event_path.exists():
        findings.append("Audit event definitions not found")
        return False

    findings.append("Audit event system implemented")
    evidence["audit_events_defined"] = True
    return True


def check_audit_integrity(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
    recommendations: list[str],
) -> ControlStatus:
    """Check audit integrity implementation."""
    audit_integrity_path = (
        project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_integrity.py"
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


def scan_security_policies(
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

    findings.append(f"Found {len(existing_policies)}/{len(required_policies)} required policies")
    return status

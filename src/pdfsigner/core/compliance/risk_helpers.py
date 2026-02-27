"""
risk_helpers.py - Helper functions for CC3 Risk Assessment checks

Extracted from risk_assessment.py to keep modules under 400 lines.
Contains file-system scanning helpers for risk analysis and mitigation checks.
"""

from pathlib import Path
from typing import Any

from pdfsigner.core.compliance.controls import ControlStatus


def check_preventive_controls(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
) -> None:
    """Check pre-commit hooks and CI security scanning."""
    precommit_path = project_root / ".pre-commit-config.yaml"
    if precommit_path.exists():
        findings.append("Pre-commit hooks configured for code quality")
        evidence["precommit_hooks"] = True
    else:
        evidence["precommit_hooks"] = False

    github_workflows = project_root / ".github" / "workflows"
    ci_files: list[Path] = []
    if github_workflows.exists():
        ci_files = list(github_workflows.glob("*.yml")) + list(github_workflows.glob("*.yaml"))
        evidence["ci_files"] = [f.name for f in ci_files]

    has_security_scanning = False
    for ci_file in ci_files:
        content = ci_file.read_text()
        if any(tool in content.lower() for tool in ["bandit", "safety", "snyk", "trivy"]):
            has_security_scanning = True
            findings.append(f"Security scanning configured in {ci_file.name}")
            break

    evidence["security_scanning"] = has_security_scanning


def check_audit_and_coverage(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
    recommendations: list[str],
) -> ControlStatus:
    """Check audit reports and test coverage configuration."""
    audit_report_path = project_root / "docs" / "SECURITY_AUDIT_REPORT.md"
    if audit_report_path.exists():
        findings.append("Security audit report available")
        evidence["audit_report"] = True
        status = ControlStatus.PASSED
    else:
        evidence["audit_report"] = False
        status = ControlStatus.PARTIAL
        recommendations.append("Conduct and document regular security audits")

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        if "pytest" in content or "coverage" in content:
            findings.append("Test coverage tracking enabled")
            evidence["test_coverage"] = True

    if not evidence.get("security_scanning") and status == ControlStatus.PASSED:
        status = ControlStatus.PARTIAL
        recommendations.append("Implement automated dependency vulnerability scanning")

    return status


def check_sla_documentation(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
    recommendations: list[str],
) -> ControlStatus:
    """Check for SLA definitions in security docs."""
    sla_docs = [
        project_root / "docs" / "security" / "SSP.md",
        project_root / "docs" / "security" / "change-management.md",
    ]

    for sla_doc in sla_docs:
        if sla_doc.exists():
            content = sla_doc.read_text()
            if "sla" in content.lower() or "response time" in content.lower():
                findings.append(f"SLA defined in {sla_doc.name}")
                evidence[f"sla_doc_{sla_doc.name}"] = True
                return ControlStatus.PASSED

    findings.append("Vulnerability remediation SLAs not documented")
    recommendations.append(
        "Define SLAs for vulnerability remediation (e.g., Critical: 7 days, High: 30 days)"
    )
    return ControlStatus.PARTIAL


def check_change_management_and_changelog(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
    recommendations: list[str],
    current_status: ControlStatus,
) -> ControlStatus:
    """Check change management docs and security fixes in changelog."""
    status = current_status

    change_mgmt_path = project_root / "docs" / "security" / "change-management.md"
    if change_mgmt_path.exists():
        findings.append("Change management procedures documented")
        evidence["change_management"] = True
    else:
        evidence["change_management"] = False
        if status == ControlStatus.PASSED:
            status = ControlStatus.PARTIAL
        recommendations.append("Document change management and remediation procedures")

    changelog_path = project_root / "CHANGELOG.md"
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

    return status


def check_breach_detection(
    project_root: Path,
    findings: list[str],
    evidence: dict[str, Any],
    recommendations: list[str],
) -> ControlStatus:
    """Check for breach detection system components."""
    breach_module_path = project_root / "src" / "pdfsigner" / "core" / "breach"
    evidence["breach_module_path"] = str(breach_module_path)

    if not breach_module_path.exists():
        findings.append("Breach detection module not found")
        evidence["breach_module_exists"] = False
        recommendations.append("Implement continuous monitoring and breach detection")
        return ControlStatus.FAILED

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
        return ControlStatus.PASSED
    elif existing_components:
        findings.append("Breach detection partially implemented")
        recommendations.append("Complete breach detection implementation")
        return ControlStatus.PARTIAL
    else:
        findings.append("Breach detection not implemented")
        recommendations.append("Implement breach detection system")
        return ControlStatus.FAILED

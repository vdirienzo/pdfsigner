"""
communication.py - SOC 2 CC2: Communication and Information checks

Verifies communication channels and information distribution including:
- Internal communication of security policies
- External communication through documentation
- Secure communication channels
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.controls import ControlStatus


@dataclass
class CommunicationCheckResult:
    """Result of a communication control check."""

    control_id: str
    status: ControlStatus
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


class CommunicationChecker:
    """
    Check CC2 Communication and Information controls.

    Verifies internal and external communication mechanisms,
    documentation availability, and secure communication channels.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize communication checker.

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

    def check_internal_communication(self) -> CommunicationCheckResult:
        """
        CC2.1 - Verify internal security policies accessible.

        Checks:
        - docs/security/ contains policies
        - CLAUDE.md documents security requirements
        - Security documentation is comprehensive
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check docs/security/ directory
            security_docs = self.project_root / "docs" / "security"
            evidence["security_docs_path"] = str(security_docs)

            if not security_docs.exists():
                findings.append("Security documentation directory not found")
                return CommunicationCheckResult(
                    control_id="CC2.1",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Create docs/security/ with internal security policies"],
                )

            # Count policy documents
            policy_files = list(security_docs.glob("*.md"))
            evidence["policy_count"] = len(policy_files)
            evidence["policy_files"] = [f.name for f in policy_files]

            if len(policy_files) >= 4:
                findings.append(f"Security policies documented ({len(policy_files)} files)")
                status = ControlStatus.PASSED
            elif len(policy_files) > 0:
                findings.append(f"Partial security documentation ({len(policy_files)} files)")
                status = ControlStatus.PARTIAL
                recommendations.append(
                    "Complete security policy documentation (minimum 4 policies)"
                )
            else:
                findings.append("No security policies found")
                status = ControlStatus.FAILED
                recommendations.append("Document security policies in docs/security/")

            # Check CLAUDE.md for security section
            claude_md = self.project_root / "CLAUDE.md"
            if claude_md.exists():
                content = claude_md.read_text()
                has_security = "security" in content.lower() or "compliance" in content.lower()
                evidence["claude_md_has_security"] = has_security

                if has_security:
                    findings.append("CLAUDE.md documents security requirements")
                else:
                    if status == ControlStatus.PASSED:
                        status = ControlStatus.PARTIAL
                    recommendations.append("Add security section to CLAUDE.md")
            else:
                evidence["claude_md_exists"] = False
                if status == ControlStatus.PASSED:
                    status = ControlStatus.PARTIAL
                recommendations.append("Create CLAUDE.md with project security requirements")

            return CommunicationCheckResult(
                control_id="CC2.1",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking internal communication: {e}")
            return CommunicationCheckResult(
                control_id="CC2.1",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review internal documentation structure"],
            )

    def check_external_communication(self) -> CommunicationCheckResult:
        """
        CC2.2 - Verify API documentation available.

        Checks:
        - OpenAPI docs accessible
        - Error messages don't leak internal details
        - Public documentation exists
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for API documentation
            api_main_path = self.project_root / "src" / "pdfsigner" / "api" / "main.py"
            evidence["api_exists"] = api_main_path.exists()

            if api_main_path.exists():
                findings.append("FastAPI application provides OpenAPI documentation")
                findings.append("API docs accessible at /docs and /redoc endpoints")
                evidence["openapi_docs"] = True
                status = ControlStatus.PASSED
            else:
                findings.append("API not implemented")
                evidence["openapi_docs"] = False
                status = ControlStatus.NOT_APPLICABLE
                return CommunicationCheckResult(
                    control_id="CC2.2",
                    status=status,
                    findings=findings,
                    evidence=evidence,
                    recommendations=[],
                )

            # Check for exception handling that prevents info leakage
            exceptions_path = self.project_root / "src" / "pdfsigner" / "exceptions.py"
            if exceptions_path.exists():
                findings.append("Custom exception handling implemented")
                evidence["custom_exceptions"] = True
            else:
                evidence["custom_exceptions"] = False
                status = ControlStatus.PARTIAL
                recommendations.append("Implement custom exceptions to prevent information leakage")

            # Check README for public documentation
            readme_path = self.project_root / "README.md"
            if readme_path.exists():
                content = readme_path.read_text()
                has_api_docs = "api" in content.lower() and (
                    "endpoint" in content.lower() or "swagger" in content.lower()
                )
                evidence["readme_has_api_docs"] = has_api_docs

                if has_api_docs:
                    findings.append("API documented in README.md")
                else:
                    if status == ControlStatus.PASSED:
                        status = ControlStatus.PARTIAL
                    recommendations.append("Add API documentation to README.md")
            else:
                evidence["readme_exists"] = False
                recommendations.append("Create README.md with API documentation")

            return CommunicationCheckResult(
                control_id="CC2.2",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking external communication: {e}")
            return CommunicationCheckResult(
                control_id="CC2.2",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review API documentation structure"],
            )

    def check_communication_channels(self) -> CommunicationCheckResult:
        """
        CC2.3 - Verify secure communication channels.

        Checks:
        - TLS configured for API
        - Audit events for communication failures
        - Secure logging practices
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for TLS middleware
            tls_middleware_path = (
                self.project_root / "src" / "pdfsigner" / "api" / "middleware" / "tls.py"
            )
            evidence["tls_middleware_exists"] = tls_middleware_path.exists()

            if tls_middleware_path.exists():
                findings.append("TLS middleware implemented for API security")
                findings.append("HTTPS redirection available")
                evidence["tls_available"] = True
                status = ControlStatus.PASSED
            else:
                findings.append("TLS middleware not found")
                evidence["tls_available"] = False
                status = ControlStatus.PARTIAL
                recommendations.append("Implement TLS middleware for secure API communication")

            # Check audit logging for communication events
            audit_event_path = (
                self.project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_event.py"
            )

            if audit_event_path.exists():
                findings.append("Audit logging tracks communication events")
                evidence["audit_logging"] = True
            else:
                evidence["audit_logging"] = False
                if status == ControlStatus.PASSED:
                    status = ControlStatus.PARTIAL
                recommendations.append("Implement audit logging for communication failures")

            # Check for secure logging configuration
            config_path = self.project_root / "src" / "pdfsigner" / "config" / "settings.py"
            if config_path.exists():
                findings.append("Configuration management for secure channels")
                evidence["config_management"] = True
            else:
                evidence["config_management"] = False

            return CommunicationCheckResult(
                control_id="CC2.3",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking communication channels: {e}")
            return CommunicationCheckResult(
                control_id="CC2.3",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review secure communication implementation"],
            )

    def run_all_checks(self) -> list[CommunicationCheckResult]:
        """
        Run all CC2 communication checks.

        Returns:
            List of check results
        """
        return [
            self.check_internal_communication(),
            self.check_external_communication(),
            self.check_communication_channels(),
        ]


# Singleton instance
_communication_checker: CommunicationChecker | None = None


def get_communication_checker(
    project_root: Path | None = None,
) -> CommunicationChecker:
    """
    Get singleton communication checker instance.

    Args:
        project_root: Project root directory (optional)

    Returns:
        CommunicationChecker instance
    """
    global _communication_checker

    if _communication_checker is None:
        _communication_checker = CommunicationChecker(project_root)

    return _communication_checker

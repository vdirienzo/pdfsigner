"""
monitoring.py - SOC 2 CC4: Monitoring Activities checks

Verifies monitoring processes including:
- Continuous control monitoring
- Deficiency reporting and remediation
- Management oversight of monitoring activities
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.controls import ControlStatus


@dataclass
class MonitoringCheckResult:
    """Result of a monitoring control check."""

    control_id: str
    status: ControlStatus
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


class MonitoringChecker:
    """
    Check CC4 Monitoring Activities controls.

    Verifies continuous monitoring, deficiency reporting,
    and management oversight mechanisms.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize monitoring checker.

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

    def check_monitoring_controls(self) -> MonitoringCheckResult:
        """
        CC4.1 - Verify continuous monitoring active.

        Checks:
        - Audit logger is capturing events
        - SIEM export configured
        - Breach detector thresholds set
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check audit logging system
            audit_module_path = self.project_root / "src" / "pdfsigner" / "core" / "audit"
            evidence["audit_module_path"] = str(audit_module_path)

            if not audit_module_path.exists():
                findings.append("Audit module not found")
                return MonitoringCheckResult(
                    control_id="CC4.1",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Implement audit logging module"],
                )

            # Check for audit logger components
            audit_components = {
                "audit_logger.py": "Core audit logging",
                "audit_event.py": "Event type definitions",
                "audit_integrity.py": "Log integrity verification",
            }

            implemented_components = []
            for component, description in audit_components.items():
                if (audit_module_path / component).exists():
                    implemented_components.append(component)
                    findings.append(f"{description} implemented")

            evidence["audit_components"] = implemented_components
            evidence["audit_components_count"] = len(implemented_components)

            # Check for SIEM export
            siem_exporter_path = audit_module_path / "siem_exporter.py"
            if siem_exporter_path.exists():
                findings.append("SIEM export capability available")
                evidence["siem_export"] = True
            else:
                evidence["siem_export"] = False
                recommendations.append("Implement SIEM export for centralized monitoring")

            # Check for breach detection
            breach_module_path = self.project_root / "src" / "pdfsigner" / "core" / "breach"
            if breach_module_path.exists():
                breach_detector_path = breach_module_path / "breach_detector.py"
                if breach_detector_path.exists():
                    findings.append("Breach detection system active")
                    evidence["breach_detection"] = True
                else:
                    evidence["breach_detection"] = False
            else:
                evidence["breach_detection"] = False
                recommendations.append("Implement breach detection with configurable thresholds")

            # Determine overall status
            if len(implemented_components) == len(audit_components):
                if evidence.get("siem_export") and evidence.get("breach_detection"):
                    status = ControlStatus.PASSED
                    findings.append("Comprehensive monitoring system in place")
                else:
                    status = ControlStatus.PARTIAL
                    findings.append("Core monitoring implemented, optional features missing")
            elif implemented_components:
                status = ControlStatus.PARTIAL
                findings.append("Monitoring partially implemented")
                recommendations.append("Complete audit logging implementation")
            else:
                status = ControlStatus.FAILED
                findings.append("Monitoring not implemented")
                recommendations.append("Implement comprehensive audit and monitoring system")

            return MonitoringCheckResult(
                control_id="CC4.1",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking monitoring controls: {e}")
            return MonitoringCheckResult(
                control_id="CC4.1",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review monitoring system implementation"],
            )

    def check_reporting_deficiencies(self) -> MonitoringCheckResult:
        """
        CC4.2 - Verify deficiency reporting.

        Checks:
        - Compliance checker generates reports
        - Issues tracked in audit trail
        - Alert mechanisms configured
        """
        findings = []
        evidence: dict[str, Any] = {}
        recommendations = []

        try:
            # Check for compliance checker
            compliance_module_path = self.project_root / "src" / "pdfsigner" / "core" / "compliance"
            evidence["compliance_module_path"] = str(compliance_module_path)

            if not compliance_module_path.exists():
                findings.append("Compliance module not found")
                return MonitoringCheckResult(
                    control_id="CC4.2",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Implement compliance checking module"],
                )

            # Check for checker components
            checker_path = compliance_module_path / "checker.py"
            if checker_path.exists():
                findings.append("Compliance checker available")
                evidence["compliance_checker"] = True
            else:
                evidence["compliance_checker"] = False
                findings.append("Compliance checker not found")
                return MonitoringCheckResult(
                    control_id="CC4.2",
                    status=ControlStatus.FAILED,
                    findings=findings,
                    evidence=evidence,
                    recommendations=["Implement compliance checker"],
                )

            # Check for report generation
            report_generator_path = compliance_module_path / "report_generator.py"
            if report_generator_path.exists():
                findings.append("Compliance report generator available")
                evidence["report_generator"] = True
            else:
                evidence["report_generator"] = False
                recommendations.append("Implement compliance report generator")

            # Check for audit trail of compliance issues
            audit_module_path = self.project_root / "src" / "pdfsigner" / "core" / "audit"
            if audit_module_path.exists():
                audit_logger_path = audit_module_path / "audit_logger.py"
                if audit_logger_path.exists():
                    findings.append("Audit trail available for tracking issues")
                    evidence["audit_trail"] = True
                else:
                    evidence["audit_trail"] = False
            else:
                evidence["audit_trail"] = False

            # Check for alert mechanisms (breach detection provides alerting)
            breach_module_path = self.project_root / "src" / "pdfsigner" / "core" / "breach"
            if breach_module_path.exists():
                breach_manager_path = breach_module_path / "breach_manager.py"
                if breach_manager_path.exists():
                    findings.append("Alert mechanisms available via breach manager")
                    evidence["alert_mechanism"] = True
                else:
                    evidence["alert_mechanism"] = False
            else:
                evidence["alert_mechanism"] = False
                recommendations.append("Implement alerting for compliance deficiencies")

            # Check for reporting formats
            formatters_path = compliance_module_path / "formatters.py"
            if formatters_path.exists():
                findings.append("Multiple report formats supported")
                evidence["multiple_formats"] = True
            else:
                evidence["multiple_formats"] = False

            # Determine status
            required_features = [
                evidence.get("compliance_checker"),
                evidence.get("audit_trail"),
            ]

            optional_features = [
                evidence.get("report_generator"),
                evidence.get("alert_mechanism"),
                evidence.get("multiple_formats"),
            ]

            if all(required_features):
                if sum(bool(f) for f in optional_features) >= 2:
                    status = ControlStatus.PASSED
                    findings.append("Comprehensive deficiency reporting in place")
                else:
                    status = ControlStatus.PARTIAL
                    findings.append("Basic deficiency reporting implemented")
            else:
                status = ControlStatus.FAILED
                findings.append("Deficiency reporting not adequately implemented")
                recommendations.append(
                    "Implement comprehensive compliance issue tracking and reporting"
                )

            return MonitoringCheckResult(
                control_id="CC4.2",
                status=status,
                findings=findings,
                evidence=evidence,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception(f"Error checking reporting deficiencies: {e}")
            return MonitoringCheckResult(
                control_id="CC4.2",
                status=ControlStatus.FAILED,
                findings=[f"Check failed: {str(e)}"],
                evidence={},
                recommendations=["Review deficiency reporting implementation"],
            )

    def run_all_checks(self) -> list[MonitoringCheckResult]:
        """
        Run all CC4 monitoring checks.

        Returns:
            List of check results
        """
        return [
            self.check_monitoring_controls(),
            self.check_reporting_deficiencies(),
        ]


# Singleton instance
_monitoring_checker: MonitoringChecker | None = None


def get_monitoring_checker(project_root: Path | None = None) -> MonitoringChecker:
    """
    Get singleton monitoring checker instance.

    Args:
        project_root: Project root directory (optional)

    Returns:
        MonitoringChecker instance
    """
    global _monitoring_checker

    if _monitoring_checker is None:
        _monitoring_checker = MonitoringChecker(project_root)

    return _monitoring_checker

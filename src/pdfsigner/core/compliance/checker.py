"""
checker.py - Compliance verification engine

Performs automated compliance checks against various standards by
inspecting current Settings configuration.

Sub-checkers handle the detailed control logic:
- HIPAAChecker: HIPAA Security Rule (§164.312)
- NISTChecker: NIST 800-53 AC/IA families
- NISTAuditChecker: NIST 800-53 AU/SC families
- FedRAMPChecker: FedRAMP Moderate
- EIDASChecker: eIDAS regulation (EU 910/2014)
- GDPRChecker: GDPR data protection
- SOC2Checker: SOC 2 Type II Trust Services Criteria
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from loguru import logger

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import (
    ComplianceStandard,
    ControlDefinition,
    ControlStatus,
    get_controls_for_standard,
)


@dataclass
class ControlCheck:
    """Result of a single control check."""

    control_id: str
    name: str
    description: str
    standard: ComplianceStandard
    status: ControlStatus
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Comprehensive compliance report for a standard."""

    standard: ComplianceStandard
    score: float  # 0-100
    passed_controls: list[ControlCheck]
    failed_controls: list[ControlCheck]
    partial_controls: list[ControlCheck]
    recommendations: list[str]
    generated_at: datetime


class ComplianceChecker:
    """
    Central compliance verification engine.

    Checks PDFSigner configuration against various compliance standards
    and generates detailed reports with evidence and recommendations.

    Delegates control-specific checks to per-standard sub-checkers
    (HIPAAChecker, NISTChecker, EIDASChecker, GDPRChecker, SOC2Checker).
    """

    def __init__(self, settings: Settings):
        """
        Initialize compliance checker.

        Args:
            settings: PDFSigner settings to check
        """
        self.settings = settings

        # Lazy-initialized sub-checkers to avoid circular imports
        self._sub_checkers: list[object] | None = None

    def _get_sub_checkers(self) -> list[object]:
        """Get all sub-checker instances, initializing lazily."""
        if self._sub_checkers is None:
            from pdfsigner.core.compliance.eidas_checker import EIDASChecker
            from pdfsigner.core.compliance.fedramp_checker import FedRAMPChecker
            from pdfsigner.core.compliance.gdpr_checker import GDPRChecker
            from pdfsigner.core.compliance.hipaa_checker import HIPAAChecker
            from pdfsigner.core.compliance.nist_audit_checker import NISTAuditChecker
            from pdfsigner.core.compliance.nist_checker import NISTChecker
            from pdfsigner.core.compliance.soc2_checker import SOC2Checker

            self._sub_checkers = [
                HIPAAChecker(self.settings),
                NISTChecker(self.settings),
                NISTAuditChecker(self.settings),
                FedRAMPChecker(self.settings),
                EIDASChecker(self.settings),
                GDPRChecker(self.settings),
                SOC2Checker(self.settings),
            ]

        return self._sub_checkers

    def _find_check_method(self, method_name: str):
        """
        Find a check method by name across all sub-checkers.

        Args:
            method_name: Name of the check method (e.g., '_check_hipaa_encryption')

        Returns:
            Bound method if found

        Raises:
            AttributeError: If method not found in any sub-checker
        """
        for sub_checker in self._get_sub_checkers():
            method = getattr(sub_checker, method_name, None)
            if method is not None:
                return method

        raise AttributeError(f"Check method not found: {method_name}")

    # ========================================================================
    # Public API
    # ========================================================================

    def check_hipaa(self) -> ComplianceReport:
        """
        Check HIPAA security rule controls (§164.312).

        Returns:
            Compliance report for HIPAA
        """
        return self._check_standard(ComplianceStandard.HIPAA)

    def check_nist_800_53(self) -> ComplianceReport:
        """
        Check NIST 800-53 Moderate baseline controls.

        Returns:
            Compliance report for NIST 800-53
        """
        return self._check_standard(ComplianceStandard.NIST_800_53)

    def check_fedramp(self) -> ComplianceReport:
        """
        Check FedRAMP Moderate controls.

        Returns:
            Compliance report for FedRAMP
        """
        return self._check_standard(ComplianceStandard.FEDRAMP)

    def check_eidas(self) -> ComplianceReport:
        """
        Check eIDAS regulation compliance.

        Returns:
            Compliance report for eIDAS
        """
        return self._check_standard(ComplianceStandard.EIDAS)

    def check_gdpr(self) -> ComplianceReport:
        """
        Check GDPR data protection controls.

        Returns:
            Compliance report for GDPR
        """
        return self._check_standard(ComplianceStandard.GDPR)

    def check_soc2(self) -> ComplianceReport:
        """
        Check SOC 2 Type II controls.

        Returns:
            Compliance report for SOC 2
        """
        return self._check_standard(ComplianceStandard.SOC2)

    def check_all(self) -> dict[ComplianceStandard, ComplianceReport]:
        """
        Run all compliance checks.

        Returns:
            Dictionary mapping standard to compliance report
        """
        return {
            ComplianceStandard.HIPAA: self.check_hipaa(),
            ComplianceStandard.NIST_800_53: self.check_nist_800_53(),
            ComplianceStandard.FEDRAMP: self.check_fedramp(),
            ComplianceStandard.EIDAS: self.check_eidas(),
            ComplianceStandard.GDPR: self.check_gdpr(),
            ComplianceStandard.SOC2: self.check_soc2(),
        }

    def get_overall_score(
        self, reports: dict[ComplianceStandard, ComplianceReport] | None = None
    ) -> float:
        """
        Calculate weighted overall compliance score (0-100).

        Averages scores across all standards with equal weighting.

        Args:
            reports: Pre-computed reports from check_all() to avoid re-running checks

        Returns:
            Overall compliance score
        """
        all_reports = reports if reports is not None else self.check_all()
        if not all_reports:
            return 0.0

        total_score = sum(report.score for report in all_reports.values())
        return total_score / len(all_reports)

    # ========================================================================
    # Internal Check Logic
    # ========================================================================

    def _check_standard(self, standard: ComplianceStandard) -> ComplianceReport:
        """
        Check all controls for a given standard.

        Args:
            standard: Compliance standard to check

        Returns:
            Compliance report
        """
        controls = get_controls_for_standard(standard)
        results = []

        for control in controls:
            try:
                check_method = self._find_check_method(control.check_func)
                result = check_method(control)
                results.append(result)
            except AttributeError:
                logger.warning(
                    f"Check method not found: {control.check_func} for {control.control_id}"
                )
                results.append(
                    ControlCheck(
                        control_id=control.control_id,
                        name=control.name,
                        description=control.description,
                        standard=standard,
                        status=ControlStatus.FAILED,
                        evidence=[],
                        recommendations=[f"Check method {control.check_func} not implemented"],
                    )
                )
            except Exception as e:
                logger.exception(f"Error checking {control.control_id}: {e}")
                results.append(
                    ControlCheck(
                        control_id=control.control_id,
                        name=control.name,
                        description=control.description,
                        standard=standard,
                        status=ControlStatus.FAILED,
                        evidence=[],
                        recommendations=[f"Error during check: {str(e)}"],
                    )
                )

        # Categorize results
        passed = [r for r in results if r.status == ControlStatus.PASSED]
        failed = [r for r in results if r.status == ControlStatus.FAILED]
        partial = [r for r in results if r.status == ControlStatus.PARTIAL]

        # Calculate score
        score = self._calculate_score(results, controls)

        # Aggregate recommendations
        all_recommendations = []
        for result in failed + partial:
            all_recommendations.extend(result.recommendations)

        return ComplianceReport(
            standard=standard,
            score=score,
            passed_controls=passed,
            failed_controls=failed,
            partial_controls=partial,
            recommendations=all_recommendations,
            generated_at=datetime.now(UTC),
        )

    def _calculate_score(
        self, results: list[ControlCheck], controls: list[ControlDefinition]
    ) -> float:
        """
        Calculate compliance score (0-100) based on control results.

        Weights controls by importance and calculates percentage of
        maximum possible weighted score.

        Args:
            results: List of control check results
            controls: List of control definitions (for weights)

        Returns:
            Score from 0-100
        """
        if not results:
            return 0.0

        # Build control weight map
        weight_map = {c.control_id: c.weight for c in controls}

        total_weight = 0.0
        earned_weight = 0.0

        for result in results:
            weight = weight_map.get(result.control_id, 1.0)
            total_weight += weight

            if result.status == ControlStatus.PASSED:
                earned_weight += weight
            elif result.status == ControlStatus.PARTIAL:
                earned_weight += weight * 0.5  # Partial credit
            # Failed or N/A = 0 weight

        if total_weight == 0:
            return 0.0

        return (earned_weight / total_weight) * 100.0


# Singleton instance
_compliance_checker: ComplianceChecker | None = None


def get_compliance_checker(settings: Settings | None = None) -> ComplianceChecker:
    """
    Get singleton compliance checker instance.

    Args:
        settings: Settings to use (if None, loads from singleton)

    Returns:
        ComplianceChecker instance
    """
    global _compliance_checker

    if settings is None:
        from pdfsigner.config.settings import get_settings

        settings = get_settings()

    # Recreate if settings changed
    if _compliance_checker is None or _compliance_checker.settings is not settings:
        _compliance_checker = ComplianceChecker(settings)

    return _compliance_checker

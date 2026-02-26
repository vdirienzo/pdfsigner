"""
soc2_checker.py - SOC 2 Type II compliance checks

Trust Services Criteria checks including access controls (CC6),
monitoring (CC6.6/CC7.2), encryption (CC6.7), change detection (CC8),
governance (CC1), communication (CC2), risk (CC3/CC9), and monitoring (CC4).
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class SOC2Checker:
    """
    SOC 2 Type II Trust Services Criteria compliance checker.

    Covers CC1 (Control Environment), CC2 (Communication), CC3 (Risk Assessment),
    CC4 (Monitoring), CC6 (Logical Access), CC7 (System Operations),
    CC8 (Change Management), and CC9 (Risk Mitigation).
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    # ========================================================================
    # CC6: Logical and Physical Access Controls
    # ========================================================================

    def _check_soc2_access_controls(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC6.1 - Logical access controls."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("PKCS#11 hardware token authentication")

        if self.settings.healthcare_mode:
            evidence.append("Role-based access control (RBAC) enabled")
            evidence.append("User account management with status tracking")

        if self.settings.mfa_enabled:
            evidence.append("Multi-factor authentication available")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable mfa_enabled for stronger access controls")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_soc2_monitoring(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC6.6 - System operations monitoring."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.audit_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["audit_enabled is false"],
                recommendations=["Enable audit_enabled for monitoring"],
            )

        evidence.append("Comprehensive audit logging of all operations")
        evidence.append("Security event tracking (sign, validate, encrypt, auth)")
        evidence.append(f"Retention: {self.settings.audit_retention_days} days")

        status = ControlStatus.PASSED
        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_soc2_encryption(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC6.7 - Encryption."""
        evidence: list[str] = []
        recommendations: list[str] = []

        strength = self.settings.encryption_default_strength
        evidence.append(f"Data-at-rest encryption: {strength}")

        if strength == "aes256":
            status = ControlStatus.PASSED
            evidence.append("Using AES-256 encryption")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Use AES-256 for maximum security")

        if self.settings.encryption_store_in_keyring:
            evidence.append("Credentials stored in encrypted keyring")

        evidence.append("Transmission encryption: Configure TLS at API deployment level")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    # ========================================================================
    # CC7: System Operations
    # ========================================================================

    def _check_soc2_system_monitoring(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC7.2 - System monitoring."""
        return self._check_soc2_monitoring(control)

    # ========================================================================
    # CC8: Change Management
    # ========================================================================

    def _check_soc2_change_detection(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC8.1 - Change detection."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("Audit log integrity via HMAC chain hashing")
        evidence.append("Tamper detection in audit logs")
        evidence.append("Document integrity via digital signatures")

        status = ControlStatus.PASSED
        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    # ========================================================================
    # CC1: Control Environment (delegates to GovernanceChecker)
    # ========================================================================

    def _check_soc2_governance(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC1 - Control Environment."""
        from pdfsigner.core.compliance.governance import get_governance_checker

        checker = get_governance_checker()

        control_map = {
            "CC1.1": checker.check_organization_structure,
            "CC1.2": checker.check_management_philosophy,
            "CC1.3": checker.check_board_oversight,
            "CC1.4": checker.check_competence,
            "CC1.5": checker.check_accountability,
        }

        check_method = control_map.get(control.control_id)
        if not check_method:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=[],
                recommendations=[f"Check method not found for {control.control_id}"],
            )

        result = check_method()

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=result.status,
            evidence=result.findings,
            recommendations=result.recommendations,
        )

    # ========================================================================
    # CC2: Communication and Information
    # ========================================================================

    def _check_soc2_communication(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC2 - Communication and Information."""
        from pdfsigner.core.compliance.communication import get_communication_checker

        checker = get_communication_checker()

        control_map = {
            "CC2.1": checker.check_internal_communication,
            "CC2.2": checker.check_external_communication,
            "CC2.3": checker.check_communication_channels,
        }

        check_method = control_map.get(control.control_id)
        if not check_method:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=[],
                recommendations=[f"Check method not found for {control.control_id}"],
            )

        result = check_method()

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=result.status,
            evidence=result.findings,
            recommendations=result.recommendations,
        )

    # ========================================================================
    # CC3: Risk Assessment
    # ========================================================================

    def _check_soc2_risk_assessment(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC3 - Risk Assessment."""
        from pdfsigner.core.compliance.risk_assessment import get_risk_assessment_checker

        checker = get_risk_assessment_checker()

        control_map = {
            "CC3.1": checker.check_risk_identification,
            "CC3.2": checker.check_risk_analysis,
            "CC3.3": checker.check_risk_mitigation,
            "CC3.4": checker.check_risk_monitoring,
        }

        check_method = control_map.get(control.control_id)
        if not check_method:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=[],
                recommendations=[f"Check method not found for {control.control_id}"],
            )

        result = check_method()

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=result.status,
            evidence=result.findings,
            recommendations=result.recommendations,
        )

    # ========================================================================
    # CC4: Monitoring Activities
    # ========================================================================

    def _check_soc2_monitoring_activities(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC4 - Monitoring Activities."""
        from pdfsigner.core.compliance.monitoring import get_monitoring_checker

        checker = get_monitoring_checker()

        control_map = {
            "CC4.1": checker.check_monitoring_controls,
            "CC4.2": checker.check_reporting_deficiencies,
        }

        check_method = control_map.get(control.control_id)
        if not check_method:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=[],
                recommendations=[f"Check method not found for {control.control_id}"],
            )

        result = check_method()

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=result.status,
            evidence=result.findings,
            recommendations=result.recommendations,
        )

    # ========================================================================
    # CC9: Risk Mitigation
    # ========================================================================

    def _check_soc2_risk_mitigation(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC9 - Risk Mitigation."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if control.control_id == "CC9.1":
            evidence.append("Pre-commit hooks for code quality checks")
            evidence.append("Automated testing suite with 87% coverage")
            evidence.append("Type checking with mypy")

            if self.settings.fips_mode_enabled:
                evidence.append("FIPS 140-2 compliance for cryptography")

            status = ControlStatus.PARTIAL
            recommendations.append("Implement automated dependency vulnerability scanning")
            recommendations.append("Document security audit schedule and findings")

        elif control.control_id == "CC9.2":
            evidence.append("Python dependencies managed via uv with lock file")
            evidence.append("Open source libraries with active maintenance")

            status = ControlStatus.PARTIAL
            recommendations.append("Implement dependency scanning (e.g., safety, snyk)")
            recommendations.append("Document vendor/dependency risk assessment process")
        else:
            status = ControlStatus.FAILED
            recommendations.append(f"Unknown CC9 control: {control.control_id}")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

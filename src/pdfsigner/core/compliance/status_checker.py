"""
status_checker.py - HIPAA compliance status monitoring

Author: Homero Thompson del Lago del Terror

Monitors HIPAA compliance status across all implemented controls:
- Encryption (§164.312(a)(2)(iv))
- Audit Controls (§164.312(b))
- Access Control (§164.312(a)(1))
- Session Management (§164.312(a)(2)(iii))
- Temp File Security (§164.310(d)(1))
- PHI Detection (§164.514)
- Emergency Access (§164.312(a)(2)(ii))
"""

from loguru import logger

# Re-export types for backwards compatibility
from pdfsigner.core.compliance.status_types import (
    ComplianceCategory,
    ComplianceCheck,
    ComplianceReport,
    ComplianceStatus,
)

__all__ = [
    "ComplianceCategory",
    "ComplianceCheck",
    "ComplianceReport",
    "ComplianceStatus",
    "ComplianceStatusChecker",
    "get_compliance_checker",
]


class ComplianceStatusChecker:
    """
    Checks HIPAA compliance status of PDFSigner configuration.

    Singleton pattern - use get_compliance_checker() to obtain instance.
    """

    def __init__(self):
        """Initialize compliance checker."""
        self._settings = None

    @property
    def settings(self):
        """
        Lazy-load settings to avoid circular imports.

        Returns:
            PDFSigner settings instance
        """
        if self._settings is None:
            from pdfsigner.config.settings import get_settings

            self._settings = get_settings()
        return self._settings

    def check_all(self) -> ComplianceReport:
        """
        Run all compliance checks and return report.

        Returns:
            ComplianceReport with results from all checks
        """
        logger.info("Running HIPAA compliance checks")

        checks = [
            self._check_encryption(),
            self._check_audit_controls(),
            self._check_access_control(),
            self._check_session_management(),
            self._check_temp_file_security(),
            self._check_phi_detection(),
            self._check_emergency_access(),
        ]

        compliant = sum(1 for c in checks if c.status == ComplianceStatus.COMPLIANT)
        warning = sum(1 for c in checks if c.status == ComplianceStatus.WARNING)
        non_compliant = sum(1 for c in checks if c.status == ComplianceStatus.NON_COMPLIANT)

        if non_compliant > 0:
            overall = ComplianceStatus.NON_COMPLIANT
        elif warning > 0:
            overall = ComplianceStatus.WARNING
        else:
            overall = ComplianceStatus.COMPLIANT

        logger.info(
            f"Compliance check complete: {compliant} compliant, "
            f"{warning} warnings, {non_compliant} non-compliant"
        )

        return ComplianceReport(
            checks=checks,
            overall_status=overall,
            compliant_count=compliant,
            warning_count=warning,
            non_compliant_count=non_compliant,
        )

    def _check_encryption(self) -> ComplianceCheck:
        """
        Check encryption configuration §164.312(a)(2)(iv).

        Returns:
            ComplianceCheck for encryption settings
        """
        settings = self.settings

        if not settings.healthcare_mode:
            return ComplianceCheck(
                name="PDF Encryption",
                category=ComplianceCategory.ENCRYPTION,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.312(a)(2)(iv)",
                description="Encryption and decryption capability",
                details="Healthcare mode is disabled. Encryption not enforced.",
                remediation="Enable healthcare_mode in settings",
            )

        if settings.encryption_default_strength == "aes256":
            return ComplianceCheck(
                name="PDF Encryption",
                category=ComplianceCategory.ENCRYPTION,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.312(a)(2)(iv)",
                description="Encryption and decryption capability",
                details="AES-256 encryption enabled (HIPAA compliant)",
            )
        else:
            return ComplianceCheck(
                name="PDF Encryption",
                category=ComplianceCategory.ENCRYPTION,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.312(a)(2)(iv)",
                description="Encryption and decryption capability",
                details=f"Using {settings.encryption_default_strength}. AES-256 recommended.",
                remediation="Set encryption_default_strength to 'aes256'",
            )

    def _check_audit_controls(self) -> ComplianceCheck:
        """
        Check audit trail configuration §164.312(b).

        Returns:
            ComplianceCheck for audit controls
        """
        from pdfsigner.core.compliance.status_helpers import check_audit_controls

        return check_audit_controls(self.settings)

    def _check_access_control(self) -> ComplianceCheck:
        """
        Check RBAC configuration §164.312(a)(1).

        Returns:
            ComplianceCheck for access control
        """
        settings = self.settings

        if not settings.healthcare_mode:
            return ComplianceCheck(
                name="Access Control",
                category=ComplianceCategory.ACCESS_CONTROL,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.312(a)(1)",
                description="Role-based access control",
                details="Healthcare mode disabled. RBAC not enforced.",
                remediation="Enable healthcare_mode in settings",
            )

        return ComplianceCheck(
            name="Access Control",
            category=ComplianceCategory.ACCESS_CONTROL,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(a)(1)",
            description="Role-based access control",
            details="RBAC enabled with 5 roles and 10 permissions",
        )

    def _check_session_management(self) -> ComplianceCheck:
        """
        Check session timeout configuration §164.312(a)(2)(iii).

        Returns:
            ComplianceCheck for session management
        """
        from pdfsigner.core.compliance.status_helpers import check_session_management

        return check_session_management(self.settings)

    def _check_temp_file_security(self) -> ComplianceCheck:
        """
        Check secure temp file handling §164.310(d)(1).

        Returns:
            ComplianceCheck for temp file security
        """
        settings = self.settings

        if settings.temp_secure_delete:
            return ComplianceCheck(
                name="Temp File Security",
                category=ComplianceCategory.TEMP_FILE_SECURITY,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.310(d)(1)",
                description="Secure deletion of temporary files",
                details="DoD 5220.22-M secure deletion enabled",
            )
        else:
            return ComplianceCheck(
                name="Temp File Security",
                category=ComplianceCategory.TEMP_FILE_SECURITY,
                status=ComplianceStatus.NON_COMPLIANT,
                hipaa_reference="§164.310(d)(1)",
                description="Secure deletion of temporary files",
                details="Secure deletion is disabled",
                remediation="Set temp_secure_delete to true",
            )

    def _check_phi_detection(self) -> ComplianceCheck:
        """
        Check PHI detection configuration §164.514.

        Returns:
            ComplianceCheck for PHI detection
        """
        settings = self.settings

        if settings.phi_detection_enabled:
            return ComplianceCheck(
                name="PHI Detection",
                category=ComplianceCategory.PHI_DETECTION,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.514",
                description="Detection of Protected Health Information",
                details="PHI scanning enabled before document operations",
            )
        else:
            return ComplianceCheck(
                name="PHI Detection",
                category=ComplianceCategory.PHI_DETECTION,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.514",
                description="Detection of Protected Health Information",
                details="PHI detection is not enabled",
                remediation="Consider enabling phi_detection_enabled",
            )

    def _check_emergency_access(self) -> ComplianceCheck:
        """
        Check emergency access procedure §164.312(a)(2)(ii).

        Returns:
            ComplianceCheck for emergency access
        """
        settings = self.settings

        if not settings.healthcare_mode:
            return ComplianceCheck(
                name="Emergency Access",
                category=ComplianceCategory.EMERGENCY_ACCESS,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.312(a)(2)(ii)",
                description="Emergency access procedure (break-glass)",
                details="Healthcare mode disabled. Emergency access not configured.",
                remediation="Enable healthcare_mode in settings",
            )

        if settings.healthcare_emergency_require_approval:
            status = ComplianceStatus.COMPLIANT
            details = "Emergency access requires admin approval"
            remediation = None
        else:
            status = ComplianceStatus.WARNING
            details = "Emergency access does not require approval"
            remediation = "Enable healthcare_emergency_require_approval"

        return ComplianceCheck(
            name="Emergency Access",
            category=ComplianceCategory.EMERGENCY_ACCESS,
            status=status,
            hipaa_reference="§164.312(a)(2)(ii)",
            description="Emergency access procedure (break-glass)",
            details=details,
            remediation=remediation,
        )


# Singleton
_compliance_checker: ComplianceStatusChecker | None = None


def get_compliance_checker() -> ComplianceStatusChecker:
    """
    Get ComplianceStatusChecker singleton instance.

    Returns:
        ComplianceStatusChecker instance
    """
    global _compliance_checker
    if _compliance_checker is None:
        _compliance_checker = ComplianceStatusChecker()
    return _compliance_checker

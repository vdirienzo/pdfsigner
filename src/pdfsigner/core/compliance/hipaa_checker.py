"""
hipaa_checker.py - HIPAA Security Rule compliance checks (§164.312)

Extracts HIPAA-specific control checks from the main ComplianceChecker
to follow Single Responsibility Principle.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class HIPAAChecker:
    """
    HIPAA Security Rule (§164.312) compliance checker.

    Checks PDFSigner configuration against HIPAA technical safeguards
    including access control, audit, integrity, and authentication.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def _check_hipaa_unique_user_id(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(a)(1) - Unique user identification."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.healthcare_mode:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["healthcare_mode is disabled"],
                recommendations=["Enable healthcare_mode to activate user registry and tracking"],
            )

        evidence.append("User registry available via UserRepository")
        evidence.append(f"Healthcare mode enabled: {self.settings.healthcare_mode}")

        if self.settings.audit_enabled:
            evidence.append(
                f"Audit logging enabled with {self.settings.audit_retention_days} day retention"
            )
            status = ControlStatus.PASSED
        else:
            evidence.append("Audit logging is disabled - cannot track user activity")
            status = ControlStatus.PARTIAL
            recommendations.append("Enable audit_enabled to track individual user activity")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_emergency_access(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(a)(2)(i) - Emergency access procedure."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.healthcare_mode:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["healthcare_mode is disabled"],
                recommendations=["Enable healthcare_mode to activate emergency access features"],
            )

        evidence.append("Emergency access repository available")
        evidence.append(
            f"Emergency access duration: {self.settings.healthcare_emergency_duration_hours} hours"
        )

        approval_required = self.settings.healthcare_emergency_require_approval
        evidence.append(f"Admin approval required: {approval_required}")

        if approval_required:
            status = ControlStatus.PASSED
            evidence.append("Emergency access requires admin approval for audit trail")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Set healthcare_emergency_require_approval=true for stronger controls"
            )

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_automatic_logoff(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(a)(2)(iii) - Automatic logoff."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.healthcare_mode:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["healthcare_mode is disabled"],
                recommendations=["Enable healthcare_mode to activate session timeout"],
            )

        timeout_minutes = self.settings.healthcare_session_timeout_minutes
        evidence.append(f"Session timeout configured: {timeout_minutes} minutes")
        evidence.append(f"Maximum concurrent sessions: {self.settings.healthcare_max_sessions}")

        if timeout_minutes <= 15:
            status = ControlStatus.PASSED
            evidence.append("Session timeout meets recommended 15-minute threshold")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Set healthcare_session_timeout_minutes to 15 or less for optimal compliance"
            )

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_encryption(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(a)(2)(iv) - Encryption and decryption."""
        evidence: list[str] = []
        recommendations: list[str] = []

        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        if strength == "aes256":
            status = ControlStatus.PASSED
            evidence.append("Using AES-256 encryption (HIPAA recommended)")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Set encryption_default_strength='aes256' for optimal compliance"
            )

        if self.settings.encryption_hipaa_mode:
            evidence.append("HIPAA encryption mode enabled (enforces strict settings)")
        else:
            recommendations.append(
                "Enable encryption_hipaa_mode to enforce HIPAA-compliant encryption defaults"
            )

        if self.settings.encryption_store_in_keyring:
            evidence.append("Credentials stored securely in system keyring")
        else:
            evidence.append("Credentials not stored in keyring")
            recommendations.append(
                "Enable encryption_store_in_keyring for secure credential storage"
            )

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_audit_controls(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(b) - Audit controls."""
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
                recommendations=["Enable audit_enabled to meet HIPAA audit requirements"],
            )

        evidence.append(
            f"Audit logging enabled with {self.settings.audit_retention_days} day retention"
        )

        if self.settings.audit_retention_days >= 2190:  # ~6 years
            evidence.append("Audit retention meets HIPAA 6-year requirement")
            status = ControlStatus.PASSED
        elif self.settings.audit_retention_days >= 365:
            evidence.append("Audit retention is at least 1 year")
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Set audit_retention_days to 2190+ days (6 years) for full HIPAA compliance"
            )
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Increase audit_retention_days to at least 365 days (HIPAA recommends 6 years)"
            )

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_integrity(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(c)(1) - Integrity mechanism."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("PDF digital signatures via PKCS#11 tokens")
        evidence.append("PAdES-LTA support for long-term validation")

        if self.settings.ltv_enabled:
            evidence.append("LTV (DSS) embedding enabled for signature validation info")
        else:
            recommendations.append("Enable ltv_enabled for long-term signature validation")

        if self.settings.archive_ts_enabled:
            evidence.append("Archive timestamps enabled for PAdES-LTA compliance")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Enable archive_ts_enabled for long-term document integrity (PAdES-LTA)"
            )

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_hipaa_authentication(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(d) - Person authentication."""
        evidence: list[str] = []
        recommendations: list[str] = []

        nss_path = self.settings.nss_db_path
        evidence.append(f"PKCS#11 token authentication via NSS database: {nss_path}")

        if self.settings.healthcare_mode:
            evidence.append("Certificate binding to user accounts enabled")

        if self.settings.mfa_enabled:
            evidence.append("Multi-factor authentication (MFA) enabled")
            required_roles = self.settings.mfa_required_for_roles
            evidence.append(f"MFA required for roles: {', '.join(required_roles)}")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable mfa_enabled and require MFA for administrative roles")

        min_length = self.settings.password_min_length
        evidence.append(f"Password minimum length: {min_length} characters")

        if min_length >= 12:
            evidence.append("Password policy meets NIST recommendations (12+ chars)")
        else:
            recommendations.append("Set password_min_length to 12+ for stronger authentication")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

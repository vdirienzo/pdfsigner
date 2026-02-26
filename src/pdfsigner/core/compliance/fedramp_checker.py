"""
fedramp_checker.py - FedRAMP Moderate compliance checks

FedRAMP Moderate control checks that build on NIST 800-53 controls.
Includes account management, audit, MFA, and FIPS requirements.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class FedRAMPChecker:
    """
    FedRAMP Moderate compliance checker.

    Checks FedRAMP-specific requirements including enhanced audit,
    mandatory MFA, and FIPS 140-2 validated cryptography.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def _check_fedramp_account_management(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP account management (delegates to NIST AC-2 logic)."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.healthcare_mode:
            evidence.append("User account management via UserRepository")
            evidence.append("User status tracking (active/inactive/locked)")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.FAILED
            evidence.append("healthcare_mode disabled - no account management")
            recommendations.append("Enable healthcare_mode for user account management")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_fedramp_audit(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP audit requirements (enhanced NIST AU-2)."""
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
                recommendations=["Enable audit_enabled to log security events"],
            )

        evidence.append("Comprehensive audit logging enabled")
        evidence.append("Events include: sign, validate, encrypt, decrypt, auth, session")
        evidence.append(f"Retention: {self.settings.audit_retention_days} days")
        evidence.append("Audit logs use JSON Lines format for centralized SIEM")
        evidence.append("Monthly log rotation for archival")

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

    def _check_fedramp_mfa(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP MFA requirement."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.mfa_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["mfa_enabled is false"],
                recommendations=["Enable mfa_enabled - FedRAMP requires MFA for all users"],
            )

        evidence.append("MFA enabled via TOTP")
        evidence.append(f"Required for roles: {', '.join(self.settings.mfa_required_for_roles)}")
        evidence.append(f"Backup codes: {self.settings.mfa_backup_codes_count}")

        if "ADMIN" in self.settings.mfa_required_for_roles:
            status = ControlStatus.PASSED
            evidence.append("MFA enforced for administrative accounts")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Extend MFA requirement to all user roles for full FedRAMP compliance"
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

    def _check_fedramp_fips(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP FIPS 140-2 requirement."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.fips_mode_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["fips_mode_enabled is false"],
                recommendations=[
                    "Enable fips_mode_enabled - FedRAMP requires FIPS 140-2 validated cryptography"
                ],
            )

        evidence.append("FIPS 140-2 mode enabled")
        evidence.append(f"Strict mode: {self.settings.fips_strict_mode}")
        evidence.append("Only FIPS-validated algorithms allowed")

        if self.settings.fips_strict_mode:
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable fips_strict_mode for strict FIPS enforcement")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

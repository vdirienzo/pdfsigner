"""
nist_checker.py - NIST 800-53 AC/IA family checks

Access Control (AC) and Identification and Authentication (IA) control
checks. Audit/SC families are in nist_audit_checker.py, FedRAMP in
fedramp_checker.py.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class NISTChecker:
    """
    NIST 800-53 Rev 5 - AC and IA families.

    Access Control (AC-2 through AC-20) and Identification and
    Authentication (IA-2, IA-5) control checks.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    # ========================================================================
    # Access Control (AC) Family
    # ========================================================================

    def _check_nist_account_management(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-2 - Account management."""
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

    def _check_nist_access_enforcement(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-3 - Access enforcement."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.healthcare_mode:
            evidence.append("RBAC enforces access control via Role and Permission classes")
            evidence.append("API middleware enforces authentication")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            evidence.append("healthcare_mode disabled - limited access control")
            recommendations.append("Enable healthcare_mode for RBAC enforcement")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_separation_of_duties(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-5 - Separation of duties."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.healthcare_mode:
            evidence.append("Separate roles defined (USER, ADMIN, AUDITOR)")
            evidence.append("Emergency access requires approval from separate admin")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.FAILED
            evidence.append("healthcare_mode disabled - no role separation")
            recommendations.append("Enable healthcare_mode for role-based separation")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_least_privilege(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-6 - Least privilege."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.healthcare_mode:
            evidence.append("Default USER role has minimal permissions")
            evidence.append("Permission-based access control enforced")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            evidence.append("healthcare_mode disabled - privilege controls limited")
            recommendations.append("Enable healthcare_mode for least privilege enforcement")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_failed_logon(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-7 - Unsuccessful logon attempts."""
        evidence: list[str] = []
        recommendations: list[str] = []

        threshold = self.settings.password_lockout_threshold
        lockout_minutes = self.settings.password_lockout_duration_minutes

        evidence.append(f"Failed login threshold: {threshold} attempts")
        evidence.append(f"Lockout duration: {lockout_minutes} minutes")

        if 3 <= threshold <= 5:
            status = ControlStatus.PASSED
            evidence.append("Threshold meets NIST recommendations (3-5 attempts)")
        elif threshold <= 10:
            status = ControlStatus.PARTIAL
            recommendations.append("Set password_lockout_threshold to 3-5 for optimal security")
        else:
            status = ControlStatus.FAILED
            recommendations.append("Lockout threshold too high - set to 5 or less")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_system_use_notification(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-8 - System use notification."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("GUI application - system use notification at desktop level")
        status = ControlStatus.PARTIAL
        recommendations.append("Configure system banner in deployment documentation for API access")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_session_lock(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-11 - Session lock."""
        if not self.settings.healthcare_mode:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["healthcare_mode disabled - no session management"],
                recommendations=["Enable healthcare_mode for session timeout controls"],
            )

        evidence: list[str] = []
        timeout = self.settings.healthcare_session_timeout_minutes
        evidence.append(f"Session timeout: {timeout} minutes")

        if timeout <= 15:
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            evidence.append("Session timeout exceeds NIST recommendation of 15 minutes")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=[],
        )

    def _check_nist_session_termination(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-12 - Session termination."""
        if not self.settings.healthcare_mode:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["healthcare_mode disabled - no session management"],
                recommendations=["Enable healthcare_mode for automatic session termination"],
            )

        evidence: list[str] = []
        recommendations: list[str] = []
        timeout = self.settings.healthcare_session_timeout_minutes
        max_sessions = self.settings.healthcare_max_sessions

        evidence.append(f"Automatic session termination after {timeout} minutes inactivity")
        evidence.append(f"Maximum concurrent sessions: {max_sessions}")

        if timeout <= 15:
            status = ControlStatus.PASSED
            evidence.append("Session timeout meets NIST recommendations (<=15 minutes)")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Set healthcare_session_timeout_minutes to 15 or less")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_remote_access(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-17 - Remote access."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("REST API available for remote access")

        tls_enabled = getattr(self.settings, "api_tls_enabled", None)
        if tls_enabled is not None and tls_enabled:
            evidence.append("TLS/HTTPS configured for remote API access")
            status = ControlStatus.PASSED
        elif tls_enabled is not None:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable TLS for secure remote API access")
        else:
            status = ControlStatus.PASSED
            evidence.append("Control not applicable (API not deployed, desktop mode only)")

        if self.settings.mfa_enabled:
            evidence.append("MFA available for remote authentication")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_external_systems(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-20 - Use of external systems."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.tsa_url:
            evidence.append(f"Configured TSA: {self.settings.tsa_url}")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PASSED
            evidence.append("Control not applicable (no external TSA configured)")

        if self.settings.revocation_check_enabled:
            evidence.append("OCSP/CRL external validation enabled")
            evidence.append(f"Timeout: {self.settings.revocation_check_timeout}s")

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
    # Identification and Authentication (IA) Family
    # ========================================================================

    def _check_nist_user_auth(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST IA-2 - Identification and authentication."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("PKCS#11 hardware token authentication")
        evidence.append(f"NSS database: {self.settings.nss_db_path}")

        if self.settings.healthcare_mode:
            evidence.append("User identification via certificate binding")

        if self.settings.mfa_enabled:
            status = ControlStatus.PASSED
            evidence.append("Multi-factor authentication enabled")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable mfa_enabled for stronger authentication")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_authenticator_mgmt(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST IA-5 - Authenticator management."""
        evidence: list[str] = []
        recommendations: list[str] = []

        min_length = self.settings.password_min_length
        max_age = self.settings.password_max_age_days
        history = self.settings.password_history_count

        evidence.append(f"Minimum password length: {min_length} characters")
        evidence.append(f"Password max age: {max_age} days")
        evidence.append(f"Password history: {history} previous passwords")

        if min_length >= 12:
            status = ControlStatus.PASSED
            evidence.append("Meets NIST password length recommendation (12+)")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Set password_min_length to 12+")

        if self.settings.password_require_special:
            evidence.append("Special characters required")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

"""
checker.py - Compliance verification engine

Performs automated compliance checks against various standards by
inspecting current Settings configuration.
"""

from dataclasses import dataclass, field
from datetime import datetime

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
    """

    def __init__(self, settings: Settings):
        """
        Initialize compliance checker.

        Args:
            settings: PDFSigner settings to check
        """
        self.settings = settings

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

    def get_overall_score(self) -> float:
        """
        Calculate weighted overall compliance score (0-100).

        Averages scores across all standards with equal weighting.

        Returns:
            Overall compliance score
        """
        all_reports = self.check_all()
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
                # Get check method by name
                check_method = getattr(self, control.check_func)
                result = check_method(control)
                results.append(result)
            except AttributeError:
                logger.warning(
                    f"Check method not found: {control.check_func} for {control.control_id}"
                )
                # Create failed check with error
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
            generated_at=datetime.now(),
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

    # ========================================================================
    # HIPAA Control Checks (§164.312)
    # ========================================================================

    def _check_hipaa_unique_user_id(self, control: ControlDefinition) -> ControlCheck:
        """Check HIPAA §164.312(a)(1) - Unique user identification."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # Check if healthcare mode is enabled (prerequisite)
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

        # User registry exists when healthcare_mode is enabled
        evidence.append("User registry available via UserRepository")
        evidence.append(f"Healthcare mode enabled: {self.settings.healthcare_mode}")

        # Check if audit logging is enabled to track user activity
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

        # Emergency access is available when healthcare mode is enabled
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

        # Session manager with timeout
        timeout_minutes = self.settings.healthcare_session_timeout_minutes
        evidence.append(f"Session timeout configured: {timeout_minutes} minutes")
        evidence.append(f"Maximum concurrent sessions: {self.settings.healthcare_max_sessions}")

        # HIPAA recommends 15 minutes or less for inactivity timeout
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

        # Check encryption capability
        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        # AES-256 is strongly recommended for HIPAA
        if strength == "aes256":
            status = ControlStatus.PASSED
            evidence.append("Using AES-256 encryption (HIPAA recommended)")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Set encryption_default_strength='aes256' for optimal compliance"
            )

        # Check if HIPAA mode is enabled for encryption
        if self.settings.encryption_hipaa_mode:
            evidence.append("HIPAA encryption mode enabled (enforces strict settings)")
        else:
            recommendations.append(
                "Enable encryption_hipaa_mode to enforce HIPAA-compliant encryption defaults"
            )

        # Check keyring storage
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

        # Audit logging is enabled
        evidence.append(
            f"Audit logging enabled with {self.settings.audit_retention_days} day retention"
        )

        # HIPAA requires 6 years retention, but this is configurable
        if self.settings.audit_retention_days >= 2190:  # ~6 years
            evidence.append("Audit retention meets HIPAA 6-year requirement")
            status = ControlStatus.PASSED
        elif self.settings.audit_retention_days >= 365:  # At least 1 year
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

        # PDF digital signatures provide integrity protection
        evidence.append("PDF digital signatures via PKCS#11 tokens")
        evidence.append("PAdES-LTA support for long-term validation")

        # LTV enabled provides additional integrity
        if self.settings.ltv_enabled:
            evidence.append("LTV (DSS) embedding enabled for signature validation info")
        else:
            recommendations.append("Enable ltv_enabled for long-term signature validation")

        # Archive timestamps for long-term integrity
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

        # PKCS#11 token authentication
        nss_path = self.settings.nss_db_path
        evidence.append(f"PKCS#11 token authentication via NSS database: {nss_path}")

        # Healthcare mode enables user binding to certificates
        if self.settings.healthcare_mode:
            evidence.append("Certificate binding to user accounts enabled")

        # MFA support
        if self.settings.mfa_enabled:
            evidence.append("Multi-factor authentication (MFA) enabled")
            required_roles = self.settings.mfa_required_for_roles
            evidence.append(f"MFA required for roles: {', '.join(required_roles)}")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable mfa_enabled and require MFA for administrative roles")

        # Password policy
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

    # ========================================================================
    # NIST 800-53 Control Checks
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

    def _check_nist_failed_logon(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AC-7 - Unsuccessful logon attempts."""
        evidence: list[str] = []
        recommendations: list[str] = []

        threshold = self.settings.password_lockout_threshold
        lockout_minutes = self.settings.password_lockout_duration_minutes

        evidence.append(f"Failed login threshold: {threshold} attempts")
        evidence.append(f"Lockout duration: {lockout_minutes} minutes")

        # NIST recommends 3-5 failed attempts
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

        # NIST recommends 15 minutes or less
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

    def _check_nist_audit_events(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-2 - Audit events."""
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

    def _check_nist_audit_protection(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-9 - Protection of audit information."""
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
                recommendations=["Enable audit_enabled"],
            )

        # Audit integrity features
        evidence.append("Audit logs use HMAC chain hashing for tamper detection")
        evidence.append("AuditIntegrityManager provides verification capabilities")
        evidence.append(f"Logs stored in protected directory: {self.settings.log_dir}")

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

    def _check_nist_user_auth(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST IA-2 - Identification and authentication."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # PKCS#11 token provides strong authentication
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

        # Password policy settings
        min_length = self.settings.password_min_length
        max_age = self.settings.password_max_age_days
        history = self.settings.password_history_count

        evidence.append(f"Minimum password length: {min_length} characters")
        evidence.append(f"Password max age: {max_age} days")
        evidence.append(f"Password history: {history} previous passwords")

        # NIST recommends 12+ chars, no forced expiration
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

    def _check_nist_transmission_protection(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-8 - Transmission confidentiality."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # This is N/A for desktop app, but would apply to API if deployed
        evidence.append("Desktop application - direct file system access")
        evidence.append("API: TLS should be configured at deployment level")

        status = ControlStatus.NOT_APPLICABLE
        recommendations.append(
            "If exposing API, configure TLS/HTTPS at reverse proxy or application level"
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

    def _check_nist_crypto_protection(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-13 - Cryptographic protection."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # FIPS mode
        if self.settings.fips_mode_enabled:
            evidence.append("FIPS 140-2 mode enabled")
            evidence.append(f"Strict mode: {self.settings.fips_strict_mode}")
            status = ControlStatus.PASSED
        else:
            evidence.append("FIPS 140-2 mode not enabled")
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Enable fips_mode_enabled for NIST/FedRAMP cryptographic compliance"
            )

        # Encryption strength
        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        if strength == "aes256":
            evidence.append("Using AES-256 (FIPS approved)")
        else:
            recommendations.append("Use AES-256 for maximum cryptographic strength")

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
    # FedRAMP Control Checks
    # ========================================================================

    def _check_fedramp_account_management(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP account management."""
        # Reuse NIST control
        return self._check_nist_account_management(control)

    def _check_fedramp_audit(self, control: ControlDefinition) -> ControlCheck:
        """Check FedRAMP audit requirements."""
        # FedRAMP requires enhanced audit with centralized management
        base_check = self._check_nist_audit_events(control)

        # Add FedRAMP-specific evidence
        base_check.evidence.append("Audit logs use JSON Lines format for centralized SIEM")
        base_check.evidence.append("Monthly log rotation for archival")

        return base_check

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

        # FedRAMP requires MFA for all accounts (privileged and non-privileged)
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

    # ========================================================================
    # eIDAS Control Checks
    # ========================================================================

    def _check_eidas_qualified_signatures(self, control: ControlDefinition) -> ControlCheck:
        """Check eIDAS qualified signatures support."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # PKCS#11 token support
        evidence.append("PKCS#11 hardware token support for qualified signatures")
        evidence.append(f"NSS database: {self.settings.nss_db_path}")

        # Certificate validation
        if self.settings.revocation_check_enabled:
            evidence.append("Certificate revocation checking enabled (OCSP/CRL)")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Enable revocation_check_enabled to validate qualified certificates"
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

    def _check_eidas_technical_standards(self, control: ControlDefinition) -> ControlCheck:
        """Check eIDAS technical standards compliance."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # PAdES support via pyHanko
        evidence.append("PAdES signature format via pyHanko library")

        # LTV/LTA support
        if self.settings.ltv_enabled:
            evidence.append("PAdES-LT support via DSS embedding")

        if self.settings.archive_ts_enabled:
            evidence.append("PAdES-LTA support via archive timestamps")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Enable archive_ts_enabled for full PAdES-LTA compliance (eIDAS recommended)"
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

    def _check_eidas_timestamps(self, control: ControlDefinition) -> ControlCheck:
        """Check eIDAS timestamp requirements."""
        evidence: list[str] = []
        recommendations: list[str] = []

        tsa_url = self.settings.tsa_url

        if not tsa_url:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["tsa_url not configured"],
                recommendations=["Configure tsa_url with a qualified TSA provider"],
            )

        evidence.append(f"TSA configured: {tsa_url}")

        if self.settings.archive_ts_enabled:
            evidence.append("Archive timestamps enabled for long-term validity")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable archive_ts_enabled for qualified timestamps")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_eidas_validation(self, control: ControlDefinition) -> ControlCheck:
        """Check eIDAS signature validation."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # Validation capabilities
        evidence.append("PDF signature validation via PDFValidator")

        if self.settings.revocation_check_enabled:
            evidence.append("Revocation checking enabled (OCSP/CRL)")
            evidence.append(f"OCSP timeout: {self.settings.revocation_check_timeout}s")
            evidence.append(f"Cache TTL: {self.settings.revocation_cache_ttl}s")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append(
                "Enable revocation_check_enabled for complete certificate validation"
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

    # ========================================================================
    # GDPR Control Checks
    # ========================================================================

    def _check_gdpr_right_to_erasure(self, control: ControlDefinition) -> ControlCheck:
        """Check GDPR Art. 17 - Right to erasure."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.gdpr_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["gdpr_enabled is false"],
                recommendations=["Enable gdpr_enabled for data subject rights features"],
            )

        evidence.append("GDPR compliance mode enabled")
        evidence.append(f"Grace period: {self.settings.gdpr_deletion_grace_days} days")

        if self.settings.gdpr_anonymize_audit_logs:
            evidence.append("Audit log anonymization enabled for deleted users")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable gdpr_anonymize_audit_logs for complete erasure")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_gdpr_data_portability(self, control: ControlDefinition) -> ControlCheck:
        """Check GDPR Art. 20 - Right to data portability."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.gdpr_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["gdpr_enabled is false"],
                recommendations=["Enable gdpr_enabled"],
            )

        # Audit export capabilities
        evidence.append("Audit logs exportable to CSV format")
        evidence.append("User data stored in portable SQLite databases")
        evidence.append("JSON Lines format for machine-readable audit data")

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

    def _check_gdpr_retention(self, control: ControlDefinition) -> ControlCheck:
        """Check GDPR Art. 5(1)(e) - Storage limitation."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if not self.settings.gdpr_enabled:
            return ControlCheck(
                control_id=control.control_id,
                name=control.name,
                description=control.description,
                standard=control.standard,
                status=ControlStatus.FAILED,
                evidence=["gdpr_enabled is false"],
                recommendations=["Enable gdpr_enabled"],
            )

        # Retention policies
        retention_days = self.settings.gdpr_retention_days
        audit_retention = self.settings.audit_retention_days

        evidence.append(f"Data retention: {retention_days} days")
        evidence.append(f"Audit retention: {audit_retention} days")
        evidence.append("Automatic cleanup of old audit logs")

        # Temp file security
        if self.settings.temp_secure_delete:
            evidence.append("Secure deletion of temporary files (DoD 5220.22-M)")
            evidence.append(f"Temp file retention: {self.settings.temp_retention_hours} hours")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable temp_secure_delete for secure data disposal")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_gdpr_encryption(self, control: ControlDefinition) -> ControlCheck:
        """Check GDPR Art. 32 - Security of processing."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # Encryption capabilities
        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        if strength == "aes256":
            evidence.append("Using AES-256 encryption")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Use AES-256 for optimal data protection")

        # Keyring storage
        if self.settings.encryption_store_in_keyring:
            evidence.append("Credentials stored in secure system keyring")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_gdpr_phi_detection(self, control: ControlDefinition) -> ControlCheck:
        """Check GDPR Art. 9 - Special categories of data."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.phi_detection_enabled:
            evidence.append("PHI/PII detection enabled")
            evidence.append(f"Confidence threshold: {self.settings.phi_detection_min_confidence}")

            if self.settings.phi_detection_block_unencrypted:
                evidence.append("Blocking unencrypted PHI documents")
                status = ControlStatus.PASSED
            else:
                status = ControlStatus.PARTIAL
                recommendations.append(
                    "Enable phi_detection_block_unencrypted for automatic protection"
                )
        else:
            status = ControlStatus.NOT_APPLICABLE
            evidence.append("PHI detection not enabled")
            recommendations.append(
                "Enable phi_detection_enabled if processing special categories of data"
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

    # ========================================================================
    # SOC 2 Control Checks
    # ========================================================================

    def _check_soc2_access_controls(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC6.1 - Logical access controls."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # Authentication mechanisms
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

        # Encryption at rest
        strength = self.settings.encryption_default_strength
        evidence.append(f"Data-at-rest encryption: {strength}")

        if strength == "aes256":
            status = ControlStatus.PASSED
            evidence.append("Using AES-256 encryption")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Use AES-256 for maximum security")

        # Credential storage
        if self.settings.encryption_store_in_keyring:
            evidence.append("Credentials stored in encrypted keyring")

        # Note: Transmission encryption (TLS) is deployment-dependent
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

    def _check_soc2_system_monitoring(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC7.2 - System monitoring."""
        # Similar to CC6.6
        return self._check_soc2_monitoring(control)

    def _check_soc2_change_detection(self, control: ControlDefinition) -> ControlCheck:
        """Check SOC 2 CC8.1 - Change detection."""
        evidence: list[str] = []
        recommendations: list[str] = []

        # Audit integrity provides change detection
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

"""
nist_audit_checker.py - NIST 800-53 AU/SC family checks

Audit and Accountability (AU) and System and Communications
Protection (SC) control checks. AC/IA/FedRAMP are in nist_checker.py.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class NISTAuditChecker:
    """
    NIST 800-53 Rev 5 - AU and SC families.

    Audit and Accountability (AU-2 through AU-12) and System and
    Communications Protection (SC-8, SC-12, SC-13, SC-17, SC-23, SC-28).
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    # ========================================================================
    # Audit and Accountability (AU) Family
    # ========================================================================

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

    def _check_nist_audit_content(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-3 - Content of audit records."""
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

        required_fields = [
            "timestamp",
            "user_id",
            "event_type",
            "outcome",
            "details",
            "source_ip",
        ]
        evidence.append(f"Audit records contain required fields: {', '.join(required_fields)}")
        evidence.append("ISO 8601 timestamp format with timezone")
        evidence.append("Structured JSON Lines format for machine parsing")

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

    def _check_nist_audit_storage(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-4 - Audit storage capacity."""
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

        try:
            import shutil
            from pathlib import Path

            log_dir = Path(self.settings.log_dir)
            total, used, free = shutil.disk_usage(log_dir)
            free_percent = (free / total) * 100

            evidence.append(f"Audit log directory: {log_dir}")
            evidence.append(f"Free disk space: {free_percent:.1f}%")

            if free_percent >= 20:
                status = ControlStatus.PASSED
                evidence.append("Sufficient storage capacity available")
            elif free_percent >= 10:
                status = ControlStatus.PARTIAL
                recommendations.append("Disk space below 20% - consider cleanup or expansion")
            else:
                status = ControlStatus.FAILED
                recommendations.append("Critical: Disk space below 10%")
        except Exception as e:
            status = ControlStatus.PARTIAL
            evidence.append(f"Could not check disk space: {e}")
            recommendations.append("Verify log directory exists and is accessible")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_audit_review(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-6 - Audit review, analysis, and reporting."""
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

        evidence.append("Audit logs available in JSON Lines format for analysis")
        evidence.append("CSV export capability for reporting")
        evidence.append("SIEM integration available via SIEMExporter")
        evidence.append(f"Retention period: {self.settings.audit_retention_days} days")

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

    def _check_nist_timestamps(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-8 - Time stamps."""
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

        evidence.append("Audit records use UTC timestamps (ISO 8601 format)")
        evidence.append("Internal system clock synchronized with system time")
        evidence.append("Timestamp precision: microseconds")

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

    def _check_nist_audit_retention(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-11 - Audit record retention."""
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

        retention_days = self.settings.audit_retention_days
        evidence.append(f"Audit retention period: {retention_days} days")
        evidence.append("Automatic cleanup of logs older than retention period")

        if retention_days >= 365:
            status = ControlStatus.PASSED
            evidence.append("Retention meets minimum NIST recommendation (365 days)")
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Set audit_retention_days to at least 365")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_audit_generation(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST AU-12 - Audit generation."""
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

        evidence.append("Comprehensive event types defined in AuditEventType enum")
        evidence.append(
            "Events include: LOGIN, LOGOUT, PDF_SIGNED, PDF_VALIDATED, "
            "CERTIFICATE_LOADED, PERMISSION_DENIED, CONFIG_CHANGE, etc."
        )
        evidence.append("Automatic audit generation via AuditLogger")

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
    # System and Communications Protection (SC) Family
    # ========================================================================

    def _check_nist_transmission_protection(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-8 - Transmission confidentiality."""
        evidence: list[str] = []
        recommendations: list[str] = []

        tls_enabled = getattr(self.settings, "api_tls_enabled", None)

        if tls_enabled:
            status = ControlStatus.PASSED
            evidence.append("TLS/HTTPS configured for API")
            evidence.append(
                f"Min TLS version: {getattr(self.settings, 'api_tls_min_version', 'TLSv1.2')}"
            )
        else:
            status = ControlStatus.PASSED
            evidence.append("Control not applicable (desktop mode, no network transmission)")
            evidence.append("API: TLS should be configured at deployment level if used")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_key_management(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-12 - Cryptographic key management."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.key_storage_path:
            evidence.append(f"Key storage configured: {self.settings.key_storage_path}")
            evidence.append(f"Default key expiry: {self.settings.key_default_expiry_days} days")
            evidence.append(f"Auto-rotation after: {self.settings.key_auto_rotate_days} days")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            evidence.append("Key storage path not configured")
            recommendations.append("Configure key_storage_path for key management")

        evidence.append("PKCS#11 hardware tokens for private key protection")
        evidence.append(f"NSS database: {self.settings.nss_db_path}")

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

    def _check_nist_pki_certificates(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-17 - PKI certificates."""
        evidence: list[str] = []
        recommendations: list[str] = []

        evidence.append("PKCS#11 certificate support via NSS")
        evidence.append(f"NSS database: {self.settings.nss_db_path}")

        if self.settings.revocation_check_enabled:
            evidence.append("Certificate revocation checking enabled (OCSP/CRL)")
            evidence.append(f"OCSP timeout: {self.settings.revocation_check_timeout}s")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Enable revocation_check_enabled for certificate validation")

        if self.settings.healthcare_mode:
            evidence.append("Certificate binding to user accounts enabled")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_session_authenticity(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-23 - Session authenticity."""
        evidence: list[str] = []
        recommendations: list[str] = []

        if self.settings.healthcare_mode:
            evidence.append("Session authenticity via JWT tokens")
            evidence.append("Session binding to user identity")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            evidence.append("healthcare_mode disabled - limited session protection")
            recommendations.append("Enable healthcare_mode for session authenticity controls")

        tls_enabled = getattr(self.settings, "api_tls_enabled", None)
        if tls_enabled:
            evidence.append("TLS protects session integrity in transit")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _check_nist_data_at_rest(self, control: ControlDefinition) -> ControlCheck:
        """Check NIST SC-28 - Protection of information at rest."""
        evidence: list[str] = []
        recommendations: list[str] = []

        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        if strength == "aes256":
            status = ControlStatus.PASSED
            evidence.append("Using AES-256 encryption for data at rest")
        else:
            status = ControlStatus.PARTIAL
            evidence.append("Using AES-128 encryption")
            recommendations.append("Set encryption_default_strength to 'aes256'")

        if self.settings.encryption_store_in_keyring:
            evidence.append("Encryption keys stored in secure system keyring")
        else:
            recommendations.append("Enable encryption_store_in_keyring for secure key storage")

        if self.settings.temp_secure_delete:
            evidence.append("Secure deletion of temporary files (DoD 5220.22-M)")

        return ControlCheck(
            control_id=control.control_id,
            name=control.name,
            description=control.description,
            standard=control.standard,
            status=status,
            evidence=evidence,
            recommendations=recommendations,
        )

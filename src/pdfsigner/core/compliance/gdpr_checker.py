"""
gdpr_checker.py - GDPR data protection compliance checks

Checks data subject rights (erasure, portability), retention policies,
encryption, and special category data handling per GDPR.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.controls import ControlDefinition, ControlStatus

from .checker import ControlCheck


class GDPRChecker:
    """
    GDPR (General Data Protection Regulation) compliance checker.

    Checks Art. 17 (erasure), Art. 20 (portability), Art. 5(1)(e)
    (storage limitation), Art. 32 (security), Art. 9 (special data).
    """

    def __init__(self, settings: Settings):
        self.settings = settings

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

        retention_days = self.settings.gdpr_retention_days
        audit_retention = self.settings.audit_retention_days

        evidence.append(f"Data retention: {retention_days} days")
        evidence.append(f"Audit retention: {audit_retention} days")
        evidence.append("Automatic cleanup of old audit logs")

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

        strength = self.settings.encryption_default_strength
        evidence.append(f"Encryption strength: {strength}")

        if strength == "aes256":
            evidence.append("Using AES-256 encryption")
            status = ControlStatus.PASSED
        else:
            status = ControlStatus.PARTIAL
            recommendations.append("Use AES-256 for optimal data protection")

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

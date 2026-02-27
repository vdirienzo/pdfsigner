"""
status_helpers.py - Helper functions for HIPAA compliance checks

Extracted from status_checker.py to keep modules under 400 lines.
Contains the audit controls check which requires multiple imports.
"""

from loguru import logger

from pdfsigner.core.compliance.status_types import (
    ComplianceCategory,
    ComplianceCheck,
    ComplianceStatus,
)


def check_audit_controls(settings) -> ComplianceCheck:
    """
    Check audit trail configuration HIPAA 164.312(b).

    Args:
        settings: PDFSigner settings instance

    Returns:
        ComplianceCheck for audit controls
    """
    if not settings.audit_enabled:
        return ComplianceCheck(
            name="Audit Controls",
            category=ComplianceCategory.AUDIT_CONTROLS,
            status=ComplianceStatus.NON_COMPLIANT,
            hipaa_reference="§164.312(b)",
            description="Audit trail with integrity protection",
            details="Audit logging is disabled",
            remediation="Enable audit_enabled in settings",
        )

    try:
        from pdfsigner.core.audit import get_audit_integrity_manager

        # Verify that integrity manager is available and configured
        manager = get_audit_integrity_manager()

        # Create a test event to verify signing works
        from pdfsigner.core.audit import AuditEvent, AuditEventType

        test_event = AuditEvent(
            event_type=AuditEventType.AUDIT_INTEGRITY_CHECK,
            user_id="compliance_checker",
            details={"test": "integrity_check"},
        )

        # Try to sign the event (this verifies HMAC key is configured)
        signed_event = manager.sign_event(test_event)

        # Verify the signed event
        is_valid, reason = manager.verify_event(signed_event)

        if is_valid:
            return ComplianceCheck(
                name="Audit Controls",
                category=ComplianceCategory.AUDIT_CONTROLS,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.312(b)",
                description="Audit trail with integrity protection",
                details="HMAC-protected audit logging is functioning correctly",
            )
        else:
            return ComplianceCheck(
                name="Audit Controls",
                category=ComplianceCategory.AUDIT_CONTROLS,
                status=ComplianceStatus.NON_COMPLIANT,
                hipaa_reference="§164.312(b)",
                description="Audit trail with integrity protection",
                details=f"Audit integrity verification failed: {reason}",
                remediation="Check audit integrity configuration",
            )
    except Exception as e:
        logger.warning(f"Could not verify audit integrity: {e}")
        return ComplianceCheck(
            name="Audit Controls",
            category=ComplianceCategory.AUDIT_CONTROLS,
            status=ComplianceStatus.WARNING,
            hipaa_reference="§164.312(b)",
            description="Audit trail with integrity protection",
            details=f"Could not verify audit integrity: {e}",
            remediation="Ensure audit system is properly configured",
        )


def check_session_management(settings) -> ComplianceCheck:
    """
    Check session timeout configuration HIPAA 164.312(a)(2)(iii).

    Args:
        settings: PDFSigner settings instance

    Returns:
        ComplianceCheck for session management
    """
    if not settings.healthcare_mode:
        return ComplianceCheck(
            name="Session Management",
            category=ComplianceCategory.SESSION_MANAGEMENT,
            status=ComplianceStatus.WARNING,
            hipaa_reference="§164.312(a)(2)(iii)",
            description="Automatic logoff after inactivity",
            details="Healthcare mode disabled. Auto-logoff not enforced.",
            remediation="Enable healthcare_mode in settings",
        )

    timeout = settings.healthcare_session_timeout_minutes
    if timeout <= 15:
        status = ComplianceStatus.COMPLIANT
        details = f"Auto-logoff after {timeout} minutes (recommended: ≤15)"
        remediation = None
    elif timeout <= 30:
        status = ComplianceStatus.WARNING
        details = f"Auto-logoff after {timeout} minutes (recommended: ≤15)"
        remediation = "Set healthcare_session_timeout_minutes to 15 or less"
    else:
        status = ComplianceStatus.NON_COMPLIANT
        details = f"Auto-logoff after {timeout} minutes is too long"
        remediation = "Set healthcare_session_timeout_minutes to 15 or less"

    return ComplianceCheck(
        name="Session Management",
        category=ComplianceCategory.SESSION_MANAGEMENT,
        status=status,
        hipaa_reference="§164.312(a)(2)(iii)",
        description="Automatic logoff after inactivity",
        details=details,
        remediation=remediation,
    )

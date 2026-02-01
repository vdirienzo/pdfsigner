"""
cef_formatter.py - Common Event Format (CEF) formatter

Author: Homero Thompson del Lago del Terror

Implements CEF format for SIEM systems like ArcSight and Splunk.

CEF Format:
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Example:
CEF:0|PDFSigner|AuditLogger|1.7.0|1001|PDF Signature|3|src=192.168.1.100 suser=john.doe
"""


from pdfsigner.core.audit.audit_event import AuditEvent

# Severity mapping (DEBUG=0, INFO=3, WARNING=5, ERROR=7, CRITICAL=10)
SEVERITY_MAP = {
    "DEBUG": 0,
    "INFO": 3,
    "WARNING": 5,
    "ERROR": 7,
    "CRITICAL": 10,
}

# Event type to Signature ID mapping
SIGNATURE_IDS = {
    "sign_success": "1001",
    "sign_failure": "1001",
    "validate_success": "1002",
    "validate_failure": "1002",
    "encrypt_success": "1003",
    "encrypt_failure": "1003",
    "decrypt_success": "1004",
    "decrypt_failure": "1004",
    "user_login": "2001",
    "user_logout": "2002",
    "mfa_enrolled": "2003",
    "mfa_verified": "2004",
    "mfa_verification_failed": "2004",
    "access_denied": "3001",
    "emergency_access": "3002",
    "emergency_access_requested": "3002",
    "emergency_access_approved": "3002",
    "emergency_access_denied": "3002",
    "emergency_access_revoked": "3002",
    "emergency_access_used": "3002",
    "session_start": "2001",
    "session_end": "2002",
    "session_timeout": "2002",
    "token_login": "2001",
    "token_logout": "2002",
}


class CEFFormatter:
    """
    Format audit events in Common Event Format (CEF).

    CEF is a standard format for security event logging used by
    HP ArcSight, Splunk, and other SIEM systems.
    """

    VERSION = "0"  # CEF version
    VENDOR = "PDFSigner"
    PRODUCT = "AuditLogger"
    DEVICE_VERSION = "1.7.0"

    @classmethod
    def format(cls, event: AuditEvent) -> str:
        """
        Format audit event as CEF string.

        Args:
            event: AuditEvent to format

        Returns:
            CEF-formatted string
        """
        # Build header
        signature_id = SIGNATURE_IDS.get(event.event_type.value, "9999")
        name = cls._get_event_name(event)
        severity = cls._get_severity(event)

        # Build extension (key=value pairs)
        extension = cls._build_extension(event)

        # Construct CEF message
        header = "|".join(
            [
                f"CEF:{cls.VERSION}",
                cls._escape_header(cls.VENDOR),
                cls._escape_header(cls.PRODUCT),
                cls._escape_header(cls.DEVICE_VERSION),
                cls._escape_header(signature_id),
                cls._escape_header(name),
                str(severity),
            ]
        )

        return f"{header}|{extension}"

    @classmethod
    def _get_event_name(cls, event: AuditEvent) -> str:
        """Get human-readable event name."""
        # Convert snake_case to Title Case
        name = event.event_type.value.replace("_", " ").title()
        return name

    @classmethod
    def _get_severity(cls, event: AuditEvent) -> int:
        """
        Determine severity level from event status.

        Maps event status to CEF severity:
        - SUCCESS: INFO (3)
        - FAILURE: WARNING (5)
        - ERROR: ERROR (7)
        """
        if event.status == "SUCCESS":
            return SEVERITY_MAP["INFO"]
        elif event.status == "FAILURE":
            return SEVERITY_MAP["WARNING"]
        else:  # ERROR or other
            return SEVERITY_MAP["ERROR"]

    @classmethod
    def _build_extension(cls, event: AuditEvent) -> str:
        """
        Build CEF extension field from event data.

        Returns key=value pairs separated by spaces.
        """
        fields = []

        # Standard CEF fields
        if event.hostname:
            fields.append(f"dvchost={cls._escape_extension(event.hostname)}")

        if event.ip_address:
            fields.append(f"src={cls._escape_extension(event.ip_address)}")

        if event.user_cn:
            fields.append(f"suser={cls._escape_extension(event.user_cn)}")

        if event.user_id:
            fields.append(f"suid={cls._escape_extension(event.user_id)}")

        if event.document_path:
            fields.append(f"fname={cls._escape_extension(event.document_path)}")

        if event.document_hash_sha256:
            fields.append(f"fileHash={cls._escape_extension(event.document_hash_sha256)}")

        # Outcome
        outcome = "success" if event.status == "SUCCESS" else "failure"
        fields.append(f"outcome={outcome}")

        # Timestamp (CEF format: MMM dd yyyy HH:mm:ss)
        rt = event.timestamp.strftime("%b %d %Y %H:%M:%S")
        fields.append(f"rt={rt}")

        # Event ID
        fields.append(f"externalId={cls._escape_extension(event.event_id)}")

        # Session ID
        if event.session_id:
            fields.append(f"cs1Label=SessionID cs1={cls._escape_extension(event.session_id)}")

        # Certificate info
        if event.certificate_serial:
            fields.append(
                f"cs2Label=CertificateSerial cs2={cls._escape_extension(event.certificate_serial)}"
            )

        if event.certificate_issuer:
            fields.append(
                f"cs3Label=CertificateIssuer cs3={cls._escape_extension(event.certificate_issuer)}"
            )

        # Error message
        if event.error_message:
            fields.append(f"msg={cls._escape_extension(event.error_message)}")

        # PHI access flag
        if event.phi_accessed:
            fields.append("cs4Label=PHIAccessed cs4=true")

        # User agent
        if event.user_agent:
            fields.append(f"requestClientApplication={cls._escape_extension(event.user_agent)}")

        # Additional details
        if event.details:
            # Add up to 3 custom fields
            for i, (key, value) in enumerate(list(event.details.items())[:3], start=5):
                fields.append(
                    f"cs{i}Label={cls._escape_extension(key)} "
                    f"cs{i}={cls._escape_extension(str(value))}"
                )

        return " ".join(fields)

    @classmethod
    def _escape_header(cls, value: str) -> str:
        """
        Escape special characters in CEF header fields.

        Header fields (before extension) must escape: | and \
        """
        if not value:
            return ""
        return value.replace("\\", "\\\\").replace("|", "\\|")

    @classmethod
    def _escape_extension(cls, value: str) -> str:
        """
        Escape special characters in CEF extension fields.

        Extension fields must escape: = and \
        Newlines should be replaced with spaces.
        """
        if not value:
            return ""
        return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", "")

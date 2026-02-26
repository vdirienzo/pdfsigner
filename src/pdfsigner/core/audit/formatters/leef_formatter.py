"""
leef_formatter.py - Log Event Extended Format (LEEF) formatter

Author: Homero Thompson del Lago del Terror

Implements LEEF format for IBM QRadar SIEM.

LEEF Format:
LEEF:Version|Vendor|Product|Version|EventID|Extension

Example:
LEEF:2.0|PDFSigner|AuditLogger|1.7.0|1001|src=192.168.1.100\tusrName=john.doe\tresult=success
"""

from pdfsigner.core.audit.audit_event import AuditEvent

# Event type to Event ID mapping (same as CEF)
EVENT_IDS = {
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


class LEEFFormatter:
    """
    Format audit events in Log Event Extended Format (LEEF).

    LEEF is IBM's standard format for security event logging,
    used primarily with QRadar SIEM.
    """

    VERSION = "2.0"  # LEEF version
    VENDOR = "PDFSigner"
    PRODUCT = "AuditLogger"
    DEVICE_VERSION = "1.7.0"

    @classmethod
    def format(cls, event: AuditEvent) -> str:
        """
        Format audit event as LEEF string.

        Args:
            event: AuditEvent to format

        Returns:
            LEEF-formatted string
        """
        # Build header
        event_id = EVENT_IDS.get(event.event_type.value, "9999")

        # Build extension (key=value pairs separated by tabs)
        extension = cls._build_extension(event)

        # Construct LEEF message
        header = "|".join(
            [
                f"LEEF:{cls.VERSION}",
                cls._escape_header(cls.VENDOR),
                cls._escape_header(cls.PRODUCT),
                cls._escape_header(cls.DEVICE_VERSION),
                cls._escape_header(event_id),
            ]
        )

        return f"{header}|{extension}"

    @classmethod
    def _build_extension(cls, event: AuditEvent) -> str:
        """
        Build LEEF extension field from event data.

        Returns key=value pairs separated by tabs (\t).
        """
        fields = []

        # Standard LEEF fields
        if event.hostname:
            fields.append(f"devHost={cls._escape_extension(event.hostname)}")

        if event.ip_address:
            fields.append(f"src={cls._escape_extension(event.ip_address)}")

        if event.user_cn:
            fields.append(f"usrName={cls._escape_extension(event.user_cn)}")

        if event.user_id:
            fields.append(f"identSrc={cls._escape_extension(event.user_id)}")

        if event.document_path:
            fields.append(f"fileName={cls._escape_extension(event.document_path)}")

        if event.document_hash_sha256:
            fields.append(f"fileHash={cls._escape_extension(event.document_hash_sha256)}")

        # Result/outcome
        result = "success" if event.status == "SUCCESS" else "failure"
        fields.append(f"result={result}")

        # Event type
        fields.append(f"cat={cls._escape_extension(event.event_type.value)}")

        # Timestamp (ISO 8601 format)
        dev_time = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        fields.append(f"devTime={dev_time}")

        # Event ID
        fields.append(f"eventId={cls._escape_extension(event.event_id)}")

        # Session ID
        if event.session_id:
            fields.append(f"sessionId={cls._escape_extension(event.session_id)}")

        # Certificate info
        if event.certificate_serial:
            fields.append(f"certSerial={cls._escape_extension(event.certificate_serial)}")

        if event.certificate_issuer:
            fields.append(f"certIssuer={cls._escape_extension(event.certificate_issuer)}")

        # Error message
        if event.error_message:
            fields.append(f"msg={cls._escape_extension(event.error_message)}")

        # PHI access flag
        if event.phi_accessed:
            fields.append("phiAccessed=true")

        # User agent
        if event.user_agent:
            fields.append(f"userAgent={cls._escape_extension(event.user_agent)}")

        # Severity (based on status)
        severity = cls._get_severity(event)
        fields.append(f"sev={severity}")

        # Additional details as JSON-like string
        if event.details:
            # Convert details to key:value pairs
            details_str = ", ".join(
                f"{k}:{cls._escape_extension(str(v))}" for k, v in event.details.items()
            )
            fields.append(f"details={cls._escape_extension(details_str)}")

        return "\t".join(fields)

    @classmethod
    def _get_severity(cls, event: AuditEvent) -> int:
        """
        Determine severity level from event status.

        LEEF severity scale: 0-10
        - SUCCESS: 2 (low)
        - FAILURE: 5 (medium)
        - ERROR: 8 (high)
        """
        if event.status == "SUCCESS":
            return 2
        elif event.status == "FAILURE":
            return 5
        else:  # ERROR
            return 8

    @classmethod
    def _escape_header(cls, value: str) -> str:
        """
        Escape special characters in LEEF header fields.

        Header fields (before extension) must escape: | and \
        """
        if not value:
            return ""
        return value.replace("\\", "\\\\").replace("|", "\\|")

    @classmethod
    def _escape_extension(cls, value: str) -> str:
        """
        Escape special characters in LEEF extension fields.

        Extension fields must escape: = \t \n \r and \
        """
        if not value:
            return ""
        return (
            value.replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )

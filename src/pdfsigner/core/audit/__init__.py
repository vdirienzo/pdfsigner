"""
audit - Audit trail module for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides structured audit logging for security and compliance.
Logs events to JSON Lines format with monthly rotation.
"""

import hashlib
from pathlib import Path

from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.audit.audit_logger import AuditLogger

# Re-export public API
__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "log_signing_event",
    "log_validation_event",
    "log_token_event",
    "log_certificate_selection",
    "log_config_change",
    "get_audit_logger",
]


def get_audit_logger() -> AuditLogger:
    """
    Get configured audit logger instance.

    Reads settings from configuration and returns singleton instance.

    Returns:
        AuditLogger instance
    """
    settings = get_settings()
    return AuditLogger.get_instance(
        enabled=settings.audit_enabled,
        retention_days=settings.audit_retention_days,
    )


def _calculate_document_hash(document_path: Path) -> str:
    """
    Calculate SHA-256 hash of document.

    Args:
        document_path: Path to document

    Returns:
        Hex string of SHA-256 hash
    """
    try:
        sha256 = hashlib.sha256()
        with open(document_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.warning(f"Could not hash document: {e}")
        return ""


def log_signing_event(
    document_path: str | Path,
    certificate_serial: str | None,
    certificate_issuer: str | None,
    user_cn: str | None,
    success: bool,
    error: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Log a PDF signing event.

    Args:
        document_path: Path to PDF being signed
        certificate_serial: Certificate serial number (hex)
        certificate_issuer: Certificate issuer DN
        user_cn: User common name from certificate
        success: Whether signing succeeded
        error: Error message if failed
        details: Additional event details
    """
    audit_logger = get_audit_logger()

    document_path = Path(document_path)
    doc_hash = _calculate_document_hash(document_path) if document_path.exists() else None

    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS if success else AuditEventType.SIGN_FAILURE,
        user_cn=user_cn,
        document_path=str(document_path),
        document_hash_sha256=doc_hash,
        certificate_serial=certificate_serial,
        certificate_issuer=certificate_issuer,
        status="SUCCESS" if success else "FAILURE",
        error_message=error,
        details=details or {},
    )

    audit_logger.log_event(event)


def log_validation_event(
    document_path: str | Path,
    signature_count: int,
    all_valid: bool,
    error: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Log a PDF validation event.

    Args:
        document_path: Path to PDF being validated
        signature_count: Number of signatures found
        all_valid: Whether all signatures are valid
        error: Error message if validation failed
        details: Additional event details (e.g., signature info)
    """
    audit_logger = get_audit_logger()

    document_path = Path(document_path)
    doc_hash = _calculate_document_hash(document_path) if document_path.exists() else None

    success = error is None

    event = AuditEvent(
        event_type=AuditEventType.VALIDATE_SUCCESS if success else AuditEventType.VALIDATE_FAILURE,
        document_path=str(document_path),
        document_hash_sha256=doc_hash,
        status="SUCCESS" if success else "FAILURE",
        error_message=error,
        details={
            "signature_count": signature_count,
            "all_valid": all_valid,
            **(details or {}),
        },
    )

    audit_logger.log_event(event)


def log_token_event(
    event_type: AuditEventType,
    user_cn: str | None = None,
    success: bool = True,
    error: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Log a token (PKCS#11) event.

    Args:
        event_type: TOKEN_LOGIN or TOKEN_LOGOUT
        user_cn: User common name if known
        success: Whether operation succeeded
        error: Error message if failed
        details: Additional event details
    """
    if event_type not in (AuditEventType.TOKEN_LOGIN, AuditEventType.TOKEN_LOGOUT):
        logger.warning(f"Invalid token event type: {event_type}")
        return

    audit_logger = get_audit_logger()

    event = AuditEvent(
        event_type=event_type,
        user_cn=user_cn,
        status="SUCCESS" if success else "FAILURE",
        error_message=error,
        details=details or {},
    )

    audit_logger.log_event(event)


def log_certificate_selection(
    certificate_serial: str,
    certificate_issuer: str,
    user_cn: str,
    details: dict | None = None,
) -> None:
    """
    Log certificate selection event.

    Args:
        certificate_serial: Certificate serial number (hex)
        certificate_issuer: Certificate issuer DN
        user_cn: User common name from certificate
        details: Additional event details (e.g., selection criteria)
    """
    audit_logger = get_audit_logger()

    event = AuditEvent(
        event_type=AuditEventType.CERTIFICATE_SELECTED,
        user_cn=user_cn,
        certificate_serial=certificate_serial,
        certificate_issuer=certificate_issuer,
        status="SUCCESS",
        details=details or {},
    )

    audit_logger.log_event(event)


def log_config_change(
    setting_name: str,
    old_value: str | None,
    new_value: str | None,
    user_cn: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Log configuration change event.

    Args:
        setting_name: Name of setting changed
        old_value: Previous value (as string)
        new_value: New value (as string)
        user_cn: User who made the change (if known)
        details: Additional event details
    """
    audit_logger = get_audit_logger()

    event = AuditEvent(
        event_type=AuditEventType.CONFIG_CHANGE,
        user_cn=user_cn,
        status="SUCCESS",
        details={
            "setting_name": setting_name,
            "old_value": old_value,
            "new_value": new_value,
            **(details or {}),
        },
    )

    audit_logger.log_event(event)

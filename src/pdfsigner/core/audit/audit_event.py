"""
audit_event.py - Audit event data structures

Author: Homero Thompson del Lago del Terror

Defines audit event types and data structure for security
and compliance tracking in PDFSigner.
"""

import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class AuditEventType(Enum):
    """Types of audit events tracked in the system."""

    SIGN_SUCCESS = "sign_success"
    SIGN_FAILURE = "sign_failure"
    VALIDATE_SUCCESS = "validate_success"
    VALIDATE_FAILURE = "validate_failure"
    CONFIG_CHANGE = "config_change"
    TOKEN_LOGIN = "token_login"  # nosec B105 - not a password, event type identifier
    TOKEN_LOGOUT = "token_logout"  # nosec B105 - not a password, event type identifier
    CERTIFICATE_SELECTED = "certificate_selected"

    # HIPAA compliance events
    DOCUMENT_VIEW = "document_view"  # Documento visualizado
    DOCUMENT_EXPORT = "document_export"  # Documento exportado
    ENCRYPT_SUCCESS = "encrypt_success"  # Encriptación exitosa
    ENCRYPT_FAILURE = "encrypt_failure"  # Encriptación fallida
    DECRYPT_SUCCESS = "decrypt_success"  # Desencriptación exitosa
    DECRYPT_FAILURE = "decrypt_failure"  # Desencriptación fallida
    ACCESS_GRANTED = "access_granted"  # Acceso concedido
    ACCESS_DENIED = "access_denied"  # Acceso denegado
    EMERGENCY_ACCESS = "emergency_access"  # Acceso de emergencia (legacy)
    EMERGENCY_ACCESS_REQUESTED = "emergency_access_requested"  # Solicitud de acceso de emergencia
    EMERGENCY_ACCESS_APPROVED = "emergency_access_approved"  # Acceso de emergencia aprobado
    EMERGENCY_ACCESS_DENIED = "emergency_access_denied"  # Acceso de emergencia denegado
    EMERGENCY_ACCESS_REVOKED = "emergency_access_revoked"  # Acceso de emergencia revocado
    EMERGENCY_ACCESS_USED = "emergency_access_used"  # Acceso de emergencia utilizado
    SESSION_START = "session_start"  # Inicio de sesión
    SESSION_END = "session_end"  # Fin de sesión
    SESSION_TIMEOUT = "session_timeout"  # Timeout de sesión
    AUDIT_EXPORT = "audit_export"  # Exportación de audit logs
    AUDIT_INTEGRITY_CHECK = "audit_integrity_check"  # Verificación de integridad
    SYSTEM_CLEANUP = "system_cleanup"  # Limpieza de archivos temporales
    SYSTEM_BACKUP = "system_backup"  # Backup del sistema

    # MFA events
    MFA_ENROLLED = "mfa_enrolled"  # Usuario enroló MFA
    MFA_VERIFIED = "mfa_verified"  # Código MFA verificado
    MFA_DISABLED = "mfa_disabled"  # MFA deshabilitado
    MFA_BACKUP_USED = "mfa_backup_used"  # Código de respaldo usado
    MFA_BACKUP_REGENERATED = "mfa_backup_regenerated"  # Códigos de respaldo regenerados
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"  # Verificación MFA fallida

    # Password and account security events (NIST IA-5, AC-7)
    PASSWORD_CHANGED = "password_changed"  # User changed their password
    PASSWORD_RESET = "password_reset"  # Admin reset user password
    ACCOUNT_LOCKED = "account_locked"  # Account locked after failed attempts
    ACCOUNT_UNLOCKED = "account_unlocked"  # Account unlocked by admin
    PRIVILEGE_ESCALATION = "privilege_escalation"  # User role/permissions changed

    # User management events
    USER_CREATE = "user_create"  # Usuario creado
    USER_UPDATE = "user_update"  # Usuario actualizado
    USER_DELETE = "user_delete"  # Usuario eliminado/anonimizado

    # PHI/PII detection events
    PHI_DETECTED = "phi_detected"  # PHI/PII detected in document
    DOCUMENT_VALIDATED = "document_validated"  # Document validation completed

    # System events
    SYSTEM_EVENT = "system_event"  # Evento del sistema (purge, cleanup, etc.)


@dataclass
class AuditEvent:
    """
    Audit event with complete context.

    Represents a security or operational event in PDFSigner for audit trail.
    Serializable to JSON for storage in JSON Lines format.
    """

    event_type: AuditEventType
    timestamp: datetime = field(default_factory=datetime.now)
    event_id: str = field(default_factory=lambda: str(uuid4()))

    # Context
    user_cn: str | None = None  # Certificate CN if available
    hostname: str = field(default_factory=lambda: socket.gethostname())

    # Document info
    document_path: str | None = None
    document_hash_sha256: str | None = None

    # Certificate info
    certificate_serial: str | None = None
    certificate_issuer: str | None = None

    # Result
    status: str = "SUCCESS"  # SUCCESS, FAILURE, ERROR
    error_message: str | None = None

    # HIPAA compliance fields
    user_id: str | None = None  # ID único de usuario
    session_id: str | None = None  # ID de sesión
    ip_address: str | None = None  # Dirección IP del cliente
    user_agent: str | None = None  # User agent (API/GUI)
    phi_accessed: bool = False  # ¿Se accedió a PHI?

    # Integrity fields for audit chain
    record_hash: str | None = None  # Hash de este registro
    previous_hash: str | None = None  # Hash del registro anterior (chain)
    hmac_signature: str | None = None  # HMAC para verificación

    # Additional details
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary with all fields, converting enum and datetime to strings
        """
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        """
        Create AuditEvent from dictionary.

        Args:
            data: Dictionary with event fields

        Returns:
            AuditEvent instance
        """
        # Convert event_type string to enum
        if "event_type" in data:
            data["event_type"] = AuditEventType(data["event_type"])

        # Convert timestamp string to datetime
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])

        return cls(**data)

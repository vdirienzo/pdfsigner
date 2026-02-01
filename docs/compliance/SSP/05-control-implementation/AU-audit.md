# Audit and Accountability (AU) Family

## Control Implementation Status

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AU-1 | Policy and Procedures | ✅ | This document |
| AU-2 | Audit Events | ✅ | 35+ event types |
| AU-3 | Content of Audit Records | ✅ | Full context |
| AU-4 | Audit Storage Capacity | ✅ | Configurable retention |
| AU-5 | Response to Failures | ✅ | Fail-safe logging |
| AU-6 | Audit Review | ✅ | SIEM integration |
| AU-7 | Audit Reduction | ✅ | Query/filter API |
| AU-8 | Time Stamps | ✅ | ISO 8601 |
| AU-9 | Protection of Audit | ✅ | HMAC integrity |
| AU-10 | Non-repudiation | ✅ | Digital signatures |
| AU-11 | Audit Record Retention | ✅ | 90 days default |
| AU-12 | Audit Generation | ✅ | Automatic logging |

---

## AU-2: Audit Events

### Event Categories

**Module:** `core/audit/audit_event.py`

```python
class AuditEventType(Enum):
    # Document Operations
    SIGN_SUCCESS = "sign_success"
    SIGN_FAILURE = "sign_failure"
    VALIDATE_SUCCESS = "validate_success"
    VALIDATE_FAILURE = "validate_failure"
    DOCUMENT_VIEW = "document_view"
    DOCUMENT_EXPORT = "document_export"

    # Encryption
    ENCRYPT_SUCCESS = "encrypt_success"
    ENCRYPT_FAILURE = "encrypt_failure"
    DECRYPT_SUCCESS = "decrypt_success"
    DECRYPT_FAILURE = "decrypt_failure"

    # Authentication
    TOKEN_LOGIN = "token_login"
    TOKEN_LOGOUT = "token_logout"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"

    # Account Security
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # MFA
    MFA_ENROLLED = "mfa_enrolled"
    MFA_VERIFIED = "mfa_verified"
    MFA_DISABLED = "mfa_disabled"
    MFA_BACKUP_USED = "mfa_backup_used"
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"

    # Access Control
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    EMERGENCY_ACCESS_REQUESTED = "emergency_access_requested"
    EMERGENCY_ACCESS_APPROVED = "emergency_access_approved"

    # Session Management
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    SESSION_TIMEOUT = "session_timeout"

    # User Management
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"

    # System Events
    CONFIG_CHANGE = "config_change"
    SYSTEM_CLEANUP = "system_cleanup"
    SYSTEM_BACKUP = "system_backup"
    AUDIT_EXPORT = "audit_export"
    AUDIT_INTEGRITY_CHECK = "audit_integrity_check"
```

---

## AU-3: Content of Audit Records

### Audit Event Structure

```python
@dataclass
class AuditEvent:
    # Required fields
    event_type: AuditEventType
    timestamp: datetime
    event_id: str  # UUID

    # Context
    user_cn: str | None       # Certificate CN
    user_id: str | None       # User ID
    hostname: str             # System hostname
    ip_address: str | None    # Client IP
    session_id: str | None    # Session ID

    # Document info
    document_path: str | None
    document_hash_sha256: str | None

    # Certificate info
    certificate_serial: str | None
    certificate_issuer: str | None

    # Result
    status: str  # SUCCESS, FAILURE, ERROR
    error_message: str | None

    # Integrity (for chain)
    record_hash: str | None
    previous_hash: str | None
    hmac_signature: str | None

    # Additional context
    details: dict[str, Any]
```

### Example Record

```json
{
  "event_type": "sign_success",
  "timestamp": "2026-02-01T10:30:00.000Z",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user123",
  "user_cn": "CN=John Doe,O=Acme Corp",
  "hostname": "pdfsigner-prod-01",
  "ip_address": "192.168.1.100",
  "document_path": "/documents/contract.pdf",
  "document_hash_sha256": "a5b9...",
  "certificate_serial": "123456789",
  "certificate_issuer": "CN=Company CA",
  "status": "SUCCESS",
  "record_hash": "sha256:abc123...",
  "previous_hash": "sha256:def456...",
  "hmac_signature": "hmac:ghi789..."
}
```

---

## AU-6: Audit Review / SIEM Integration

### Implementation

**Module:** `core/audit/siem_exporter.py`

```python
class SIEMExporter:
    """Export audit events to SIEM systems."""

    FORMATS = ["cef", "leef", "json", "syslog"]

    def export_to_file(format: str, path: str) -> None
    def export_to_syslog(host: str, port: int, protocol: str) -> None
    def format_event_cef(event: AuditEvent) -> str  # ArcSight/Splunk
    def format_event_leef(event: AuditEvent) -> str  # QRadar
```

### Configuration

```toml
# config.toml
siem_enabled = true
siem_format = "cef"  # or "leef", "json", "syslog"
siem_syslog_host = "siem.example.com"
siem_syslog_port = 514
siem_syslog_protocol = "tls"  # or "tcp", "udp"
siem_file_path = "/var/log/pdfsigner/siem.log"
siem_file_rotation_mb = 100
siem_file_retention_days = 90
```

### Evidence

- 38 SIEM exporter tests (`test_siem_exporter.py`)
- Support for CEF (ArcSight/Splunk), LEEF (QRadar), JSON, Syslog

---

## AU-9: Protection of Audit Information

### Integrity Protection

**Module:** `core/audit/audit_integrity.py`

```python
class AuditIntegrityManager:
    """HMAC-based audit log integrity protection."""

    def sign_event(event: AuditEvent) -> AuditEvent:
        """Add record_hash, previous_hash, hmac_signature."""

    def verify_event(event: AuditEvent) -> bool:
        """Verify HMAC signature."""

    def verify_chain(events: list[AuditEvent]) -> IntegrityReport:
        """Verify entire audit chain."""
```

### Chain Hashing

1. Each event includes hash of previous event (`previous_hash`)
2. Current event hash calculated from all fields (`record_hash`)
3. HMAC signature using secret key (`hmac_signature`)
4. Tampering breaks chain and is detectable

### Verification

```python
report = integrity_manager.verify_chain(events)
# Returns:
# {
#   "total_records": 1000,
#   "valid_records": 1000,
#   "invalid_records": 0,
#   "chain_intact": True,
#   "issues": []
# }
```

### Evidence

- Audit integrity tests (`test_audit_integrity.py`)
- Chain verification on audit export
- Automated integrity checks (configurable)

---

## AU-11: Audit Record Retention

### Configuration

```toml
# config.toml
audit_retention_days = 90  # Default: 90 days
```

### Retention Policy

1. Audit logs stored in SQLite database
2. Automatic purge of records older than retention period
3. `SYSTEM_EVENT` logged for purge operations
4. Optional export before purge

### Compliance Requirements

| Regulation | Minimum Retention |
|------------|------------------|
| HIPAA | 6 years |
| GDPR | Duration of processing + statute |
| FedRAMP | 90 days minimum |
| SOX | 7 years |

---

## Test Coverage

| Control | Test File | Test Count |
|---------|-----------|------------|
| AU-2/3 | test_audit_event.py | 25 |
| AU-6 | test_siem_exporter.py | 38 |
| AU-9 | test_audit_integrity.py | 20 |
| AU-* | test_audit_logger.py | 45 |

**Total: 128 tests for AU family**

---

*Next: [Identification and Authentication (IA)](IA-identification.md)*

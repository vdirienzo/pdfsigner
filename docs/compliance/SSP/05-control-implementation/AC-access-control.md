# Access Control (AC) Family

## Control Implementation Status

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AC-1 | Policy and Procedures | ✅ | This document |
| AC-2 | Account Management | ✅ | User repository |
| AC-3 | Access Enforcement | ✅ | RBAC system |
| AC-4 | Information Flow | ✅ | API middleware |
| AC-5 | Separation of Duties | ✅ | Role definitions |
| AC-6 | Least Privilege | ✅ | Permission model |
| AC-7 | Unsuccessful Logon | ✅ | Account lockout |
| AC-8 | System Use Notification | ⚠️ | Partial |
| AC-11 | Session Lock | ✅ | Auto-logoff |
| AC-12 | Session Termination | ✅ | Timeout |
| AC-14 | Permitted Actions | ✅ | Role permissions |
| AC-17 | Remote Access | ✅ | TLS/mTLS |
| AC-18 | Wireless Access | N/A | Not applicable |
| AC-19 | Mobile Device Access | N/A | Not applicable |
| AC-20 | External Systems | ✅ | TSA/OCSP only |
| AC-21 | Information Sharing | ✅ | API controls |
| AC-22 | Publicly Accessible | ✅ | API only |

---

## AC-2: Account Management

### Implementation

**Module:** `core/users/user_repository.py`

```python
class UserRepository:
    """SQLite-backed user management with audit trail."""

    def create_user(user: User) -> User
    def update_user(user_id: str, updates: dict) -> User
    def delete_user(user_id: str) -> bool  # Soft delete with anonymization
    def get_user(user_id: str) -> User | None
    def list_users(filters: dict) -> list[User]
```

### Evidence

- User creation generates `USER_CREATE` audit event
- User modification generates `USER_UPDATE` audit event
- User deletion generates `USER_DELETE` audit event
- Certificate binding tracked via `CertificateBindingService`

### Configuration

```toml
# config.toml
healthcare_mode = true  # Enables enhanced user management
gdpr_enabled = true     # Enables deletion/anonymization
```

---

## AC-3: Access Enforcement

### Implementation

**Module:** `core/rbac/role_manager.py`

```python
class RoleManager:
    """Role-Based Access Control implementation."""

    ROLES = {
        "ADMIN": ["*"],  # All permissions
        "AUDITOR": ["VIEW_AUDIT", "EXPORT_AUDIT", "GENERATE_REPORT"],
        "SIGNER": ["SIGN_DOCUMENT", "VALIDATE_DOCUMENT", "VIEW_CERTIFICATE"],
        "VIEWER": ["VIEW_DOCUMENT", "VIEW_SIGNATURE"],
        "OPERATOR": ["BATCH_SIGN", "BATCH_VALIDATE"]
    }

    def has_permission(user_role: str, permission: str) -> bool
    def get_permissions(user_role: str) -> list[str]
```

### API Enforcement

**Module:** `api/middleware/auth.py`

```python
@app.middleware("http")
async def auth_middleware(request, call_next):
    # Validate JWT/API key
    # Check RBAC permission for endpoint
    # Log access attempt
```

### Evidence

- 65+ RBAC unit tests (`test_rbac.py`)
- API integration tests (`test_api.py`)
- Audit events for `ACCESS_GRANTED` / `ACCESS_DENIED`

---

## AC-6: Least Privilege

### Implementation

Each role has minimum necessary permissions:

| Role | Permissions | Rationale |
|------|-------------|-----------|
| VIEWER | VIEW_* only | Read-only access |
| SIGNER | SIGN, VALIDATE, VIEW_CERT | Signing operations only |
| AUDITOR | VIEW_AUDIT, EXPORT_AUDIT, REPORT | Compliance review only |
| OPERATOR | BATCH_* | Bulk operations only |
| ADMIN | * | System administration |

### Evidence

- Permissions defined in `core/rbac/permissions.py`
- Role assignment in user creation workflow
- Permission checks at API and GUI layers

---

## AC-7: Unsuccessful Logon Attempts

### Implementation

**Module:** `core/auth/password_validator.py`

```python
# Settings (config.toml)
password_lockout_threshold = 5      # Failed attempts
password_lockout_duration_minutes = 30  # Lockout duration
```

### Behavior

1. Failed login increments counter
2. After 5 failures: account locked
3. `ACCOUNT_LOCKED` audit event generated
4. After 30 minutes: account auto-unlocks
5. Admin can manually unlock via `ACCOUNT_UNLOCKED`

### Evidence

- Unit tests in `test_password_policy.py`
- Audit events: `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`

---

## AC-11: Session Lock / AC-12: Session Termination

### Implementation

**Module:** `core/session/session_manager.py`

```python
class SessionManager:
    """Session management with HIPAA compliance."""

    def create_session(user_id: str) -> Session
    def validate_session(session_id: str) -> bool
    def terminate_session(session_id: str) -> None
    def cleanup_expired() -> int  # Called by scheduler
```

### Configuration

```toml
# config.toml
healthcare_mode = true
healthcare_session_timeout_minutes = 15  # Auto-logoff
healthcare_max_sessions = 3              # Concurrent limit
```

### Behavior

1. Session created at login with expiry timestamp
2. Each request validates session is not expired
3. Expired sessions auto-terminated
4. Concurrent session limit enforced

### Evidence

- 34+ session manager tests (`test_session_manager.py`)
- Audit events: `SESSION_START`, `SESSION_END`, `SESSION_TIMEOUT`

---

## AC-17: Remote Access

### Implementation

**Module:** `api/middleware/tls.py`

```python
class TLSMiddleware:
    """TLS enforcement for API connections."""

    # Features:
    # - TLS 1.2/1.3 minimum version
    # - HTTP to HTTPS redirect
    # - Optional mTLS (client certificates)
    # - Strict mode (reject HTTP entirely)
```

### Configuration

```toml
# Environment variables
PDFSIGNER_API_TLS_ENABLED = true
PDFSIGNER_API_TLS_CERT_PATH = "/path/to/cert.pem"
PDFSIGNER_API_TLS_KEY_PATH = "/path/to/key.pem"
PDFSIGNER_API_TLS_MIN_VERSION = "TLSv1.2"
PDFSIGNER_API_TLS_REQUIRE_CLIENT_CERT = true  # mTLS
```

### Evidence

- 28 TLS middleware tests (`test_tls_middleware.py`)
- API validates TLS configuration at startup

---

## Test Coverage

| Control | Test File | Test Count |
|---------|-----------|------------|
| AC-2 | test_user_repository.py | 45 |
| AC-3 | test_rbac.py | 65 |
| AC-7 | test_password_policy.py | 40 |
| AC-11/12 | test_session_manager.py | 34 |
| AC-17 | test_tls_middleware.py | 28 |

**Total: 212 tests for AC family**

---

*Next: [Audit and Accountability (AU)](AU-audit.md)*

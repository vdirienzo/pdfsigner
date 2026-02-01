# Identification and Authentication (IA) Family

## Control Implementation Status

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| IA-1 | Policy and Procedures | ✅ | This document |
| IA-2 | User Identification | ✅ | Unique user IDs |
| IA-2(1) | MFA - Network Access | ✅ | TOTP + backup codes |
| IA-2(2) | MFA - Local Access | ✅ | PKCS#11 PIN + MFA |
| IA-4 | Identifier Management | ✅ | User repository |
| IA-5 | Authenticator Management | ✅ | Password policy |
| IA-5(1) | Password-Based | ✅ | Argon2, history |
| IA-6 | Authenticator Feedback | ✅ | Generic errors |
| IA-7 | Cryptographic Auth | ✅ | PKCS#11 tokens |
| IA-8 | Non-Org User ID | ✅ | API key auth |
| IA-11 | Re-authentication | ✅ | Session timeout |

---

## IA-2: User Identification and Authentication

### Authentication Methods

| Method | Use Case | Implementation |
|--------|----------|----------------|
| PKCS#11 Token | Primary signing | NSS/HSM + PIN |
| Password | API/Web access | Argon2 hashed |
| MFA (TOTP) | Enhanced security | RFC 6238 |
| API Key | Service accounts | Secure random |
| mTLS | Machine-to-machine | X.509 certificates |

### Implementation

**GUI Authentication:**
```python
# User authenticates with PKCS#11 token
1. User selects certificate from token
2. User enters PIN
3. Optional: MFA verification
4. Session created with timeout
```

**API Authentication:**
```python
# JWT Bearer token
Authorization: Bearer <jwt_token>

# API Key
X-API-Key: <api_key>
```

---

## IA-2(1): Multi-Factor Authentication

### Implementation

**Module:** `core/auth/mfa/`

```python
# TOTP Provider (RFC 6238)
class TOTPProvider:
    def generate_secret() -> str
    def generate_totp(secret: str) -> str
    def verify_totp(secret: str, code: str, window: int = 1) -> bool
    def generate_qr_code(secret: str, account: str) -> bytes

# Backup Codes
class BackupCodeManager:
    def generate_codes(count: int = 10) -> list[str]
    def verify_code(user_id: str, code: str) -> bool  # Single-use

# MFA Manager
class MFAManager:
    def enroll(user_id: str) -> MFAEnrollment
    def verify_and_activate(user_id: str, code: str) -> bool
    def verify(user_id: str, code: str, is_backup: bool = False) -> bool
    def disable(user_id: str, admin_id: str = None) -> bool
    def regenerate_backup_codes(user_id: str) -> list[str]
```

### Configuration

```toml
# config.toml
mfa_enabled = true
mfa_required_for_roles = ["ADMIN", "AUDITOR"]
mfa_backup_codes_count = 10
mfa_issuer_name = "PDFSigner"
```

### Evidence

- 46 MFA tests (`test_mfa.py`)
- API endpoints: `/api/v1/mfa/setup`, `/api/v1/mfa/verify`, etc.
- Audit events: `MFA_ENROLLED`, `MFA_VERIFIED`, `MFA_VERIFICATION_FAILED`

---

## IA-5: Authenticator Management (Password Policy)

### Implementation

**Module:** `core/auth/password_policy.py`, `core/auth/password_validator.py`

```python
@dataclass
class PasswordPolicy:
    min_length: int = 12        # NIST 800-63B minimum
    max_length: int = 128       # Prevent DoS
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    special_characters: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_age_days: int = 90      # Expiration
    history_count: int = 12     # Prevent reuse
    lockout_threshold: int = 5  # Failed attempts
    lockout_duration_minutes: int = 30
    min_unique_chars: int = 8   # Prevent patterns

class PasswordValidator:
    def validate(password: str, user_id: str = None) -> ValidationResult
    def check_history(user_id: str, password: str) -> bool
    def check_common_passwords(password: str) -> bool
    def calculate_strength(password: str) -> int  # 0-100
    def hash_password(password: str) -> str       # Argon2
    def verify_password(password: str, hashed: str) -> bool
```

### Configuration

```toml
# config.toml
password_min_length = 12
password_max_age_days = 90
password_history_count = 12
password_lockout_threshold = 5
password_lockout_duration_minutes = 30
password_require_special = true
password_min_unique_chars = 8
```

### Password Storage

- **Algorithm:** Argon2id (NIST recommended)
- **History:** SQLite table with hashed passwords
- **Verification:** Constant-time comparison

### Evidence

- 40+ password policy tests (`test_password_policy.py`)
- Common passwords list (100+ entries)
- Audit events: `PASSWORD_CHANGED`, `PASSWORD_RESET`

---

## IA-7: Cryptographic Module Authentication

### PKCS#11 Integration

**Module:** `core/token/nss_handler.py`

```python
class NSSHandler:
    """PKCS#11 communication via NSS database."""

    def list_certificates() -> list[CertInfo]
    def sign(cert_serial: str, data: bytes, pin: str) -> bytes
    def get_certificate(serial: str) -> Certificate
```

### Supported Tokens

| Token Type | Interface | Status |
|------------|-----------|--------|
| NSS Software | PKCS#11 | ✅ Supported |
| SafeNet eToken | PKCS#11 | ✅ Supported |
| YubiKey | PKCS#11 | ✅ Supported |
| HSM (Thales/nCipher) | PKCS#11 | ✅ Supported |

### Evidence

- Token tests in integration suite
- Certificate binding service
- PIN cache with timeout

---

## IA-11: Re-authentication

### Implementation

**Module:** `core/session/session_manager.py`

```python
class SessionManager:
    def validate_session(session_id: str) -> bool:
        """Check session is valid and not expired."""

    def extend_session(session_id: str) -> bool:
        """Extend session on activity (sliding window)."""
```

### Configuration

```toml
# config.toml
healthcare_session_timeout_minutes = 15  # HIPAA compliance
```

### Re-authentication Triggers

| Trigger | Action |
|---------|--------|
| Session timeout | Force re-authentication |
| Privilege escalation | MFA verification |
| Emergency access | Admin approval required |
| Sensitive operation | PIN re-entry |

---

## Test Coverage

| Control | Test File | Test Count |
|---------|-----------|------------|
| IA-2(1) | test_mfa.py | 46 |
| IA-5 | test_password_policy.py | 40 |
| IA-7 | integration tests | 20 |
| IA-11 | test_session_manager.py | 34 |

**Total: 140 tests for IA family**

---

*Next: [System and Communications Protection (SC)](SC-system-comms.md)*

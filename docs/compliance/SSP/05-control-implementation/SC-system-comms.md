# System and Communications Protection (SC) Family

## Control Implementation Status

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SC-1 | Policy and Procedures | ✅ | This document |
| SC-5 | Denial of Service | ✅ | Rate limiting |
| SC-7 | Boundary Protection | ✅ | API gateway |
| SC-8 | Transmission Confidentiality | ✅ | TLS 1.2+ |
| SC-8(1) | Cryptographic Protection | ✅ | mTLS optional |
| SC-12 | Cryptographic Key Management | ✅ | KeyManager |
| SC-13 | Cryptographic Protection | ✅ | FIPS 140-2 |
| SC-17 | PKI Certificates | ✅ | PKCS#11 |
| SC-23 | Session Authenticity | ✅ | JWT tokens |
| SC-28 | Protection at Rest | ✅ | AES-256 |
| SC-28(1) | Cryptographic Protection | ✅ | Validated algorithms |

---

## SC-8: Transmission Confidentiality and Integrity

### Implementation

**Module:** `api/middleware/tls.py`

```python
class TLSMiddleware:
    """TLS enforcement for API connections."""

    def __init__(self):
        self.min_version = "TLSv1.2"
        self.redirect_http = True
        self.strict_mode = False  # Reject HTTP entirely

    async def __call__(self, request, call_next):
        # Check if request is HTTPS
        # Redirect or reject HTTP based on config
        # Validate client certificate (mTLS)
```

### Configuration

```bash
# Environment variables
PDFSIGNER_API_TLS_ENABLED=true
PDFSIGNER_API_TLS_CERT_PATH=/path/to/cert.pem
PDFSIGNER_API_TLS_KEY_PATH=/path/to/key.pem
PDFSIGNER_API_TLS_MIN_VERSION=TLSv1.2
PDFSIGNER_API_TLS_REQUIRE_CLIENT_CERT=true  # mTLS
PDFSIGNER_API_TLS_CA_CERT_PATH=/path/to/ca.pem
PDFSIGNER_API_TLS_REDIRECT_HTTP=true
PDFSIGNER_API_TLS_STRICT_MODE=false
```

### Supported TLS Versions

| Version | Status | Notes |
|---------|--------|-------|
| TLS 1.0 | ❌ Disabled | Deprecated |
| TLS 1.1 | ❌ Disabled | Deprecated |
| TLS 1.2 | ✅ Supported | Minimum |
| TLS 1.3 | ✅ Supported | Recommended |

### Evidence

- 28 TLS middleware tests (`test_tls_middleware.py`)
- Startup validation of TLS configuration
- Audit logging of TLS errors

---

## SC-12: Cryptographic Key Establishment and Management

### Implementation

**Module:** `core/crypto/key_manager.py`

```python
class KeyManager:
    """Secure key storage with encryption and rotation."""

    def store_key(key_id: str, key_data: bytes, metadata: dict) -> None
    def get_key(key_id: str) -> bytes | None
    def rotate_key(key_id: str) -> str  # Returns new key_id
    def delete_key(key_id: str) -> bool
    def list_keys(filters: dict) -> list[KeyInfo]
    def check_expiring_keys(days: int = 30) -> list[KeyInfo]
```

### Key Lifecycle

```
Generate → Store (encrypted) → Use → Rotate → Archive → Destroy
```

### Configuration

```toml
# config.toml
key_storage_path = "~/.config/pdfsigner/keys.db"
key_default_expiry_days = 365
key_auto_rotate_days = 90
```

### Key Protection

- Keys encrypted at rest using master password
- Master password from environment variable
- SQLite database with encrypted blobs
- Automatic rotation based on age

### Evidence

- 30 key manager tests (`test_key_manager.py`)
- Audit events for key operations

---

## SC-13: Cryptographic Protection (FIPS 140-2)

### Implementation

**Module:** `core/crypto/fips_provider.py`

```python
class FIPSProvider:
    """FIPS 140-2 validated algorithm enforcement."""

    FIPS_ALGORITHMS = {
        "hash": ["SHA-256", "SHA-384", "SHA-512"],
        "symmetric": ["AES-128", "AES-256"],
        "asymmetric": ["RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384"],
        "mac": ["HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512"]
    }

    def validate_algorithm(algorithm: str) -> bool
    def get_default_hash() -> str  # SHA-256
    def get_default_encryption() -> str  # AES-256
```

### Configuration

```toml
# config.toml
fips_mode_enabled = true
fips_strict_mode = true  # Raise exception for non-FIPS
```

### Rejected Algorithms (FIPS Mode)

| Algorithm | Reason |
|-----------|--------|
| MD5 | Weak hash |
| SHA-1 | Deprecated |
| DES, 3DES | Weak encryption |
| RSA < 2048 | Insufficient key size |

### Evidence

- 25 FIPS provider tests (`test_fips_provider.py`)
- Algorithm validation at signing time
- Audit logging of algorithm usage

---

## SC-28: Protection of Information at Rest

### Implementation

**Module:** `core/encryption/`

```python
class PDFEncryptor:
    """PDF encryption for HIPAA compliance."""

    def encrypt(
        pdf_path: str,
        password: str,
        strength: str = "aes256",  # or "aes128"
        allow_print: bool = False,
        allow_copy: bool = False
    ) -> str

class EncryptionValidator:
    """Validate encryption meets HIPAA requirements."""

    def validate_hipaa_compliant(settings: dict) -> ValidationResult
```

### Configuration

```toml
# config.toml
encryption_default_strength = "aes256"
encryption_hipaa_mode = true
encryption_default_allow_print = false  # HIPAA: must be false
encryption_default_allow_copy = false
```

### HIPAA Encryption Requirements

| Requirement | Implementation |
|-------------|----------------|
| AES-256 minimum | ✅ Default strength |
| No printing | ✅ Configurable |
| No copying | ✅ Configurable |
| Password protection | ✅ Required |

### Evidence

- 36 encryption tests
- HIPAA validation in `EncryptionValidator`
- Audit events: `ENCRYPT_SUCCESS`, `DECRYPT_SUCCESS`

---

## Cryptographic Algorithms Summary

### Signing

| Algorithm | Use Case | FIPS Status |
|-----------|----------|-------------|
| RSA-2048 | Legacy compatibility | ✅ Approved |
| RSA-4096 | High security | ✅ Approved |
| ECDSA P-256 | Modern signing | ✅ Approved |
| ECDSA P-384 | High security | ✅ Approved |

### Hashing

| Algorithm | Use Case | FIPS Status |
|-----------|----------|-------------|
| SHA-256 | Default | ✅ Approved |
| SHA-384 | High security | ✅ Approved |
| SHA-512 | Maximum security | ✅ Approved |

### Encryption

| Algorithm | Use Case | FIPS Status |
|-----------|----------|-------------|
| AES-256-CBC | Document encryption | ✅ Approved |
| AES-256-GCM | Authenticated encryption | ✅ Approved |

---

## Test Coverage

| Control | Test File | Test Count |
|---------|-----------|------------|
| SC-8 | test_tls_middleware.py | 28 |
| SC-12 | test_key_manager.py | 30 |
| SC-13 | test_fips_provider.py | 25 |
| SC-28 | test_encryption*.py | 36 |

**Total: 119 tests for SC family**

---

*Next: [Incident Response (IR)](IR-incident.md)*

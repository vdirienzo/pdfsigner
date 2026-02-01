# Encryption and Key Management Policy

**Document Version:** 1.0
**Effective Date:** 2026-02-01
**Review Cycle:** Annual
**Owner:** Security Operations Team
**Classification:** Internal Use

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Policy Statement](#2-policy-statement)
3. [Approved Cryptographic Algorithms](#3-approved-cryptographic-algorithms)
4. [FIPS 140-2 Compliance](#4-fips-140-2-compliance)
5. [Key Lifecycle Management](#5-key-lifecycle-management)
6. [Key Storage Requirements](#6-key-storage-requirements)
7. [Key Rotation Schedule](#7-key-rotation-schedule)
8. [Certificate Lifecycle Management](#8-certificate-lifecycle-management)
9. [Encryption at Rest](#9-encryption-at-rest)
10. [Encryption in Transit](#10-encryption-in-transit)
11. [Memory Security and Sensitive Data Handling](#11-memory-security-and-sensitive-data-handling)
12. [Compliance Mapping](#12-compliance-mapping)
13. [Roles and Responsibilities](#13-roles-and-responsibilities)
14. [Exceptions and Waivers](#14-exceptions-and-waivers)
15. [Policy Enforcement](#15-policy-enforcement)
16. [Revision History](#16-revision-history)

---

## 1. Purpose and Scope

### 1.1 Purpose

This policy establishes the cryptographic standards and key management procedures for PDFSigner to ensure:

- **Confidentiality**: Protection of sensitive data through strong encryption
- **Integrity**: Assurance that data has not been altered without authorization
- **Authenticity**: Verification of data origin and signer identity
- **Non-repudiation**: Prevention of denial of actions performed
- **Compliance**: Adherence to HIPAA §164.312(a)(2)(iv), NIST SP 800-53, and FIPS 140-2

### 1.2 Scope

This policy applies to:

- All cryptographic operations performed by PDFSigner
- Digital signature creation and validation
- PDF document encryption and decryption
- Cryptographic key generation, storage, distribution, rotation, and destruction
- Certificate lifecycle management
- Hardware security module (HSM) and PKCS#11 token operations
- Audit log integrity protection

### 1.3 Audience

This document is intended for:

- Security officers and auditors
- System administrators deploying PDFSigner
- Development team maintaining cryptographic implementations
- Compliance officers evaluating regulatory adherence
- Third-party auditors reviewing security controls

---

## 2. Policy Statement

PDFSigner SHALL implement cryptographic controls that:

1. Use only FIPS 140-2 validated algorithms when operating in FIPS mode
2. Protect cryptographic keys throughout their lifecycle
3. Enforce minimum key lengths and algorithm strengths
4. Implement secure key storage using hardware security modules when available
5. Rotate cryptographic keys according to defined schedules
6. Encrypt sensitive data at rest and in transit
7. Maintain audit trails of all cryptographic operations
8. Support certificate-based authentication and encryption

**Compliance Mandate**: Organizations handling HIPAA-regulated data MUST enable FIPS mode and healthcare compliance features.

---

## 3. Approved Cryptographic Algorithms

PDFSigner restricts cryptographic algorithm usage based on operational mode and compliance requirements.

### 3.1 Hash Algorithms

| Algorithm | Key Length | FIPS 140-2 | Use Cases | Status |
|-----------|-----------|------------|-----------|--------|
| SHA-256 | 256-bit | ✓ | Signatures, integrity verification, audit chains | **REQUIRED** |
| SHA-384 | 384-bit | ✓ | High-security signatures, long-term validation | Recommended |
| SHA-512 | 512-bit | ✓ | High-security signatures, long-term validation | Recommended |
| SHA-1 | 160-bit | ✗ | Validation of legacy signatures only | **DEPRECATED** |
| MD5 | 128-bit | ✗ | Not permitted | **PROHIBITED** |

**Implementation**: `src/pdfsigner/core/crypto/fips_provider.py` enforces these restrictions via `FIPSCryptoProvider.ALLOWED_HASH`.

### 3.2 Symmetric Encryption Algorithms

| Algorithm | Key Length | FIPS 140-2 | Use Cases | Status |
|-----------|-----------|------------|-----------|--------|
| AES-256 | 256-bit | ✓ | PDF encryption, credential storage | **REQUIRED for HIPAA** |
| AES-128 | 128-bit | ✓ | PDF encryption (general use) | Permitted |
| 3DES | 168-bit | ✗ | Not permitted | **PROHIBITED** |
| RC4 | Variable | ✗ | Not permitted | **PROHIBITED** |

**Configuration**: Set `encryption_default_strength = "aes256"` in `~/.config/pdfsigner/config.toml`.

### 3.3 Asymmetric Signature Algorithms

| Algorithm | Key Length | FIPS 140-2 | Use Cases | Status |
|-----------|-----------|------------|-----------|--------|
| RSA | 4096-bit | ✓ | Digital signatures (preferred) | **RECOMMENDED** |
| RSA | 2048-bit | ✓ | Digital signatures (minimum) | **REQUIRED** |
| RSA | < 2048-bit | ✗ | Not permitted | **PROHIBITED** |
| ECDSA P-384 | 384-bit | ✓ | Digital signatures (elliptic curve) | Recommended |
| ECDSA P-256 | 256-bit | ✓ | Digital signatures (elliptic curve) | Permitted |
| DSA | Any | ✗ | Not permitted | **PROHIBITED** |

**Implementation**: PKCS#11 tokens must provide keys meeting minimum requirements. Validation occurs during certificate enumeration in `src/pdfsigner/core/token/nss_handler.py`.

### 3.4 Message Authentication Codes (MAC)

| Algorithm | Key Length | FIPS 140-2 | Use Cases | Status |
|-----------|-----------|------------|-----------|--------|
| HMAC-SHA-256 | 256-bit | ✓ | Audit log integrity, password storage | **REQUIRED** |
| HMAC-SHA-384 | 384-bit | ✓ | High-security audit trails | Recommended |

**Implementation**: Audit integrity manager (`src/pdfsigner/core/audit/audit_integrity.py`) uses HMAC-SHA-256 for tamper detection.

---

## 4. FIPS 140-2 Compliance

### 4.1 FIPS Mode Requirements

PDFSigner implements FIPS 140-2 compliance through configurable enforcement modes:

| Setting | Configuration | Behavior |
|---------|--------------|----------|
| FIPS Mode | `fips_mode_enabled = true` | Restricts to FIPS-approved algorithms only |
| Strict Mode | `fips_strict_mode = true` | Raises exceptions for non-FIPS algorithm attempts |
| Relaxed Mode | `fips_strict_mode = false` | Logs warnings for non-FIPS algorithms but continues |

**Configuration Location**: `~/.config/pdfsigner/config.toml`

### 4.2 FIPS Validation Checks

The `FIPSCryptoProvider` performs runtime validation:

1. **Algorithm Validation**: All cryptographic operations are checked against approved algorithm lists
2. **OpenSSL FIPS Detection**: Detects if system OpenSSL is running in FIPS mode
3. **Enforcement**: Blocks or warns about non-compliant operations based on strict_mode setting

**Test Verification**: `tests/unit/test_fips_provider.py` validates FIPS enforcement logic.

### 4.3 Federal Deployment Requirements

For U.S. federal agencies or contractors:

```toml
# Required configuration for FIPS compliance
fips_mode_enabled = true
fips_strict_mode = true
encryption_default_strength = "aes256"
healthcare_mode = true  # If handling HIPAA data
```

**Validation Command**:
```bash
uv run pdfsigner --check-fips
```

### 4.4 OpenSSL FIPS Module

PDFSigner leverages system OpenSSL for cryptographic operations. To enable full FIPS validation:

**Ubuntu/Debian**:
```bash
sudo apt install openssl-fips
sudo update-crypto-policies --set FIPS
```

**RHEL/CentOS**:
```bash
sudo fips-mode-setup --enable
sudo reboot
```

**Verification**:
```bash
openssl version
# Should show "fips" in output if enabled
```

---

## 5. Key Lifecycle Management

### 5.1 Key Generation

#### 5.1.1 Signing Keys (Asymmetric)

- **Method**: Generated on PKCS#11-compliant hardware tokens or HSMs
- **Minimum Strength**: RSA-2048 or ECDSA-P256
- **Recommended Strength**: RSA-4096 or ECDSA-P384
- **Generation Environment**: Hardware security module (HSM) with FIPS 140-2 Level 2+ validation
- **Random Number Generation**: Hardware-based TRNG (True Random Number Generator)

**Supported Tokens**:
- SafeNet eToken
- YubiKey (PIV/PKCS#11 mode)
- Nitrokey HSM
- OpenSC-compatible smart cards
- SoftHSM (development/testing only - NOT for production)

**Implementation**: `src/pdfsigner/core/token/pkcs11_libs.py` defines supported token libraries.

#### 5.1.2 Encryption Keys (Symmetric)

- **Method**: Derived from user passwords using PBKDF2
- **Key Derivation**: PBKDF2-HMAC-SHA256 with minimum 10,000 iterations
- **Salt**: Cryptographically random, unique per document
- **Storage**: System keyring (libsecret/KeyChain/Windows Credential Manager)

**Implementation**: `src/pdfsigner/core/encryption/credential_store.py`

#### 5.1.3 Audit Integrity Keys (HMAC)

- **Method**: Derived from machine-specific identifiers
- **Algorithm**: HMAC-SHA-256
- **Derivation**: SHA-256(hostname + MAC address)
- **Purpose**: Tamper detection for audit logs

**Implementation**: `AuditIntegrityManager._get_default_secret()` in `src/pdfsigner/core/audit/audit_integrity.py`

### 5.2 Key Distribution

#### 5.2.1 Certificate Distribution

- **Method**: X.509 certificates embedded in PKCS#11 tokens
- **Chain Validation**: Full chain validation including intermediate CAs
- **Revocation Checking**: OCSP (preferred) or CRL when enabled
- **Certificate Binding**: User accounts bound to specific certificates via serial number

**Configuration**:
```toml
revocation_check_enabled = true
revocation_prefer_ocsp = true
revocation_check_timeout = 10  # seconds
```

#### 5.2.2 Password Distribution

- **Transmission**: Never transmitted - generated/entered locally only
- **Storage**: Encrypted in system keyring with per-file unique identifiers
- **Access Control**: Operating system-enforced keyring access controls

### 5.3 Key Usage

#### 5.3.1 Usage Restrictions

| Key Type | Permitted Operations | Prohibited Operations |
|----------|---------------------|----------------------|
| Signing Keys | Digital signature creation | Encryption, key agreement |
| Encryption Keys | PDF encryption/decryption | Signing, authentication |
| HMAC Keys | Audit log signing | Encryption, signatures |

**Enforcement**: PKCS#11 Key Usage extensions enforced by token hardware.

#### 5.3.2 PIN/Password Protection

- **PIN Caching**: Configurable with timeout (default: disabled)
- **Maximum Cache Duration**: 60 minutes
- **Failed Attempt Handling**: Honors token lockout policies
- **Multi-factor Authentication**: Supported via PKCS#11 token biometrics

**Configuration**:
```toml
pin_cache_enabled = false
pin_cache_timeout_seconds = 300
```

**Security Note**: PIN caching is disabled by default and should only be enabled for batch operations in controlled environments.

### 5.4 Key Storage

See [Section 6: Key Storage Requirements](#6-key-storage-requirements)

### 5.5 Key Backup and Recovery

#### 5.5.1 Certificate Backup

- **Method**: Export certificate (public key only) from token for archival
- **Private Keys**: NEVER exported from hardware token
- **Backup Location**: Encrypted offline storage
- **Access Control**: Multi-person authorization required for backup access

#### 5.5.2 Encryption Password Recovery

- **Method**: Owner password recovery via secure keyring backup
- **Backup Requirement**: System keyring backup per organization policy
- **Emergency Access**: Healthcare mode supports emergency access procedures

**Healthcare Emergency Access**:
```toml
healthcare_emergency_duration_hours = 4
healthcare_emergency_require_approval = true
```

### 5.6 Key Destruction

#### 5.6.1 Hardware Token Key Destruction

- **Method**: PKCS#11 C_DestroyObject() call or token reinitialization
- **Verification**: Enumerate objects post-destruction to confirm removal
- **Physical Destruction**: Token physical destruction for decommissioning

#### 5.6.2 Software Key Destruction

- **Method**: Secure deletion from keyring
- **Memory Wiping**: Sensitive data cleared from memory (see Section 11)
- **File Deletion**: Secure overwrite (DoD 5220.22-M when enabled)

**Configuration**:
```toml
temp_secure_delete = true  # Enable 3-pass secure overwrite
```

**Implementation**: `src/pdfsigner/core/security/credential_manager.py` handles secure deletion.

---

## 6. Key Storage Requirements

### 6.1 Hardware Security Modules (HSM)

#### 6.1.1 Production Environment Requirements

**REQUIRED for production systems processing sensitive data**:

- **FIPS 140-2 Validation**: Minimum Level 2 (physical tamper-evidence)
- **Recommended**: Level 3 (tamper-responsive) for HIPAA environments
- **Interface**: PKCS#11 v2.40 or later
- **Key Export**: Private keys SHALL NOT be exportable
- **Authentication**: Multi-factor authentication (PIN + biometric) preferred

**Supported HSM Types**:
- USB cryptographic tokens (YubiKey, Nitrokey, SafeNet)
- Smart cards with PIV/PKCS#11 support
- Network HSMs via PKCS#11 proxy (Luna SA, nCipher nShield)

#### 6.1.2 NSS Database Configuration

PDFSigner uses NSS (Network Security Services) as the PKCS#11 middleware:

**Location**: `~/.config/pdfsigner/config.toml`
```toml
nss_db_path = "~/.nss"  # NSS database location
```

**Initialization**:
```bash
# Create NSS database
mkdir -p ~/.nss
certutil -N -d sql:$HOME/.nss

# List tokens
uv run pdfsigner list-tokens
```

**Security Notes**:
- NSS database password should be different from token PIN
- Database files should have 0600 permissions (owner read/write only)
- Backup NSS database separately from tokens

### 6.2 Encrypted Key Storage (Software)

#### 6.2.1 System Keyring (Preferred)

**Implementation**: `EncryptionCredentialStore` uses system keyring services:

- **Linux**: libsecret (GNOME Keyring / KWallet)
- **macOS**: Keychain
- **Windows**: Windows Credential Manager

**Security Features**:
- Operating system access control enforcement
- Encryption at rest using system credentials
- Per-user isolation
- Optional additional password protection

**Storage Format**:
```
Service: pdfsigner
Key: pdfsigner_encrypt_{filename}_{hash16}_{owner|user}
Value: AES-256 encrypted password
```

#### 6.2.2 Encrypted SQLite Database (Alternative)

For systems without keyring support:

**Location**: `~/.config/pdfsigner/keys.db`

**Configuration**:
```toml
key_storage_path = "~/.config/pdfsigner/keys.db"
# Set via environment variable:
# export PDFSIGNER_KEY_STORAGE_MASTER_PASSWORD="strong-master-password"
```

**Encryption**:
- AES-256-GCM encryption
- PBKDF2 key derivation (100,000 iterations minimum)
- Per-record unique nonces
- HMAC integrity verification

**Access Control**:
- File permissions: 0600 (owner only)
- Master password required for database decryption
- Automatic locking after inactivity

**Security Warning**: Master password must be stored securely (environment variable, secret manager). Do not hardcode in configuration files.

### 6.3 Audit Log Integrity Keys

**Storage Method**: In-memory derived keys (not persisted)

**Derivation**:
```python
# Pseudo-code
machine_id = f"{hostname}-{mac_address}"
hmac_key = SHA-256(machine_id)
```

**Rationale**: Machine-specific keys prevent audit log tampering while allowing verification on the same system.

**Limitation**: Audit logs cannot be verified on different systems without key export (intentional security feature).

---

## 7. Key Rotation Schedule

### 7.1 Signing Key Rotation

| Key Type | Rotation Schedule | Trigger Events | Configuration |
|----------|------------------|----------------|---------------|
| RSA-2048 | **Annual** | Certificate expiration, compromise | `key_default_expiry_days = 365` |
| RSA-4096 | Biennial (2 years) | Certificate expiration, compromise | N/A |
| ECDSA-P256 | **Annual** | Certificate expiration, compromise | N/A |
| ECDSA-P384 | Biennial (2 years) | Certificate expiration, compromise | N/A |

**Automatic Rotation Warning**:
```toml
key_auto_rotate_days = 90  # Warn 90 days before expiration
```

**Implementation**: Certificate expiration monitoring via `src/pdfsigner/core/token/nss_handler.py` (`CertificateInfo.not_after`).

### 7.2 Encryption Key Rotation

| Key Type | Rotation Schedule | Trigger Events |
|----------|------------------|----------------|
| PDF Encryption (Password) | Per-document | Each encryption operation uses unique key |
| PDF Encryption (Certificate) | Annual | Certificate renewal |
| Credential Store Master Key | Annual | Policy review, administrator change |

**Best Practice**: Re-encrypt sensitive PDFs annually even without policy change.

### 7.3 HMAC Key Rotation

| Key Type | Rotation Schedule | Trigger Events |
|----------|------------------|----------------|
| Audit Integrity HMAC | Not rotated | Machine reimaging, security incident |

**Note**: HMAC key rotation requires re-signing entire audit log history.

### 7.4 Emergency Key Rotation

**Immediate rotation required upon**:
- **Suspected compromise**: Any indication of unauthorized key access
- **Token loss**: Physical loss or theft of HSM/token
- **Employee termination**: Departure of personnel with key access
- **Security incident**: Confirmed or suspected breach
- **Vulnerability disclosure**: Critical cryptographic vulnerability (e.g., key length downgrade attack)

**Emergency Rotation Procedure**:
1. Revoke compromised certificate via CA portal
2. Generate new key pair on fresh token
3. Obtain new certificate from CA
4. Update certificate bindings in user registry
5. Re-sign critical documents if necessary
6. Document incident in audit log

**Audit Event**: Emergency rotations trigger `AuditEventType.KEY_ROTATION` events.

---

## 8. Certificate Lifecycle Management

### 8.1 Certificate Issuance

#### 8.1.1 Certificate Authority Requirements

**Production Certificates**:
- **Issuer**: Public CA on Adobe Approved Trust List (AATL) or EU Trusted List (EUTL)
- **Certificate Type**: Qualified Electronic Signature (QES) preferred for eIDAS compliance
- **Minimum Key Length**: RSA-2048 or ECDSA-P256
- **Extended Key Usage**: `1.3.6.1.5.5.7.3.4` (Email Protection) or `1.2.840.113583.1.1.5` (PDF Signing)

**Internal/Development Certificates**:
- **Issuer**: Organization internal CA
- **Use Case**: Testing, development, internal documents
- **Trust**: Not globally trusted - requires manual trust configuration

#### 8.1.2 Certificate Enrollment

**Process**:
1. Generate key pair on PKCS#11 token (non-exportable)
2. Create Certificate Signing Request (CSR) via token
3. Submit CSR to CA via secure channel
4. Verify identity per CA policy (in-person, video verification, etc.)
5. Receive signed certificate
6. Import certificate to token
7. Bind certificate to user account in PDFSigner user registry

**Implementation**: User registry certificate binding in `src/pdfsigner/core/users/certificate_binding.py`.

### 8.2 Certificate Validation

#### 8.2.1 Validation During Signing

**Pre-signing Checks**:
- Certificate validity period (not before/after dates)
- Key usage extension includes digital signature or non-repudiation
- Certificate not revoked (if revocation checking enabled)
- Full chain validation to trusted root

**Implementation**: `src/pdfsigner/core/token/nss_handler.py` (`list_certificates()`, `can_sign` attribute).

#### 8.2.2 Validation During Verification

**Post-signature Validation**:
- Signature cryptographic validity
- Certificate chain validation
- Revocation status (OCSP/CRL when enabled)
- Timestamp validation for long-term signatures
- DSS validation for PAdES-LT/LTA

**Configuration**:
```toml
revocation_check_enabled = true
revocation_prefer_ocsp = true
revocation_cache_ttl = 3600  # 1 hour cache
```

**Implementation**: `src/pdfsigner/core/validator/pdf_validator.py`

### 8.3 Certificate Renewal

**Renewal Triggers**:
- Certificate expiring within 90 days (configurable warning threshold)
- Annual key rotation policy requirement
- Algorithm upgrade (e.g., RSA-2048 to RSA-4096)

**Renewal Process**:
1. Generate new key pair (recommended for RSA-2048, required for algorithm upgrade)
2. Submit renewal request to CA
3. Receive new certificate
4. Import to token
5. Update certificate binding in user registry
6. Archive old certificate (for signature validation)
7. Continue using old certificate until all prior-signed documents are archived

**Parallel Operation Period**: Old and new certificates may coexist during transition.

### 8.4 Certificate Revocation

#### 8.4.1 Revocation Scenarios

**Immediate revocation required**:
- Token/HSM compromise or loss
- Private key exposure
- Certificate holder termination
- Organization name change
- Discovery of fraudulent issuance

#### 8.4.2 Revocation Process

1. **Notify CA**: Contact certificate authority to initiate revocation
2. **Revocation Reason**: Specify reason code (keyCompromise, affiliationChanged, etc.)
3. **Disable in PDFSigner**: Remove certificate binding from user registry
4. **OCSP/CRL Update**: Verify revocation appears in OCSP/CRL within 24 hours
5. **Audit Trail**: Document revocation reason and date

**Implementation**: Certificate revocation status checked via `revocation_check_enabled` in validator.

#### 8.4.3 Signature Implications

**Existing Signatures**:
- Signatures created before revocation date remain valid
- Timestamps prove signature creation time
- Long-term validation (PAdES-LTA) preserves proof of validity

**Future Signatures**:
- Revoked certificate cannot create new valid signatures
- PDFSigner will reject revoked certificates during pre-signing validation

---

## 9. Encryption at Rest

### 9.1 PDF Document Encryption

#### 9.1.1 Encryption Methods

PDFSigner supports two PDF encryption methods:

**Password-Based Encryption**:
- **Algorithm**: AES-128 or AES-256 (configurable)
- **Key Derivation**: PBKDF2 from user/owner passwords
- **Use Case**: General document protection, email transmission

**Certificate-Based Encryption**:
- **Algorithm**: AES-256 with RSA/ECDSA key encryption
- **Key Wrapping**: Symmetric key wrapped with recipient's public key
- **Use Case**: Recipient-specific access control, enterprise deployments

#### 9.1.2 Encryption Configuration

**HIPAA-Compliant Defaults**:
```toml
encryption_default_strength = "aes256"
encryption_hipaa_mode = true
encryption_default_allow_print = false
encryption_default_allow_copy = false
```

**Permissions Control**:
- Print (low quality / high quality)
- Copy content
- Modify content
- Modify annotations
- Fill forms
- Assemble pages
- Accessibility (MUST remain enabled for HIPAA - screen reader access)

**Implementation**: `src/pdfsigner/core/encryption/encryption_config.py` (`PDFPermissions` class).

#### 9.1.3 Metadata Encryption

**Requirement**: Metadata SHALL be encrypted by default to prevent information leakage.

```toml
encrypt_metadata = true  # Default
```

**Unencrypted Metadata Risk**: PDF metadata may contain PHI (patient names, dates, etc.).

### 9.2 Credential Storage Encryption

#### 9.2.1 System Keyring Encryption

**Encryption Method**: Operating system-provided encryption
- **Linux (libsecret)**: AES-256 with user login password
- **macOS (Keychain)**: AES-128 with Keychain password
- **Windows (Credential Manager)**: DPAPI with user credentials

**Key Derivation**: Operating system handles key derivation from user authentication credentials.

#### 9.2.2 SQLite Database Encryption

**Algorithm**: AES-256-GCM

**Key Derivation**:
```python
# Pseudo-code
salt = os.urandom(32)  # 256-bit random salt
key = PBKDF2(master_password, salt, iterations=100000, dklen=32)
```

**Implementation**: `src/pdfsigner/core/security/credential_manager.py`

**Per-Record Structure**:
```json
{
  "id": "unique_record_id",
  "service": "pdfsigner",
  "username": "file_identifier",
  "encrypted_password": "base64(AES-GCM-encrypt(password))",
  "nonce": "base64(random_96bit)",
  "auth_tag": "base64(gcm_tag)"
}
```

### 9.3 Temporary File Encryption

**Policy**: Temporary files containing sensitive data SHALL be encrypted during processing.

**Implementation**:
- **In-memory processing**: Preferred for sensitive operations
- **Disk-based temp files**: Encrypted using AES-256 with ephemeral keys
- **Secure deletion**: 3-pass overwrite (DoD 5220.22-M) when enabled

**Configuration**:
```toml
temp_secure_delete = true
temp_retention_hours = 24
temp_cleanup_interval_minutes = 15
```

---

## 10. Encryption in Transit

### 10.1 TLS Requirements

#### 10.1.1 REST API Communication

PDFSigner REST API requires TLS for all network communication:

**Minimum Requirements**:
- **Protocol Version**: TLS 1.2 (minimum), TLS 1.3 (preferred)
- **Cipher Suites**: FIPS 140-2 approved ciphers only in FIPS mode
- **Certificate Validation**: Full chain validation, hostname verification
- **Certificate Pinning**: Recommended for production deployments

**Prohibited**:
- TLS 1.0 / TLS 1.1 (deprecated)
- SSLv3 / SSLv2 (deprecated)
- NULL ciphers
- EXPORT-grade ciphers
- Anonymous ciphers

**Recommended Cipher Suites** (TLS 1.2):
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

**TLS 1.3 Cipher Suites** (preferred):
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

#### 10.1.2 Timestamp Authority (TSA) Communication

**Configuration**:
```toml
tsa_url = "https://tsa.example.com"  # HTTPS required
```

**Requirements**:
- TLS 1.2+ required
- Certificate validation enforced
- Timeout: 30 seconds (configurable)
- Retry logic: 3 attempts with exponential backoff

**Implementation**: `pyhanko.sign.timestamps.HTTPTimeStamper` with TLS verification.

#### 10.1.3 OCSP/CRL Retrieval

**Protocol**: HTTPS preferred for OCSP responders
- Fallback to HTTP permitted for CRL downloads (CRLs are signed, providing integrity)
- Timeout enforcement to prevent DoS attacks

**Configuration**:
```toml
ltv_ocsp_timeout = 10  # seconds
ltv_crl_timeout = 30   # seconds
```

### 10.2 Mutual TLS (mTLS)

#### 10.2.1 API Client Authentication

**Optional Configuration** for high-security deployments:

**Requirements**:
- Client certificate issued by trusted CA
- Certificate CN/SAN matches authenticated user
- Client private key protected by PKCS#11 token

**Use Cases**:
- Government deployments requiring CAC/PIV authentication
- Enterprise environments with certificate-based access control
- Zero-trust network architectures

**Implementation**: FastAPI middleware with SSL context configuration.

#### 10.2.2 HSM Network Communication

For network-attached HSMs:

**Protocol**: PKCS#11 over TLS (vendor-specific tunneling)
- SafeNet: SAC (Secure Authenticated Channel)
- Luna: NTLS (Network Trust Link)
- nCipher: nShield Connect with TLS

**Authentication**: Mutual TLS with HSM client certificate

---

## 11. Memory Security and Sensitive Data Handling

### 11.1 Memory Wiping Requirements

**Policy**: Sensitive data SHALL be cleared from memory immediately after use.

**Sensitive Data Types**:
- PKCS#11 PINs
- Encryption passwords
- Symmetric encryption keys
- Private key material (when in software)
- Decrypted PDF content

### 11.2 Secure Memory Handling Practices

#### 11.2.1 PIN/Password Handling

**Python Implementation**:
```python
# Use mutable bytearray for sensitive data
pin_bytes = bytearray(pin.encode('utf-8'))

try:
    # Use PIN for authentication
    session = token.open(user_pin=bytes(pin_bytes))
finally:
    # Zero-fill memory
    for i in range(len(pin_bytes)):
        pin_bytes[i] = 0
    del pin_bytes
```

**Best Practices**:
- Never log sensitive data
- Avoid string copies (use bytearray/memoryview)
- Clear immediately after use
- Disable Python bytecode generation for sensitive modules

#### 11.2.2 Cryptographic Key Material

**Hardware Keys** (PKCS#11):
- Private keys never leave hardware token
- Operations performed on-token
- No memory wiping necessary (keys never in software)

**Software Keys** (temporary):
- Use `memset()` via ctypes for C-level clearing
- Overwrite with random data before deletion
- Avoid Python garbage collection delays

#### 11.2.3 Document Content

**In-Memory Processing**:
- Process PDFs in memory when possible (< 100 MB)
- Avoid swapping to disk (use `mlock()` if supported)
- Clear buffers after signing/encryption

**Temporary Files**:
- Create in secure temporary directory (0700 permissions)
- Encrypt temporary file contents
- Secure deletion on close (3-pass overwrite when enabled)

### 11.3 Core Dumps and Crash Handling

**System Configuration**:
```bash
# Disable core dumps for PDFSigner processes
ulimit -c 0

# Or system-wide via sysctl
kernel.core_pattern = /dev/null
```

**Process Limits**:
```python
# Disable core dumps programmatically
import resource
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
```

**Implementation**: `src/pdfsigner/main.py` sets resource limits at startup.

### 11.4 Swap Space Security

**Recommendation**: Disable swap on systems processing highly sensitive data.

**Linux Encrypted Swap**:
```bash
# Enable encrypted swap
cryptsetup luksFormat /dev/sdX2
cryptsetup luksOpen /dev/sdX2 swap
mkswap /dev/mapper/swap
swapon /dev/mapper/swap
```

**Memory Locking**:
```python
# Lock sensitive pages in RAM (requires CAP_IPC_LOCK)
import mmap
mmap.mlock(buffer_address, buffer_size)
```

### 11.5 Python-Specific Considerations

**Garbage Collection Delays**:
- Python's garbage collector may delay memory deallocation
- Use `gc.collect()` to force collection after sensitive operations
- Consider CPython reference counting behavior

**String Immutability**:
- Python strings are immutable - copies may exist in memory
- Use `bytearray` or `bytes` for sensitive data
- Avoid string concatenation with sensitive data

**Code Decompilation**:
- Avoid storing secrets in source code (use environment variables)
- Use runtime encryption for embedded sensitive constants
- Consider code obfuscation for on-premises deployments

---

## 12. Compliance Mapping

### 12.1 HIPAA §164.312(a)(2)(iv) - Encryption and Decryption

**Regulation**: "Implement a mechanism to encrypt and decrypt electronic protected health information."

**PDFSigner Controls**:

| Control | Implementation | Evidence |
|---------|---------------|----------|
| PDF Encryption | AES-256 encryption for PHI-containing documents | `src/pdfsigner/core/encryption/pdf_encryptor.py` |
| HIPAA Mode | Enforces AES-256 + restrictive permissions | `encryption_hipaa_mode = true` |
| Credential Protection | Encrypted keyring storage for passwords | `src/pdfsigner/core/encryption/credential_store.py` |
| Audit Trail | Encrypted audit logs with HMAC integrity | `src/pdfsigner/core/audit/audit_integrity.py` |

**Configuration**:
```toml
healthcare_mode = true
encryption_hipaa_mode = true
encryption_default_strength = "aes256"
```

**Validation**: `tests/unit/test_encryption_config.py` validates HIPAA compliance.

### 12.2 HIPAA §164.312(b) - Audit Controls

**Regulation**: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."

**PDFSigner Controls**:

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Audit Logging | All cryptographic operations logged | `src/pdfsigner/core/audit/audit_logger.py` |
| Tamper Detection | HMAC-SHA-256 + chain hashing | `src/pdfsigner/core/audit/audit_integrity.py` |
| Retention | 90-day default retention (configurable) | `audit_retention_days = 90` |
| SIEM Export | CEF/LEEF/JSON export for analysis | `siem_enabled = true` |

**Audit Events**:
- Token authentication (`TOKEN_LOGIN`, `TOKEN_LOGOUT`)
- Document signing (`DOCUMENT_SIGNED`)
- Encryption operations (`DOCUMENT_ENCRYPTED`)
- Certificate operations (`CERTIFICATE_LOADED`)
- Emergency access (`EMERGENCY_ACCESS_GRANTED`)

### 12.3 NIST SP 800-53 SC-12 - Cryptographic Key Establishment

**Control**: "The organization establishes and manages cryptographic keys for required cryptography employed within the organization's information system."

**PDFSigner Controls**:

| NIST SC-12 Requirement | PDFSigner Implementation |
|-----------------------|-------------------------|
| (1) Key Generation | PKCS#11 HSM-based key generation (RSA-2048+) |
| (2) Key Distribution | Certificate-based distribution via NSS |
| (3) Key Storage | Hardware token storage (non-exportable keys) |
| (4) Key Revocation | OCSP/CRL-based revocation checking |
| (5) Key Rotation | Configurable rotation schedule (90-365 days) |
| (6) Key Backup | Certificate backup (public keys only) |
| (7) Key Recovery | Emergency access procedures for healthcare mode |
| (8) Key Destruction | Secure deletion with memory wiping |

**Configuration**:
```toml
key_default_expiry_days = 365
key_auto_rotate_days = 90
```

### 12.4 NIST SP 800-53 SC-13 - Cryptographic Protection

**Control**: "The information system implements FIPS-validated cryptography to protect the confidentiality and integrity of information."

**PDFSigner Controls**:

| NIST SC-13 Requirement | PDFSigner Implementation |
|-----------------------|-------------------------|
| FIPS 140-2 Algorithms | AES-128/256, SHA-256/384/512, RSA-2048/4096, ECDSA-P256/P384 |
| Algorithm Enforcement | `FIPSCryptoProvider` validates all operations |
| Strict Mode | Rejects non-FIPS algorithms in FIPS mode |
| OpenSSL FIPS Module | Detects and leverages system FIPS OpenSSL |

**Configuration**:
```toml
fips_mode_enabled = true
fips_strict_mode = true
```

**Validation**: `tests/unit/test_fips_provider.py` verifies FIPS enforcement.

### 12.5 eIDAS Regulation (EU) 910/2014

**Article 26 - Advanced Electronic Signatures**:
- **Requirement**: Uniquely linked to signatory, capable of identifying signatory, created using means under signatory's sole control
- **Implementation**: PKCS#11 hardware tokens with PIN protection

**Article 32 - Qualified Electronic Signatures**:
- **Requirement**: Created by qualified signature creation device (QSCD), based on qualified certificate
- **Implementation**: FIPS 140-2 Level 2+ tokens meet QSCD requirements

**Article 35-40 - Electronic Seals**:
- **Requirement**: Organizations can create electronic seals for authenticity/integrity
- **Implementation**: Seal mode with organizational certificates

**Configuration**:
```toml
seal_enabled = true
seal_default_type = "qualified"
eidas_enabled = true
eidas_enforce_qualified = true
```

### 12.6 ISO/IEC 27001:2022 - Cryptographic Controls

**Annex A.8.24 - Use of Cryptography**:

| ISO 27001 Requirement | PDFSigner Implementation |
|----------------------|-------------------------|
| Cryptographic policy | This document |
| Key management policy | Sections 5-7 of this document |
| Algorithm selection | Section 3 (approved algorithms) |
| Key lifecycle | Section 5 (generation to destruction) |
| Roles and responsibilities | Section 13 |

**Compliance Evidence**: This policy document serves as the cryptographic controls policy required by ISO 27001.

---

## 13. Roles and Responsibilities

### 13.1 Security Officer

**Responsibilities**:
- Approve and maintain this encryption policy
- Review policy annually or upon significant changes
- Approve exceptions to policy requirements
- Monitor compliance with cryptographic controls
- Coordinate incident response for key compromise events

**Authority**:
- Mandate FIPS mode for production systems
- Require emergency key rotation
- Disable non-compliant algorithms

### 13.2 System Administrators

**Responsibilities**:
- Deploy PDFSigner with compliant configuration
- Enable FIPS mode on systems requiring it
- Configure PKCS#11 token integration
- Maintain NSS database backups
- Monitor certificate expiration warnings
- Execute approved key rotation procedures

**Requirements**:
- Complete cryptographic operations training
- Understand PKCS#11 token management
- Maintain audit trail access

### 13.3 End Users

**Responsibilities**:
- Protect PKCS#11 token PINs
- Report lost or stolen tokens immediately
- Request certificate renewal before expiration
- Use strong passwords for PDF encryption
- Comply with organization encryption policies

**Prohibited Actions**:
- Sharing tokens or PINs with other users
- Exporting private keys from tokens
- Disabling encryption for convenience
- Using weak passwords for PDF encryption

### 13.4 Auditors

**Responsibilities**:
- Review compliance with this policy
- Verify FIPS mode configuration
- Validate key rotation adherence
- Examine audit logs for cryptographic operations
- Test certificate revocation procedures

**Audit Checklist**:
- [ ] FIPS mode enabled for sensitive systems
- [ ] Hardware tokens meet FIPS 140-2 requirements
- [ ] Certificate expiration monitoring active
- [ ] Key rotation schedule adhered to
- [ ] Audit logs protected with integrity controls
- [ ] Emergency procedures documented and tested

### 13.5 Development Team

**Responsibilities**:
- Implement cryptographic controls per this policy
- Maintain FIPS provider and validation logic
- Test algorithm enforcement
- Review third-party library security
- Respond to cryptographic vulnerabilities

**Code Review Requirements**:
- All cryptographic code changes require security review
- New algorithm additions require policy approval
- Cryptographic tests must cover FIPS enforcement

---

## 14. Exceptions and Waivers

### 14.1 Exception Process

**Request Procedure**:
1. Submit written exception request to Security Officer
2. Document business justification
3. Propose compensating controls
4. Specify exception duration (maximum 1 year)
5. Obtain approval from Security Officer and Compliance Officer

**Required Information**:
- System or deployment affected
- Specific policy requirement needing exception
- Business justification
- Risk assessment
- Compensating controls
- Expiration date

### 14.2 Approved Exceptions

#### 14.2.1 Development and Testing

**Exception**: FIPS mode may be disabled for development environments

**Justification**: Developers require flexibility to test non-FIPS algorithms and configurations

**Compensating Controls**:
- Development systems SHALL NOT process production data
- Development systems SHALL NOT contain PHI or sensitive data
- FIPS mode MUST be enabled in staging environments

**Configuration**:
```toml
# Development only
fips_mode_enabled = false
dry_run = true  # Simulate token operations
```

#### 14.2.2 Legacy System Integration

**Exception**: TLS 1.1 may be permitted for integration with legacy timestamp authorities

**Justification**: Some organizational internal TSAs do not support TLS 1.2

**Compensating Controls**:
- Restrict to internal network only (no Internet-facing TSAs)
- Require network segmentation
- Implement certificate pinning
- Annual review of TSA upgrade roadmap

**Expiration**: December 31, 2026 (mandatory TLS 1.2 after this date)

#### 14.2.3 SoftHSM for Pilot Deployments

**Exception**: SoftHSM (software token) may be used for proof-of-concept deployments

**Justification**: Organizations evaluating PDFSigner may not have hardware tokens available

**Compensating Controls**:
- Pilot duration maximum 90 days
- No sensitive or production data
- Require migration plan to hardware tokens
- Document as non-compliant deployment

**Restrictions**:
- Not permitted for HIPAA-regulated data
- Not permitted for federal government use
- Not permitted for production environments

### 14.3 Exception Review

**Review Frequency**: All exceptions reviewed quarterly

**Automatic Expiration**: Exceptions expire after 1 year unless renewed

**Revocation**: Security Officer may revoke exceptions if risk increases

---

## 15. Policy Enforcement

### 15.1 Technical Controls

**Enforcement Mechanisms**:

| Control | Enforcement Method | Bypass Possible? |
|---------|-------------------|------------------|
| FIPS Algorithm Restrictions | `FIPSCryptoProvider` validation | No (strict mode) |
| Minimum Key Lengths | PKCS#11 token constraints | No (hardware enforced) |
| Certificate Validation | Pre-signing validation checks | No |
| TLS Requirements | Python `ssl` module configuration | No |
| Audit Logging | Mandatory (cannot disable) | No |

**Configuration Validation**:
```bash
# Validate FIPS compliance
uv run pdfsigner --check-fips

# Validate configuration
uv run pdfsigner --validate-config
```

### 15.2 Operational Controls

**Periodic Reviews**:
- **Monthly**: Certificate expiration monitoring
- **Quarterly**: Exception review, key rotation status
- **Annual**: Full policy review, algorithm assessment

**Compliance Reporting**:
```bash
# Generate compliance report
uv run pdfsigner compliance-report --output report.pdf

# Audit log integrity verification
uv run pdfsigner verify-audit-integrity
```

### 15.3 Consequences of Non-Compliance

**For System Administrators**:
- Warning for first minor violation (documentation, configuration)
- Remediation required within 30 days
- Escalation to Security Officer for repeat violations
- Access revocation for willful violations

**For End Users**:
- Training required for inadvertent violations
- Account suspension for policy violations (e.g., sharing tokens)
- Termination for willful violations (e.g., exporting private keys)

**For Systems**:
- Non-compliant systems SHALL NOT process sensitive data
- Production systems non-compliant for >90 days SHALL be decommissioned
- Emergency access disabled for non-compliant deployments

### 15.4 Incident Response

**Key Compromise Procedure**:
1. **Immediate**: Disable affected user account/certificate binding
2. **Within 1 hour**: Initiate certificate revocation with CA
3. **Within 4 hours**: Issue new certificate to affected user
4. **Within 24 hours**: Complete incident report
5. **Within 7 days**: Notify affected parties (if required by regulation)

**Incident Categories**:
- **P0 (Critical)**: Private key compromise, HSM theft - 1 hour response
- **P1 (High)**: Certificate misuse, unauthorized access - 4 hour response
- **P2 (Medium)**: Policy violation, weak algorithm use - 24 hour response
- **P3 (Low)**: Configuration drift, documentation issue - 7 day response

---

## 16. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-01 | Security Team | Initial policy creation based on PDFSigner v1.1 capabilities |

---

## Appendix A: Configuration Examples

### A.1 HIPAA-Compliant Configuration

```toml
# ~/.config/pdfsigner/config.toml

# FIPS Compliance
fips_mode_enabled = true
fips_strict_mode = true

# Healthcare Mode
healthcare_mode = true
healthcare_session_timeout_minutes = 15
healthcare_max_sessions = 3
healthcare_emergency_duration_hours = 4
healthcare_emergency_require_approval = true

# Encryption
encryption_default_strength = "aes256"
encryption_hipaa_mode = true
encryption_default_allow_print = false
encryption_default_allow_copy = false
encryption_store_in_keyring = true

# Audit
audit_enabled = true
audit_retention_days = 2555  # 7 years for HIPAA

# Security
temp_secure_delete = true
revocation_check_enabled = true
ltv_enabled = true

# Key Management
key_default_expiry_days = 365
key_auto_rotate_days = 90
```

### A.2 Federal Government Configuration

```toml
# FIPS 140-2 Strict Mode
fips_mode_enabled = true
fips_strict_mode = true

# NIST SP 800-53 Controls
password_min_length = 15
password_max_age_days = 60
password_history_count = 24
password_lockout_threshold = 3

# Audit (NIST AU-2)
audit_enabled = true
audit_retention_days = 365  # 1 year minimum
siem_enabled = true
siem_format = "cef"

# Key Management (NIST SC-12)
key_default_expiry_days = 365
key_auto_rotate_days = 90

# Revocation (NIST SC-17)
revocation_check_enabled = true
revocation_prefer_ocsp = true
```

### A.3 eIDAS-Compliant Configuration (EU)

```toml
# eIDAS Qualified Signatures
eidas_enabled = true
eidas_enforce_qualified = true
eidas_auto_update = true

# Electronic Seals
seal_enabled = true
seal_default_type = "qualified"
seal_include_timestamp = true

# Long-Term Validation
ltv_enabled = true
archive_ts_enabled = true
archive_ts_auto = true

# GDPR Compliance
gdpr_enabled = true
gdpr_retention_days = 730  # 2 years
gdpr_anonymize_audit_logs = true
```

---

## Appendix B: Supported PKCS#11 Tokens

| Vendor | Product | FIPS 140-2 | Recommended Use |
|--------|---------|-----------|----------------|
| SafeNet | eToken 5110 | Level 2 | General purpose |
| Yubico | YubiKey 5 FIPS | Level 2 | Multi-factor auth + signing |
| Nitrokey | Nitrokey HSM 2 | Level 2 | Open-source HSM |
| Thales | Luna SA | Level 3 | Enterprise, high-volume |
| Entrust | nShield Connect | Level 3 | Government, healthcare |
| Feitian | ePass2003 | Level 2 | Cost-effective option |
| OpenSC | Smart cards | Varies | Generic smart card support |
| SoftHSM | SoftHSM 2 | None | **Development ONLY** |

**Configuration**: See `src/pdfsigner/core/token/pkcs11_libs.py` for library paths.

---

## Appendix C: Cryptographic Algorithm Lifecycle

| Algorithm | Status | Deprecated | Prohibited | Notes |
|-----------|--------|-----------|-----------|-------|
| SHA-256 | **Active** | - | - | Recommended for all uses |
| SHA-384 | Active | - | - | High-security applications |
| SHA-512 | Active | - | - | High-security applications |
| SHA-1 | Deprecated | 2020 | 2030 | Validation of legacy signatures only |
| MD5 | **Prohibited** | 2010 | 2012 | Never use |
| AES-256 | **Active** | - | - | HIPAA required |
| AES-128 | Active | - | - | General use acceptable |
| 3DES | **Prohibited** | 2016 | 2023 | Never use |
| RSA-4096 | Active | - | - | Preferred for new deployments |
| RSA-2048 | Active | 2030 | 2035 | Minimum acceptable |
| RSA-1024 | **Prohibited** | 2010 | 2013 | Never use |
| ECDSA-P384 | Active | - | - | Preferred elliptic curve |
| ECDSA-P256 | Active | - | - | Minimum elliptic curve |

**Policy**: Deprecated algorithms may only be used for validating existing signatures, not creating new ones.

---

## Appendix D: References

### D.1 Standards and Regulations

- **FIPS 140-2**: Security Requirements for Cryptographic Modules
- **NIST SP 800-53 Rev. 5**: Security and Privacy Controls for Information Systems
- **NIST SP 800-57**: Recommendation for Key Management
- **HIPAA Security Rule**: 45 CFR §164.312 - Technical Safeguards
- **eIDAS Regulation**: (EU) No 910/2014 - Electronic Identification and Trust Services
- **ISO/IEC 27001:2022**: Information Security Management Systems
- **PKCS#11 v2.40**: Cryptographic Token Interface Standard

### D.2 PDFSigner Documentation

- **Main Documentation**: `/home/user/projects/pdfsigner/README.md`
- **CLAUDE.md**: `/home/user/projects/pdfsigner/CLAUDE.md`
- **Security Policy**: `/home/user/projects/pdfsigner/docs/security/SSP.md`
- **Access Control Policy**: `/home/user/projects/pdfsigner/docs/security/access-control-policy.md`
- **Audit Policy**: `/home/user/projects/pdfsigner/docs/security/audit-policy.md`

### D.3 Implementation Files

- **FIPS Provider**: `src/pdfsigner/core/crypto/fips_provider.py`
- **Encryption Module**: `src/pdfsigner/core/encryption/`
- **PKCS#11 Handler**: `src/pdfsigner/core/token/nss_handler.py`
- **Audit Integrity**: `src/pdfsigner/core/audit/audit_integrity.py`
- **Settings**: `src/pdfsigner/config/settings.py`

---

## Contact Information

**Policy Owner**: Security Operations Team
**Security Officer**: [Contact via organization security portal]
**Compliance Officer**: [Contact via organization compliance portal]

**For Technical Questions**: Consult PDFSigner documentation or development team
**For Policy Exceptions**: Submit request to Security Officer
**For Incident Reporting**: Use organization incident response procedures

---

**Document Classification**: Internal Use
**Distribution**: Approved personnel only
**Review Date**: 2027-02-01


# PDFSigner System Security Plan (SSP)

## Document Control

| Field | Value |
|-------|-------|
| **Version** | 1.0 |
| **Classification** | Internal |
| **Last Updated** | 2026-02-01 |
| **Next Review** | 2026-08-01 |
| **Owner** | Security Team |
| **Approver** | [Organization CISO] |
| **Status** | Draft |

---

## 1. System Identification

### 1.1 System Name
**PDFSigner - Digital PDF Signing Solution for Linux/GNOME**

### 1.2 System Abbreviation
**PDFS**

### 1.3 System Description

PDFSigner is a comprehensive digital signature solution designed for Linux/GNOME environments that provides legally-binding electronic signatures compliant with international standards including eIDAS, HIPAA, GDPR, and 21 CFR Part 11. The system supports hardware security modules (HSMs) via PKCS#11, implements PAdES B-LTA signatures with long-term validation, and provides enterprise-grade security controls including encryption, audit logging, and role-based access control.

**Core Capabilities:**
- Digital signature creation and validation (PAdES B-LTA)
- Hardware token authentication (PKCS#11: SafeNet, YubiKey, etc.)
- PDF encryption (AES-256) with HIPAA compliance mode
- Tamper-evident audit trail with HMAC integrity
- REST API for enterprise integration
- Batch processing and automated workflows
- Long-term signature validation with archive timestamps
- Certificate chain validation with OCSP/CRL checking

### 1.4 System Owner
**[Organization Name]**
**[Department]**
**[Contact Information]**

### 1.5 System Categorization
**Security Categorization (FIPS 199):** MODERATE

**Rationale:** Based on the highest impact level across confidentiality, integrity, and availability for the information types processed by the system.

### 1.6 Authorization Boundary

**In Scope:**
- PDFSigner GUI application (GTK4/libadwaita)
- PDFSigner CLI tool
- PDFSigner REST API server (FastAPI)
- Core signing engine (pyHanko)
- Encryption module (AES-256)
- Audit logging system
- User registry and authentication
- Session management
- Configuration storage

**Out of Scope:**
- Operating system (Linux)
- Hardware tokens/HSMs (managed separately)
- External Timestamp Authorities (TSAs)
- OCSP/CRL servers
- User workstations
- Network infrastructure

---

## 2. Security Categorization (FIPS 199)

### 2.1 Information Types Processed

| Information Type | Confidentiality | Integrity | Availability | Rationale |
|-----------------|----------------|-----------|--------------|-----------|
| **Digital Signatures** | Moderate | High | Moderate | Signatures authenticate documents; integrity breach could lead to fraud |
| **Audit Logs** | Low | High | Moderate | Logs required for compliance; tampering would hide malicious activity |
| **User Credentials** | High | High | Moderate | Compromise could allow unauthorized access to signing capabilities |
| **PHI/PII Data** | High | High | Moderate | Healthcare documents contain sensitive personal information |
| **Encryption Keys** | High | High | Moderate | Key compromise would expose all encrypted documents |
| **System Configuration** | Moderate | High | Low | Configuration tampering could weaken security controls |

### 2.2 Overall Impact Assessment

**Confidentiality:** HIGH
- System processes PHI/PII and user credentials
- Unauthorized disclosure could result in privacy violations (HIPAA, GDPR)
- Financial impact: $50,000 - $500,000 per breach

**Integrity:** HIGH
- Digital signature tampering could result in fraud or legal disputes
- Audit log manipulation would hide compliance violations
- Regulatory impact: Loss of certification, legal penalties

**Availability:** MODERATE
- Service disruption affects business operations but not critical systems
- Workarounds available (manual signing processes)
- Recovery time objective: 24 hours

### 2.3 System Categorization
**FIPS 199 Security Category:** **(HIGH, HIGH, MODERATE) = MODERATE**

Per FIPS 199 guidance, the overall system categorization is MODERATE based on the highest impact level for each security objective. This aligns with NIST 800-53 Moderate Baseline controls.

---

## 3. System Environment

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         End User Layer                           │
├───────────────┬─────────────────┬──────────────────┬────────────┤
│   GUI Client  │   CLI Client    │   REST API       │  Mobile    │
│   (GTK4)      │   (argparse)    │   Clients        │  (Future)  │
└───────┬───────┴─────────┬───────┴────────┬─────────┴────────────┘
        │                 │                │
        └─────────────────┴────────────────┘
                          │
        ┌─────────────────┴─────────────────────────────┐
        │          Application Layer                     │
        ├────────────────────────────────────────────────┤
        │  • Signing Handler                             │
        │  • Batch Manager                               │
        │  • Encryption Manager                          │
        │  • RBAC Authorization                          │
        │  • Session Manager                             │
        └───────┬────────────────────────────────────────┘
                │
        ┌───────┴────────────────────────────────────────┐
        │          Core Services Layer                    │
        ├─────────────────────────────────────────────────┤
        │  • PDF Signer (pyHanko)                         │
        │  • Token Handler (PKCS#11)                      │
        │  • Validator (PAdES/eIDAS)                      │
        │  • DSS Manager (LTV)                            │
        │  • Archive TS Manager                           │
        │  • Encryption (AES-256)                         │
        └───────┬─────────────────────────────────────────┘
                │
        ┌───────┴────────────────────────────────────────┐
        │          Data Layer                             │
        ├─────────────────────────────────────────────────┤
        │  • User Registry (SQLite)                       │
        │  • Audit Trail (JSONL)                          │
        │  • Session Store (SQLite)                       │
        │  • Configuration (TOML)                         │
        │  • Certificate Cache                            │
        └───────┬─────────────────────────────────────────┘
                │
        ┌───────┴────────────────────────────────────────┐
        │          External Integrations                  │
        ├─────────────────────────────────────────────────┤
        │  • TSA Servers (RFC 3161)                       │
        │  • OCSP Responders                              │
        │  • CRL Distribution Points                      │
        │  • EU Trusted List (eIDAS)                      │
        │  • Hardware Tokens (PKCS#11)                    │
        │  • SIEM Systems (Syslog/CEF)                    │
        └─────────────────────────────────────────────────┘
```

### 3.2 Network Topology

**Deployment Scenarios:**

1. **Local Deployment (GUI/CLI)**
   - No network exposure
   - Operates on localhost only
   - USB token direct connection

2. **API Server Deployment**
   - Listens on configurable port (default: 8000)
   - TLS 1.2+ required for production
   - Optional mTLS for client authentication
   - Reverse proxy recommended (nginx/HAProxy)

3. **External Connections**
   - TSA servers: HTTPS (port 443)
   - OCSP responders: HTTP/HTTPS (ports 80/443)
   - CRL endpoints: HTTP/HTTPS (ports 80/443)
   - SIEM systems: Syslog (UDP/TCP 514, TLS 6514)

### 3.3 Data Flow

**Signature Creation Flow:**
```
1. User → GUI/CLI/API → Document Upload
2. System → PHI Detection → Encryption Policy Check
3. System → PKCS#11 Token → PIN Authentication
4. System → PDF Preparation → Signature Field Creation
5. System → pyHanko → Digital Signature Creation
6. System → TSA → RFC 3161 Timestamp Request
7. System → DSS Manager → LTV Embedding (OCSP/CRL)
8. System → Archive TS → PAdES B-LTA Completion
9. System → Audit Logger → Event Recording
10. System → User → Signed Document Delivery
```

**Audit Trail Flow:**
```
1. Any System Event → Audit Logger
2. Audit Logger → Chain Hash Calculation (previous record hash)
3. Audit Logger → HMAC Signature Generation (HMAC-SHA256)
4. Audit Logger → Append to JSONL File (append-only)
5. Audit Logger → SIEM Export (optional, real-time)
6. Periodic → Audit Integrity Verification
```

### 3.4 Data Storage

| Data Type | Location | Protection | Retention |
|-----------|----------|------------|-----------|
| Configuration | `~/.config/pdfsigner/config.toml` | File permissions (600) | Indefinite |
| User Database | `~/.local/share/pdfsigner/users.db` | SQLite encryption, file permissions (600) | Until user deletion |
| Audit Logs | `~/.local/share/pdfsigner/audit.jsonl` | HMAC chain, append-only, permissions (600) | 6 years (HIPAA) |
| Session Data | `~/.local/share/pdfsigner/sessions.db` | AES-256-GCM encrypted, permissions (600) | Session expiration |
| Temp Files | `/tmp/pdfsigner/` | Secure deletion (DoD 5220.22-M), 24h retention | 24 hours |
| Credentials | System keyring (libsecret) | OS-managed encryption | Until revoked |

---

## 4. Control Implementation Statements

### 4.1 Access Control (AC) Family

#### AC-1: Access Control Policy and Procedures
**Implementation Status:** IMPLEMENTED

**Description:** PDFSigner implements comprehensive access control through a 5-role, 10-permission RBAC system. Access control policies are documented in `docs/security/access-control-policy.md`.

**Evidence:**
- `src/pdfsigner/core/rbac/permissions.py` - Permission definitions
- `src/pdfsigner/core/rbac/authorization.py` - Authorization service
- `src/pdfsigner/api/middleware/rbac.py` - API enforcement
- Role assignment audit logs

#### AC-2: Account Management
**Implementation Status:** IMPLEMENTED

**Description:** User accounts are managed through the User Registry with unique identifiers bound to X.509 certificates. All account lifecycle events are logged to the audit trail.

**Implementation:**
- Unique user IDs generated on first certificate use
- Email-based username with certificate binding
- Automatic account creation via `CertificateBindingService`
- Account deactivation (soft delete) preserves audit history
- Role assignment requires ADMIN permission
- Department-based access segregation

**Evidence:**
- `src/pdfsigner/core/users/user_model.py` - User data model
- `src/pdfsigner/core/users/user_repository.py` - CRUD operations
- `src/pdfsigner/core/users/cert_binding.py` - Certificate binding
- Audit logs: `USER_CREATED`, `USER_DEACTIVATED`, `ROLE_ASSIGNED`

#### AC-3: Access Enforcement
**Implementation Status:** IMPLEMENTED

**Description:** Every API endpoint and GUI operation enforces permission-based access control through middleware and decorators.

**Implementation:**
- API: RBACMiddleware validates JWT claims against required permissions
- GUI: Permission checks in event handlers disable unauthorized operations
- Permission denied events logged with user ID and attempted action

**Evidence:**
- `src/pdfsigner/api/middleware/auth.py` - JWT validation
- `src/pdfsigner/core/rbac/authorization.py` - `has_permission()` checks
- Test suite: `tests/unit/test_rbac.py` (65+ tests)

#### AC-7: Unsuccessful Logon Attempts
**Implementation Status:** IMPLEMENTED

**Description:** Failed authentication attempts are tracked per user with configurable lockout thresholds.

**Implementation:**
- Default: 5 failed attempts → 30-minute account lockout
- Failed attempts logged with timestamp and source IP
- Lockout countdown timer
- Admin can manually unlock accounts

**Evidence:**
- `src/pdfsigner/core/auth/` - Authentication tracking
- Audit events: `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`
- Configuration: `password_lockout_attempts`, `password_lockout_duration_minutes`

#### AC-11: Session Lock / AC-12: Session Termination
**Implementation Status:** IMPLEMENTED

**Description:** Sessions automatically terminate after configurable inactivity period with warning dialog.

**Implementation:**
- GUI: Activity monitor tracks keyboard/mouse events
- Default timeout: 15 minutes (configurable 5-60 minutes)
- Warning displayed 2 minutes before logout
- API: JWT token expiration with sliding session support
- Maximum concurrent sessions per user: 3 (configurable)

**Evidence:**
- `src/pdfsigner/gui/session/activity_monitor.py` - Inactivity detection
- `src/pdfsigner/core/session/session_manager.py` - Session lifecycle
- Audit events: `SESSION_TIMEOUT`, `SESSION_TERMINATED`
- Configuration: `healthcare_session_timeout_minutes`

#### AC-17: Remote Access
**Implementation Status:** IMPLEMENTED

**Description:** API remote access protected by TLS 1.2+ with optional mutual TLS for client authentication.

**Implementation:**
- TLS 1.2 minimum, TLS 1.3 recommended
- Certificate-based authentication (mTLS)
- Strong cipher suites only (no RC4, DES, 3DES)
- Perfect forward secrecy (ECDHE)
- HTTP to HTTPS redirect

**Evidence:**
- `src/pdfsigner/api/middleware/tls.py` - TLS enforcement
- Configuration: `tls_enabled`, `tls_min_version`, `tls_require_client_cert`
- Certificate validation with full chain verification

### 4.2 Audit and Accountability (AU) Family

#### AU-2: Audit Events
**Implementation Status:** IMPLEMENTED

**Description:** Comprehensive audit logging covers all security-relevant events across authentication, document operations, access control, and system changes.

**Audited Events:**
- Authentication: `LOGIN`, `LOGOUT`, `LOGIN_FAILED`, `TOKEN_EXPIRED`
- Document Operations: `SIGN`, `VALIDATE`, `ENCRYPT`, `DECRYPT`, `DOCUMENT_VIEW`
- Access Control: `PERMISSION_DENIED`, `ROLE_ASSIGNED`, `USER_CREATED`
- Emergency Access: `EMERGENCY_REQUEST`, `EMERGENCY_APPROVED`, `EMERGENCY_DENIED`
- System: `CONFIG_CHANGE`, `BACKUP_CREATED`, `BACKUP_RESTORED`
- Session: `SESSION_START`, `SESSION_END`, `SESSION_TIMEOUT`

**Evidence:**
- `src/pdfsigner/core/audit/audit_event.py` - Event type definitions
- `src/pdfsigner/core/audit/audit_logger.py` - Logging implementation
- Audit log file: `~/.local/share/pdfsigner/audit.jsonl`

#### AU-3: Content of Audit Records
**Implementation Status:** IMPLEMENTED

**Description:** Each audit record contains comprehensive information for forensic analysis and compliance reporting.

**Record Structure:**
```json
{
  "timestamp": "2026-02-01T10:30:15.123456Z",
  "event_type": "SIGN",
  "user_id": "user@example.com",
  "resource": "/path/to/document.pdf",
  "action": "sign_document",
  "status": "success",
  "details": {
    "certificate": "CN=John Doe,O=Example Corp",
    "algorithm": "RSA-2048",
    "pades_level": "B-LTA"
  },
  "ip_address": "192.168.1.100",
  "session_id": "abc123def456",
  "record_hash": "sha256:...",
  "previous_hash": "sha256:...",
  "hmac_signature": "hmac-sha256:..."
}
```

#### AU-6: Audit Review, Analysis, and Reporting
**Implementation Status:** IMPLEMENTED

**Description:** Audit logs are searchable, exportable, and integrated with SIEM systems for real-time analysis.

**Implementation:**
- Query by user, event type, date range, session, PHI access
- Export formats: JSON, CSV, PDF, CEF, LEEF
- SIEM forwarding: Syslog (UDP/TCP/TLS)
- Compliance reports: HIPAA, GDPR, SOC 2
- Anomaly detection for unusual access patterns

**Evidence:**
- `src/pdfsigner/core/audit/audit_query.py` - Search and filter
- `src/pdfsigner/core/reports/hipaa_report.py` - Compliance reporting
- `src/pdfsigner/core/audit/siem_exporter.py` - SIEM integration
- API endpoints: `/api/v1/audit/`, `/api/v1/compliance/status`

#### AU-9: Protection of Audit Information
**Implementation Status:** IMPLEMENTED

**Description:** Audit logs are protected against tampering through cryptographic chain hashing and HMAC signatures.

**Implementation:**
- SHA-256 chain hashing: Each record includes hash of previous record
- HMAC-SHA256 signatures: Each record signed with secret key
- Append-only file with file-level locking
- File permissions: 600 (owner read/write only)
- Integrity verification detects: deletions, modifications, insertions, reordering

**Evidence:**
- `src/pdfsigner/core/audit/audit_integrity.py` - Integrity manager
- `verify_chain()` function validates entire log
- Audit reports include integrity verification status
- Tests: `tests/unit/test_audit_integrity.py` (20+ tests)

#### AU-10: Non-Repudiation
**Implementation Status:** IMPLEMENTED

**Description:** Digital signatures provide non-repudiation through PAdES B-LTA with qualified timestamps and long-term validation.

**Implementation:**
- PAdES B-LTA signatures include:
  - Signer certificate embedded in signature
  - RFC 3161 qualified timestamp
  - OCSP/CRL validation data (DSS)
  - Archive timestamp for long-term validity
- Audit trail includes certificate serial number
- Signature validation verifies complete chain

**Evidence:**
- `src/pdfsigner/core/signer/pdf_signer.py` - PAdES implementation
- `src/pdfsigner/core/signer/dss_manager.py` - LTV embedding
- `src/pdfsigner/core/signer/archive_ts_manager.py` - Archive timestamps
- `src/pdfsigner/core/validator/pdf_validator.py` - Signature validation

### 4.3 Identification and Authentication (IA) Family

#### IA-2: Identification and Authentication (Organizational Users)
**Implementation Status:** IMPLEMENTED

**Description:** Users authenticate via PKCS#11 hardware tokens with PIN protection or API keys/JWT tokens.

**Implementation:**
- GUI/CLI: PKCS#11 hardware tokens (SafeNet, YubiKey, etc.)
- API: JWT bearer tokens (30-minute expiration) or API keys
- Hardware-enforced PIN retry limits (typically 3 attempts)
- Certificate-based user binding
- Optional MFA (TOTP) for API access

**Evidence:**
- `src/pdfsigner/core/token/nss_handler.py` - PKCS#11 integration
- `src/pdfsigner/api/middleware/auth.py` - JWT validation
- `src/pdfsigner/core/users/cert_binding.py` - Certificate binding
- PIN dialog: `src/pdfsigner/gui/dialogs/pin_dialog.py`

#### IA-5: Authenticator Management
**Implementation Status:** IMPLEMENTED

**Description:** Passwords hashed with Argon2id; certificates validated against trusted CAs; API keys cryptographically random.

**Implementation:**
- Password hashing: Argon2id (time=4, memory=64MB, parallelism=4)
- Certificate validation: Full chain verification with OCSP/CRL
- API key generation: 32 bytes cryptographically random (hex-encoded)
- Key storage: System keyring (libsecret) with OS-managed encryption
- Password policy: 12+ characters, complexity requirements

**Evidence:**
- `src/pdfsigner/core/auth/password_handler.py` - Argon2id implementation
- `src/pdfsigner/core/token/cert_validator.py` - Certificate validation
- `src/pdfsigner/core/encryption/credential_store.py` - Key storage
- Configuration: `password_min_length`, `password_require_*`

#### IA-8: Identification and Authentication (Non-Organizational Users)
**Implementation Status:** PARTIAL

**Description:** External API clients authenticate via API keys or mTLS certificates.

**Implementation:**
- API keys with configurable expiration
- mTLS client certificates with CA validation
- Rate limiting per client (60 requests/minute)
- Client identification in audit logs

**Evidence:**
- `src/pdfsigner/api/middleware/auth.py` - API key validation
- `src/pdfsigner/api/middleware/tls.py` - mTLS support
- Configuration: `tls_require_client_cert`, `tls_ca_cert_path`

**Gap:** OAuth 2.0 / SAML integration not yet implemented (planned for future release).

### 4.4 System and Communications Protection (SC) Family

#### SC-8: Transmission Confidentiality and Integrity
**Implementation Status:** IMPLEMENTED

**Description:** All network communications protected by TLS 1.2+ with strong cipher suites.

**Implementation:**
- TLS 1.2 minimum, TLS 1.3 recommended
- Cipher suites: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384
- Perfect forward secrecy (ECDHE)
- Certificate validation with CRL/OCSP checking
- HTTP to HTTPS redirect

**Evidence:**
- `src/pdfsigner/api/middleware/tls.py` - TLS enforcement
- TSA connections: `HTTPTimeStamper` validates server certificates
- Configuration: `tls_enabled`, `tls_min_version`, `tls_cert_path`

#### SC-12: Cryptographic Key Establishment and Management
**Implementation Status:** IMPLEMENTED

**Description:** Centralized key management with support for software storage and HSM integration.

**Implementation:**
- Key generation: FIPS 140-2 approved algorithms (AES-256, RSA-2048+)
- Key storage: Encrypted SQLite (software) or PKCS#11 HSM
- Key rotation: Automated with configurable schedule
- Key destruction: Secure memory wiping (DoD 5220.22-M)
- Key backup: AES-256 encrypted backup files

**Evidence:**
- `src/pdfsigner/core/crypto/key_manager.py` - Key lifecycle management
- `src/pdfsigner/core/crypto/fips_provider.py` - FIPS mode enforcement
- `src/pdfsigner/core/encryption/credential_store.py` - Key storage

#### SC-13: Cryptographic Protection
**Implementation Status:** IMPLEMENTED

**Description:** All cryptographic operations use FIPS 140-2 validated algorithms when FIPS mode enabled.

**Approved Algorithms:**
- Encryption: AES-128, AES-256 (CBC, GCM modes)
- Hashing: SHA-256, SHA-384, SHA-512
- Signatures: RSA-2048+, ECDSA P-256/P-384
- Message Authentication: HMAC-SHA-256
- Key Derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)
- Password Hashing: Argon2id

**Evidence:**
- `src/pdfsigner/core/crypto/fips_provider.py` - FIPS enforcement
- `src/pdfsigner/core/encryption/password_handler.py` - PDF encryption
- Configuration: `fips_mode_enabled`

#### SC-28: Protection of Information at Rest
**Implementation Status:** IMPLEMENTED

**Description:** Sensitive data encrypted at rest using AES-256.

**Implementation:**
- PDF encryption: AES-256-CBC with PBKDF2 key derivation
- Database encryption: SQLite encrypted tables (session data)
- Configuration: File permissions (600)
- Keyring: OS-managed encryption (libsecret)
- Temp files: Secure deletion (DoD 5220.22-M)

**Evidence:**
- `src/pdfsigner/core/encryption/pdf_encryptor.py` - PDF encryption
- `src/pdfsigner/core/session/session_manager.py` - Encrypted sessions
- `src/pdfsigner/core/security/secure_temp.py` - Secure deletion

### 4.5 System and Information Integrity (SI) Family

#### SI-7: Software, Firmware, and Information Integrity
**Implementation Status:** IMPLEMENTED

**Description:** Digital signatures provide software integrity; audit logs protected by HMAC chain.

**Implementation:**
- PAdES signatures validate document integrity
- Audit log chain hashing detects tampering
- Configuration file checksums
- Code signing for releases (planned)

**Evidence:**
- `src/pdfsigner/core/validator/pdf_validator.py` - Signature validation
- `src/pdfsigner/core/audit/audit_integrity.py` - Audit integrity
- Release signatures: `pdfsigner-*.tar.gz.sig`

#### SI-10: Information Input Validation
**Implementation Status:** IMPLEMENTED

**Description:** All user inputs validated and sanitized to prevent injection attacks.

**Implementation:**
- Path traversal prevention: Path sanitization module
- SQL injection: Parameterized queries only
- Command injection: No shell=True in subprocess calls
- File type validation: Magic number checking
- Input length limits enforced

**Evidence:**
- `src/pdfsigner/core/security/path_sanitizer.py` - Path validation
- `src/pdfsigner/core/users/user_repository.py` - Parameterized SQL
- Test suite: `tests/unit/test_security_*.py`

---

## 5. Roles and Responsibilities

### 5.1 System Roles

| Role | Responsibilities | Required Permissions |
|------|-----------------|---------------------|
| **System Administrator** | - Install and configure PDFSigner<br>- Manage user accounts and roles<br>- Configure security settings<br>- Monitor system health<br>- Perform backups and recovery | ADMIN_USERS, ADMIN_CONFIG, EXPORT |
| **Security Officer** | - Review audit logs<br>- Investigate security incidents<br>- Approve emergency access requests<br>- Conduct compliance reviews<br>- Generate security reports | AUDIT_VIEW, EXPORT, VALIDATE |
| **End User (Signer)** | - Sign PDF documents<br>- Validate signatures<br>- Encrypt/decrypt documents<br>- View own audit history | VIEW, SIGN, VALIDATE, ENCRYPT, DECRYPT |
| **Auditor** | - Review audit logs (read-only)<br>- Generate compliance reports<br>- Verify signature validity<br>- Export audit data | VIEW, VALIDATE, AUDIT_VIEW, EXPORT |
| **Viewer** | - View documents<br>- Validate signatures (read-only) | VIEW, VALIDATE |
| **Emergency Access** | - Break-glass access for critical situations<br>- Time-limited elevated permissions<br>- Fully audited actions | EMERGENCY_ACCESS (temporary) |

### 5.2 Personnel Responsibilities

#### System Administrator
- Maintain security patches and updates
- Review and approve configuration changes
- Monitor audit logs for anomalies
- Manage user provisioning/deprovisioning
- Coordinate incident response
- Perform quarterly access reviews

#### Security Officer
- Define and enforce security policies
- Conduct monthly audit log reviews
- Investigate suspicious activities
- Approve emergency access requests
- Report security incidents to management
- Coordinate third-party security assessments

#### End Users
- Protect hardware tokens and PINs
- Report lost/stolen tokens immediately
- Follow acceptable use policies
- Report security incidents promptly
- Attend annual security training

#### Auditors
- Conduct compliance audits
- Review access controls and logs
- Verify control effectiveness
- Report findings to management
- Maintain audit independence

---

## 6. System Interconnections

### 6.1 External System Connections

| External System | Purpose | Data Exchanged | Security Controls | Ports/Protocols |
|----------------|---------|----------------|-------------------|-----------------|
| **Timestamp Authorities (TSAs)** | RFC 3161 timestamps | Timestamp requests/responses | TLS 1.2+, server certificate validation | 443/HTTPS |
| **OCSP Responders** | Certificate revocation checking | OCSP requests/responses | TLS 1.2+ (if HTTPS), certificate validation | 80/HTTP, 443/HTTPS |
| **CRL Distribution Points** | Certificate revocation lists | CRL downloads | TLS 1.2+ (if HTTPS), checksum verification | 80/HTTP, 443/HTTPS |
| **EU Trusted List** | eIDAS TSP validation | TSP registry data | HTTPS, XML signature verification | 443/HTTPS |
| **SIEM Systems** | Audit log forwarding | Audit events (CEF/LEEF) | TLS (syslog), authentication | 514/UDP, 6514/TLS |
| **Hardware Tokens (HSM)** | Cryptographic operations | Signature operations, key access | PKCS#11 API, PIN protection | USB/direct |
| **Keyring Service** | Credential storage | Encrypted credentials | OS-managed encryption (libsecret) | D-Bus/local |

### 6.2 Interconnection Security Agreements (ISAs)

**TSA Providers:**
- Agreement required for production use
- SLA: 99.9% availability
- Response time: < 5 seconds
- Certificate: Qualified Trust Service Provider (eIDAS)

**SIEM Integration:**
- Data classification: Internal
- Encryption: TLS 1.2+
- Authentication: API key or mTLS
- Retention: Per SIEM policy

---

## 7. Laws and Regulations

### 7.1 Applicable Regulations

| Regulation | Applicability | Compliance Status | Reference Controls |
|-----------|--------------|-------------------|-------------------|
| **HIPAA** (45 CFR Part 164) | Healthcare environments | Implemented | §164.312 (Technical Safeguards) |
| **GDPR** (EU 2016/679) | EU personal data processing | Implemented | Art. 5, 25, 32, 33 |
| **eIDAS** (EU 910/2014) | EU electronic signatures | Implemented | PAdES B-LTA, QES validation |
| **21 CFR Part 11** | FDA-regulated industries | Implemented | Electronic records and signatures |
| **NIST 800-53** | Federal systems (if applicable) | Moderate baseline | AC, AU, IA, SC, SI families |
| **FedRAMP** | Federal cloud services (if applicable) | In progress | Moderate baseline controls |
| **SOC 2 Type II** | Service organizations | In progress | Trust Services Criteria |
| **ISO 27001** | Information security management | Implemented | Annex A controls |
| **FIPS 140-2** | Cryptographic modules | Implemented | FIPS mode available |

### 7.2 Compliance Mapping

**HIPAA Technical Safeguards (45 CFR §164.312):**

| Requirement | Implementation |
|-------------|----------------|
| §164.312(a)(1) Access Control | RBAC with 5 roles, 10 permissions |
| §164.312(a)(2)(i) Unique User ID | User registry with certificate binding |
| §164.312(a)(2)(ii) Emergency Access | Break-glass procedure with admin approval |
| §164.312(a)(2)(iii) Automatic Logoff | 15-minute inactivity timeout |
| §164.312(a)(2)(iv) Encryption | AES-256 PDF encryption |
| §164.312(b) Audit Controls | JSON audit trail with HMAC integrity |
| §164.312(c)(1) Integrity | Digital signatures (PAdES B-LTA) |
| §164.312(c)(2) Authentication | SHA-256 hashing, signature validation |
| §164.312(d) Authentication | PKCS#11 tokens, certificate binding, JWT |
| §164.312(e)(1) Transmission Security | TLS 1.2+ with strong cipher suites |
| §164.312(e)(2)(i) Integrity Controls | TLS with HMAC, digital signatures |
| §164.312(e)(2)(ii) Encryption | TLS 1.2+ encryption in transit |

**GDPR Requirements:**

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| Art. 5(1)(f) | Integrity and confidentiality | AES-256, TLS 1.2+, RBAC |
| Art. 25 | Data protection by design | Secure defaults, HIPAA mode |
| Art. 32 | Security of processing | Encryption, access control, audit |
| Art. 33 | Breach notification | Audit trail for investigation |
| Art. 15 | Right of access | User data export API |
| Art. 17 | Right to erasure | User anonymization function |

---

## 8. System Inventory

### 8.1 Hardware Components

| Component | Description | Security Controls |
|-----------|-------------|-------------------|
| Application Server | Linux workstation or server running PDFSigner | OS hardening, firewall, antivirus |
| Hardware Tokens | PKCS#11 USB tokens (SafeNet, YubiKey) | PIN protection, tamper detection |
| Network Interface | Ethernet/WiFi for API connectivity | Network segmentation, firewall rules |

### 8.2 Software Components

| Component | Version | License | Purpose |
|-----------|---------|---------|---------|
| Python | 3.12+ | PSF | Runtime environment |
| GTK4 | 4.0+ | LGPL | GUI framework |
| pyHanko | 0.25.0+ | MIT | PDF signing engine |
| PyMuPDF | 1.24.0+ | AGPL | PDF manipulation |
| python-pkcs11 | 0.7.0+ | MIT | Hardware token interface |
| FastAPI | 0.115.0+ | MIT | REST API framework |
| cryptography | 43.0.0+ | Apache/BSD | Cryptographic operations |
| Argon2-cffi | 23.1.0+ | MIT | Password hashing |

### 8.3 Network Ports

| Port | Protocol | Service | Access Control |
|------|----------|---------|----------------|
| 8000 | HTTP/HTTPS | PDFSigner REST API | Internal network only |
| 443 | HTTPS | TSA, OCSP, CRL, EU TSL | Outbound only |
| 80 | HTTP | CRL downloads | Outbound only |
| 514 | UDP/TCP | Syslog | SIEM server only |
| 6514 | TCP/TLS | Syslog over TLS | SIEM server only |

---

## 9. Continuous Monitoring

### 9.1 Monitoring Strategy

**Real-time Monitoring:**
- Failed authentication attempts (threshold: 5 per user per hour)
- Permission denied events (threshold: 10 per user per hour)
- Emergency access requests (all events)
- Audit integrity verification failures (all events)
- Encryption policy violations (all events)

**Daily Monitoring:**
- Audit log size and rotation
- Session count and timeouts
- User account changes
- Configuration changes
- Backup completion status

**Weekly Monitoring:**
- Compliance dashboard review
- Emergency access log review
- Failed signature validation trends
- SIEM alert review

**Monthly Monitoring:**
- Full audit log review
- Access rights review
- Unused account cleanup
- Certificate expiration review
- Security patch status

### 9.2 Automated Alerts

| Alert Type | Condition | Severity | Notification |
|-----------|-----------|----------|--------------|
| Authentication Failure | 5 failed attempts | High | Security Officer |
| Account Lockout | Account locked | Medium | User + Admin |
| Emergency Access Request | New request | Critical | All Admins |
| Audit Integrity Failure | Chain verification failed | Critical | Security Officer + Admin |
| Session Timeout Warning | 2 min before timeout | Low | User |
| Certificate Expiration | 30 days before expiry | Medium | Admin |
| Configuration Change | Any config modification | Medium | Admin |
| Backup Failure | Backup did not complete | High | Admin |

### 9.3 Performance Baselines

| Metric | Baseline | Threshold | Action |
|--------|----------|-----------|--------|
| Signature creation time | < 2 seconds | > 5 seconds | Investigate |
| API response time (p95) | < 500ms | > 2 seconds | Scale resources |
| Audit log write time | < 10ms | > 100ms | Check disk I/O |
| Database query time | < 50ms | > 500ms | Optimize queries |
| Session creation time | < 100ms | > 1 second | Review session store |

---

## 10. Security Assessment and Authorization

### 10.1 Assessment Frequency

- **Continuous Monitoring:** Automated checks (daily)
- **Self-Assessment:** Quarterly (by System Administrator)
- **Internal Audit:** Annually (by Security Officer)
- **Third-Party Assessment:** Biennially (by certified assessor)
- **Penetration Testing:** Annually (by external firm)

### 10.2 Authorization Boundary Changes

Any changes to the authorization boundary require:
1. Risk assessment by Security Officer
2. SSP update and review
3. Security control re-validation
4. Approval by Authorizing Official
5. Documentation update

### 10.3 Plan of Action and Milestones (POA&M)

| Control ID | Weakness Description | Remediation Plan | Scheduled Completion | Status |
|-----------|---------------------|------------------|---------------------|--------|
| IA-5(1) | Password policy not fully enforced | Implement password policy engine (Phase 2) | 2026-Q2 | In Progress |
| IA-8(1) | OAuth/SAML not implemented | Add OAuth 2.0 / SAML support | 2026-Q3 | Planned |
| AU-6(1) | SIEM integration limited | Expand SIEM integrations (Splunk, ELK, QRadar) | 2026-Q2 | Completed |
| SC-8(1) | Certificate pinning not implemented | Implement TSA certificate pinning | 2026-Q2 | Planned |

---

## 11. Appendices

### Appendix A: Acronyms and Abbreviations

| Acronym | Definition |
|---------|------------|
| AES | Advanced Encryption Standard |
| API | Application Programming Interface |
| CA | Certificate Authority |
| CEF | Common Event Format |
| CLI | Command Line Interface |
| CRL | Certificate Revocation List |
| DSS | Document Security Store |
| eIDAS | Electronic Identification and Trust Services |
| FIPS | Federal Information Processing Standards |
| GDPR | General Data Protection Regulation |
| GUI | Graphical User Interface |
| HIPAA | Health Insurance Portability and Accountability Act |
| HMAC | Hash-based Message Authentication Code |
| HSM | Hardware Security Module |
| JSON | JavaScript Object Notation |
| JSONL | JSON Lines |
| JWT | JSON Web Token |
| LTV | Long-Term Validation |
| mTLS | Mutual Transport Layer Security |
| NIST | National Institute of Standards and Technology |
| NSS | Network Security Services |
| OCSP | Online Certificate Status Protocol |
| PAdES | PDF Advanced Electronic Signature |
| PHI | Protected Health Information |
| PII | Personally Identifiable Information |
| PKCS | Public Key Cryptography Standards |
| RBAC | Role-Based Access Control |
| REST | Representational State Transfer |
| RFC | Request for Comments |
| SIEM | Security Information and Event Management |
| SQL | Structured Query Language |
| SSP | System Security Plan |
| TLS | Transport Layer Security |
| TOML | Tom's Obvious, Minimal Language |
| TSA | Time Stamp Authority |
| TSP | Trust Service Provider |
| USB | Universal Serial Bus |

### Appendix B: References

1. NIST SP 800-53 Rev. 5, "Security and Privacy Controls for Information Systems and Organizations"
2. NIST SP 800-171, "Protecting Controlled Unclassified Information in Nonfederal Systems"
3. FIPS 199, "Standards for Security Categorization of Federal Information and Information Systems"
4. FIPS 140-2, "Security Requirements for Cryptographic Modules"
5. 45 CFR Part 164, "Security and Privacy Standards for Health Information"
6. EU Regulation 2016/679 (GDPR), "General Data Protection Regulation"
7. EU Regulation 910/2014 (eIDAS), "Electronic Identification and Trust Services"
8. 21 CFR Part 11, "Electronic Records; Electronic Signatures"
9. ETSI EN 319 142, "PAdES - PDF Advanced Electronic Signatures"
10. RFC 3161, "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)"

### Appendix C: Document Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| System Owner | [Name] | [Signature] | [Date] |
| Security Officer | [Name] | [Signature] | [Date] |
| System Administrator | [Name] | [Signature] | [Date] |
| Authorizing Official | [Name] | [Signature] | [Date] |

---

**Document Classification:** Internal
**Distribution:** Authorized Personnel Only
**Next Review Date:** 2026-08-01

*This System Security Plan is a living document and will be updated as the system evolves and security controls are enhanced.*

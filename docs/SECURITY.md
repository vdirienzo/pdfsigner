# PDFSigner Security Guide

## Overview

PDFSigner implements comprehensive security controls aligned with HIPAA requirements for healthcare document signing. This guide covers the security architecture, configuration hardening, and compliance mapping.

## Security Architecture

### Authentication

#### API Authentication
- **JWT Bearer Tokens**: Time-limited tokens with configurable expiration (default: 30 minutes)
- **API Keys**: Long-lived keys for machine-to-machine communication
- **mTLS Support**: Optional mutual TLS for enhanced client authentication
- **Token Rotation**: Automatic token refresh with secure rotation mechanism

#### GUI Authentication
- **PKCS#11 Hardware Tokens**: Smart cards, USB tokens (SafeNet, YubiKey, etc.)
- **PIN Protection**: Hardware-enforced PIN entry with retry limits
- **Certificate-based**: X.509 certificate binding to user accounts

#### Password Security
- **Argon2id Hashing**: Memory-hard password hashing resistant to GPU attacks
- **Configurable Parameters**:
  - Time cost: 4 iterations (default)
  - Memory cost: 64 MB (default)
  - Parallelism: 4 threads
- **Minimum Requirements**: Enforced 12-character minimum, complexity requirements

### Authorization

#### Role-Based Access Control (RBAC)
PDFSigner implements a 5-role, 10-permission RBAC system:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **viewer** | VIEW | Read-only access to documents |
| **signer** | VIEW, SIGN, VALIDATE, ENCRYPT, DECRYPT | Standard document signing |
| **auditor** | VIEW, VALIDATE, AUDIT_VIEW, EXPORT | Compliance auditing |
| **admin** | ALL except EMERGENCY_ACCESS | System administration |
| **emergency** | EMERGENCY_ACCESS + subset | Break-glass access |

#### Permission Matrix

| Permission | Description | Required Role |
|------------|-------------|---------------|
| VIEW | View documents and signatures | viewer+ |
| SIGN | Create digital signatures | signer+ |
| VALIDATE | Verify signature validity | signer+ |
| ENCRYPT | Encrypt PDFs | signer+ |
| DECRYPT | Decrypt PDFs | signer+ |
| EXPORT | Export reports and logs | auditor+ |
| ADMIN_USERS | Manage user accounts | admin |
| ADMIN_CONFIG | Modify system configuration | admin |
| AUDIT_VIEW | View audit logs | auditor+ |
| EMERGENCY_ACCESS | Break-glass access | emergency |

### Data Protection

#### Encryption at Rest
- **Algorithm**: AES-256-CBC (FIPS 140-2 compliant)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (600,000 iterations)
- **Compliance**: HIPAA §164.312(a)(2)(iv) - Encryption and Decryption
- **HIPAA Mode**: Enforces additional restrictions:
  - AES-256 required (AES-128 blocked)
  - Print permission disabled
  - Copy/extract permissions disabled
  - Owner password required

#### Encryption in Transit
- **TLS 1.2+**: Minimum TLS 1.2, TLS 1.3 recommended
- **Cipher Suites**: Strong ciphers only (no RC4, DES, 3DES)
- **Certificate Validation**: Full chain validation with CRL/OCSP checking
- **Perfect Forward Secrecy**: ECDHE key exchange required

#### PHI Detection
Automatic scanning for Protected Health Information:
- **SSN**: Social Security Numbers (XXX-XX-XXXX pattern)
- **MRN**: Medical Record Numbers
- **DOB**: Dates of birth
- **Phone**: US phone numbers
- **Email**: Email addresses
- **Address**: Street addresses

**Actions on Detection**:
- Warning displayed to user
- Encryption recommended/enforced (in HIPAA mode)
- Audit log entry created

#### Secure Deletion
- **Standard**: DoD 5220.22-M (3-pass overwrite)
- **Passes**:
  1. Write 0x00 (zeros)
  2. Write 0xFF (ones)
  3. Write random data
- **Verification**: Read-back verification after each pass
- **Scope**: Temporary files, decrypted PDFs, cached data

### Audit Controls

#### Audit Trail Architecture
- **Format**: JSON Lines (JSONL) for efficient streaming
- **Storage**: Append-only file with file-level locking
- **Retention**: 6 years (HIPAA §164.530(j) requirement)
- **Compression**: Automatic monthly log rotation with gzip compression

#### Tamper Detection
- **Chain Hashing**: SHA-256 hash chain linking records
- **HMAC Signatures**: HMAC-SHA256 signatures on each record
- **Integrity Verification**:
  - `verify_chain()`: Validates entire audit log
  - `verify_record()`: Validates single record
  - Detects: deletions, modifications, insertions, reordering

#### Record Structure
```json
{
  "timestamp": "2026-02-01T04:30:15.123456Z",
  "event_type": "SIGN",
  "user_id": "user@example.com",
  "resource": "/path/to/document.pdf",
  "action": "sign_document",
  "status": "success",
  "details": {"certificate": "CN=...", "algorithm": "RSA-2048"},
  "ip_address": "192.168.1.100",
  "session_id": "abc123...",
  "record_hash": "sha256:...",
  "previous_hash": "sha256:...",
  "hmac_signature": "hmac-sha256:..."
}
```

#### Audited Events
- Authentication: LOGIN, LOGOUT, LOGIN_FAILED
- Document Operations: SIGN, VALIDATE, ENCRYPT, DECRYPT
- Access Control: PERMISSION_DENIED, ROLE_ASSIGNED
- System: CONFIG_CHANGE, BACKUP_CREATED, BACKUP_RESTORED
- Emergency: EMERGENCY_REQUEST, EMERGENCY_APPROVED, EMERGENCY_DENIED

### Session Management

#### Session Security
- **Session IDs**: Cryptographically random (32 bytes, hex-encoded)
- **Auto-logoff**: Configurable timeout (5-60 minutes, default: 15)
- **Activity Tracking**: Real-time inactivity detection
- **Concurrent Limits**: Max sessions per user (configurable, default: 3)
- **Session Invalidation**: Immediate invalidation on logout/timeout

#### Session Storage
- **Backend**: SQLite with encrypted session data
- **Encryption**: AES-256-GCM for session payloads
- **Expiration**: Automatic cleanup of expired sessions
- **Revocation**: Admin-initiated session termination

#### Inactivity Detection
- **GUI**: GTK idle timer with 1-second polling
- **API**: Token expiration and refresh mechanism
- **Warning**: 2-minute warning before auto-logoff
- **Grace Period**: 30 seconds to respond to warning

### Emergency Access (Break-Glass)

#### Request Workflow
1. **Request**: User requests emergency access with justification
2. **Approval** (optional): Admin reviews and approves/denies
3. **Grant**: Temporary elevated permissions granted
4. **Monitoring**: All actions during emergency access logged
5. **Expiration**: Access automatically revoked after duration
6. **Review**: Post-access audit review required

#### Configuration Options
- **Duration**: 1-24 hours (default: 4 hours)
- **Approval**: Optional admin approval (default: required)
- **Permissions**: Configurable permission set
- **Notification**: Email/SMS alerts to security team
- **Audit Trail**: Complete log of emergency access usage

#### Security Controls
- **Justification Required**: Documented reason for access
- **Time-Limited**: Automatic expiration
- **Non-Extendable**: Cannot extend existing emergency access
- **Full Audit**: Every action logged with "EMERGENCY" flag
- **Post-Review**: Mandatory audit review after expiration

## Configuration Hardening

### Production Deployment Checklist

#### 1. Enable Healthcare Mode
```toml
[healthcare]
healthcare_mode = true
healthcare_session_timeout_minutes = 15
healthcare_max_sessions = 3
healthcare_emergency_duration_hours = 4
healthcare_emergency_require_approval = true
```

#### 2. Configure TLS/SSL
```toml
[api]
tls_enabled = true
tls_min_version = "TLSv1.2"
tls_cert_path = "/etc/pdfsigner/certs/server.crt"
tls_key_path = "/etc/pdfsigner/certs/server.key"
tls_ca_bundle = "/etc/pdfsigner/certs/ca-bundle.crt"

# Optional: mTLS for client authentication
mtls_enabled = true
mtls_client_ca = "/etc/pdfsigner/certs/client-ca.crt"
```

#### 3. Enable PHI Detection
```toml
[encryption]
phi_detection_enabled = true
phi_detection_block_unencrypted = true  # Enforce encryption for PHI
phi_patterns = [
    "ssn",           # Social Security Numbers
    "mrn",           # Medical Record Numbers
    "dob",           # Dates of Birth
    "phone",         # Phone Numbers
    "email",         # Email Addresses
]
```

#### 4. Configure Encryption
```toml
[encryption]
encryption_enabled = true
encryption_strength = "aes256"          # AES-128 or AES-256
encryption_method = "password"          # password or certificate
encryption_hipaa_mode = true            # Enforce HIPAA restrictions
encryption_allow_print = false          # Must be false in HIPAA mode
encryption_store_password = false       # Do not persist passwords
```

#### 5. Harden Audit Logging
```toml
[audit]
audit_enabled = true
audit_log_path = "/var/log/pdfsigner/audit.jsonl"
audit_retention_days = 2190             # 6 years (HIPAA requirement)
audit_integrity_enabled = true          # Enable HMAC chain
audit_syslog_enabled = true             # Forward to SIEM
audit_syslog_host = "siem.example.com"
audit_syslog_port = 514
```

#### 6. Configure Session Management
```toml
[session]
session_timeout_minutes = 15
session_max_concurrent = 3
session_warning_seconds = 120           # 2-minute warning
session_grace_period_seconds = 30
session_secure_cookies = true           # HTTPS only
session_httponly = true                 # Prevent XSS
session_samesite = "strict"             # CSRF protection
```

#### 7. Enable Secure Temp File Handling
```toml
[temp]
temp_secure_delete = true               # DoD 5220.22-M deletion
temp_retention_hours = 24               # Auto-cleanup after 24h
temp_directory = "/var/tmp/pdfsigner"   # Secure temp directory
temp_permissions = "0600"               # Owner-only access
```

#### 8. Configure Password Policy
```toml
[auth]
password_min_length = 12
password_require_uppercase = true
password_require_lowercase = true
password_require_digits = true
password_require_special = true
password_max_age_days = 90
password_history = 10                   # Prevent reuse
password_lockout_attempts = 5
password_lockout_duration_minutes = 30
```

#### 9. Configure Backups
```toml
[backup]
backup_enabled = true
backup_schedule = "0 2 * * *"           # Daily at 2 AM
backup_retention_days = 30
backup_encrypt = true
backup_encryption_key_path = "/etc/pdfsigner/backup.key"
backup_destination = "/backup/pdfsigner/"
backup_verify = true                    # Verify after backup
```

#### 10. Configure Rate Limiting
```toml
[api]
rate_limiting_enabled = true
rate_limit_per_minute = 60              # 60 requests/minute
rate_limit_per_hour = 1000              # 1000 requests/hour
rate_limit_burst = 10                   # Allow bursts of 10
```

### File Permissions

#### Application Files
```bash
# Configuration files (contains sensitive data)
chmod 600 /etc/pdfsigner/config.toml
chmod 600 /etc/pdfsigner/secrets.env

# Executable files
chmod 755 /usr/bin/pdfsigner
chmod 755 /usr/bin/pdfsigner-gui
chmod 755 /usr/bin/pdfsigner-api

# Log files
chmod 640 /var/log/pdfsigner/*.log
chown pdfsigner:pdfsigner /var/log/pdfsigner/

# Audit logs (more restrictive)
chmod 600 /var/log/pdfsigner/audit.jsonl
chown pdfsigner:pdfsigner /var/log/pdfsigner/audit.jsonl
```

#### Database Files
```bash
# SQLite databases
chmod 600 /var/lib/pdfsigner/*.db
chown pdfsigner:pdfsigner /var/lib/pdfsigner/*.db

# Database backups
chmod 600 /backup/pdfsigner/*.db.enc
```

#### SSL/TLS Certificates
```bash
# Private keys (most restrictive)
chmod 400 /etc/pdfsigner/certs/*.key
chown pdfsigner:pdfsigner /etc/pdfsigner/certs/*.key

# Certificates (read-only)
chmod 444 /etc/pdfsigner/certs/*.crt
```

### Network Security

#### Firewall Rules
```bash
# Allow HTTPS API access
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow from specific subnets only
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# Rate limiting at firewall level
iptables -A INPUT -p tcp --dport 8443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 8443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP
```

#### Reverse Proxy Configuration (nginx)
```nginx
server {
    listen 443 ssl http2;
    server_name pdfsigner.example.com;

    # SSL/TLS Configuration
    ssl_certificate /etc/ssl/certs/pdfsigner.crt;
    ssl_certificate_key /etc/ssl/private/pdfsigner.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
    limit_req zone=api burst=10 nodelay;

    # Proxy to PDFSigner API
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Testing

### Penetration Testing Scope
- Authentication bypass attempts
- Authorization privilege escalation
- SQL injection (SQLite databases)
- Path traversal attacks
- CSRF attacks
- XSS attacks (API responses)
- Session fixation/hijacking
- Cryptographic weaknesses

### Automated Security Scanning
```bash
# Semgrep SAST scanning
semgrep --config=auto src/

# Dependency vulnerability scanning
safety check
pip-audit

# Secrets detection
gitleaks detect --source . --verbose

# Container scanning (if using Docker)
trivy image pdfsigner:latest
```

### Manual Security Review Checklist
- [ ] All passwords hashed with Argon2id
- [ ] No hardcoded secrets in code
- [ ] TLS certificates validated
- [ ] Input validation on all user inputs
- [ ] Output encoding for all responses
- [ ] SQL queries use parameterization
- [ ] File paths sanitized (no traversal)
- [ ] Audit logs tamper-evident
- [ ] Sessions properly invalidated
- [ ] Rate limiting enabled
- [ ] Error messages don't leak sensitive data
- [ ] Temporary files securely deleted

## Known Security Considerations

### Rate Limiting
- **Current**: Basic rate limiting via SlowAPI
- **Recommendation**: Deploy nginx/HAProxy for distributed rate limiting
- **Reason**: Application-level rate limiting can be bypassed with multiple instances

### Network Segmentation
- **API Server**: Should be in DMZ with restricted access
- **Database**: Should be in private network, not exposed to internet
- **Hardware Tokens**: USB passthrough in virtualized environments

### Logging and Monitoring
- **Log Forwarding**: Logs should be forwarded to centralized SIEM
- **Sensitive Data**: PHI values are masked in logs (last 4 digits only)
- **Log Permissions**: Log files have restricted permissions (600)
- **SIEM Integration**: Syslog forwarding supported

### Backup Security
- **Encryption**: All backups should be encrypted
- **Testing**: Restore procedures must be tested quarterly
- **Retention**: Follow organizational retention policies
- **Offsite Storage**: Backups should be stored offsite

### Incident Response
- **Detection**: Monitor audit logs for suspicious patterns
- **Containment**: Ability to disable user accounts immediately
- **Eradication**: Session revocation and password reset
- **Recovery**: Restore from encrypted backups
- **Lessons Learned**: Post-incident review process

## Vulnerability Disclosure

### Reporting Security Issues
**Email**: security@example.com
**PGP Key**: Available at https://example.com/security.asc

### Response Timeline
- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours
- **Resolution Timeline**: Based on severity
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days
  - Low: Next release

### Disclosure Policy
- **Coordinated Disclosure**: 90-day embargo
- **Public Disclosure**: After patch release
- **Credit**: Security researchers acknowledged in CHANGELOG

## Compliance Mapping

### HIPAA Technical Safeguards (45 CFR §164.312)

| HIPAA Requirement | Reference | PDFSigner Implementation |
|-------------------|-----------|--------------------------|
| **Access Control** | §164.312(a)(1) | |
| - Unique User Identification | §164.312(a)(2)(i) | User accounts with email/certificate binding |
| - Emergency Access Procedure | §164.312(a)(2)(ii) | Break-glass emergency access system |
| - Automatic Logoff | §164.312(a)(2)(iii) | Configurable session timeout (default: 15 min) |
| - Encryption and Decryption | §164.312(a)(2)(iv) | AES-256 PDF encryption with PBKDF2 |
| **Audit Controls** | §164.312(b) | JSON audit trail with HMAC chain integrity |
| **Integrity** | §164.312(c)(1) | Digital signatures (PAdES B-LTA) |
| - Mechanism to Authenticate ePHI | §164.312(c)(2) | SHA-256 document hashing, signature validation |
| **Person or Entity Authentication** | §164.312(d) | Certificate binding, PKCS#11 tokens, JWT |
| **Transmission Security** | §164.312(e)(1) | TLS 1.2+ with strong cipher suites |
| - Integrity Controls | §164.312(e)(2)(i) | TLS with HMAC, digital signatures |
| - Encryption | §164.312(e)(2)(ii) | TLS 1.2+ encryption in transit |

### GDPR Requirements

| GDPR Article | Requirement | Implementation |
|--------------|-------------|----------------|
| Art. 5(1)(f) | Integrity and confidentiality | AES-256 encryption, TLS 1.2+, RBAC |
| Art. 25 | Data protection by design | Default secure settings, HIPAA mode |
| Art. 32 | Security of processing | Encryption, access control, audit logs |
| Art. 33 | Breach notification | Audit trail for incident investigation |

### ISO 27001 Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| A.9.2.1 | User registration and de-registration | User management with audit trail |
| A.9.2.2 | User access provisioning | RBAC with 5 roles, 10 permissions |
| A.9.2.3 | Management of privileged access | Admin and emergency roles |
| A.9.2.4 | User authentication | PKCS#11 tokens, JWT, API keys |
| A.9.2.6 | Access rights review | Audit logs for access monitoring |
| A.9.4.1 | Information access restriction | Permission-based access control |
| A.10.1.1 | Cryptographic controls | AES-256, TLS 1.2+, RSA-2048+ |
| A.12.4.1 | Event logging | Comprehensive JSON audit trail |
| A.12.4.3 | Administrator logs | All admin actions logged |

### NIST Cybersecurity Framework

| Function | Category | Implementation |
|----------|----------|----------------|
| **Identify** | Asset Management | Certificate inventory, user registry |
| **Protect** | Access Control | RBAC, PKCS#11, certificate binding |
| **Protect** | Data Security | AES-256 encryption, secure deletion |
| **Detect** | Anomalies and Events | Audit logging, PHI detection |
| **Respond** | Response Planning | Emergency access, session revocation |

## Security Updates

### Update Policy
- **Security Patches**: Released immediately for critical vulnerabilities
- **Version Support**: Current version + 1 previous major version
- **Notification**: Security advisories published on GitHub Releases

### Update Channels
- **GitHub Releases**: https://github.com/example/pdfsigner/releases
- **Security Advisories**: https://github.com/example/pdfsigner/security/advisories
- **Mailing List**: security-announce@example.com

### Verification
```bash
# Verify release signature
gpg --verify pdfsigner-1.1.0.tar.gz.sig pdfsigner-1.1.0.tar.gz

# Verify checksums
sha256sum -c pdfsigner-1.1.0.tar.gz.sha256
```

## Security Best Practices

### For Administrators
1. Enable healthcare mode in production
2. Use TLS 1.3 with strong cipher suites
3. Enable mTLS for API clients
4. Forward audit logs to SIEM
5. Test backup restoration quarterly
6. Review emergency access logs weekly
7. Rotate API keys every 90 days
8. Keep dependencies updated
9. Monitor security advisories
10. Conduct annual penetration testing

### For Developers
1. Never commit secrets to version control
2. Use parameterized queries (no string concatenation)
3. Validate all user inputs
4. Encode all outputs
5. Use constant-time comparisons for secrets
6. Follow secure coding guidelines
7. Run SAST tools before committing
8. Review security implications of changes
9. Document security considerations
10. Participate in security training

### For End Users
1. Use hardware tokens (PKCS#11) when possible
2. Choose strong passwords (12+ characters)
3. Enable encryption for documents with PHI
4. Log out when finished
5. Report suspicious activity
6. Keep application updated
7. Verify signature validity
8. Use secure networks (no public WiFi)
9. Protect API keys (store securely)
10. Review audit logs for your account

---

**Document Version**: 1.0
**Last Updated**: 2026-02-01
**Next Review**: 2026-08-01

# Audit and Accountability Policy

**Document Owner:** Security & Compliance Team
**Version:** 1.0
**Effective Date:** 2026-02-01
**Review Cycle:** Annual
**Last Review:** 2026-02-01
**Next Review:** 2027-02-01

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-01 | PDFSigner Security Team | Initial release |

---

## 1. Purpose and Scope

### 1.1 Purpose

This Audit and Accountability Policy establishes requirements for the creation, protection, and retention of audit records within PDFSigner to:

- Enable detection and investigation of security incidents
- Support compliance with regulatory requirements (HIPAA, GDPR, NIST)
- Provide evidence for legal and regulatory proceedings
- Ensure accountability for user actions on Protected Health Information (PHI) and other sensitive documents
- Detect unauthorized access, modifications, or tampering

### 1.2 Scope

This policy applies to:

- All PDFSigner deployments (GUI, CLI, REST API)
- All users, administrators, and automated processes
- All audit-generating activities including document signing, validation, encryption, authentication, and administrative actions
- All audit storage systems, SIEM integrations, and backup mechanisms

### 1.3 Regulatory Compliance

This policy addresses:

- **HIPAA** §164.312(b) - Audit controls for ePHI systems
- **HIPAA** §164.308(a)(1)(ii)(D) - Information system activity review
- **NIST SP 800-53 Rev. 5** - AU (Audit and Accountability) family
- **GDPR** Article 30 - Records of processing activities
- **ISO 27001:2022** - A.8.15 Logging

---

## 2. Audit Event Categories

PDFSigner captures the following categories of security-relevant events:

### 2.1 Document Operations

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `SIGN_SUCCESS` | Successful PDF signature operation | High |
| `SIGN_FAILURE` | Failed PDF signature attempt | Medium |
| `VALIDATE_SUCCESS` | Successful signature validation | High |
| `VALIDATE_FAILURE` | Failed signature validation | Low |
| `DOCUMENT_VIEW` | Document accessed for viewing | High |
| `DOCUMENT_EXPORT` | Document exported or downloaded | High |

### 2.2 Encryption Operations

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `ENCRYPT_SUCCESS` | Document encrypted successfully | High |
| `ENCRYPT_FAILURE` | Encryption operation failed | Medium |
| `DECRYPT_SUCCESS` | Document decrypted successfully | High |
| `DECRYPT_FAILURE` | Decryption operation failed | Medium |

### 2.3 Authentication and Access Control

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `TOKEN_LOGIN` | PKCS#11 token authentication | Medium |
| `TOKEN_LOGOUT` | Token logout/disconnection | Low |
| `ACCESS_GRANTED` | Access permission granted | Medium |
| `ACCESS_DENIED` | Access permission denied | High |
| `CERTIFICATE_SELECTED` | Digital certificate selected for use | Medium |

### 2.4 Session Management

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `SESSION_START` | User session initiated | Low |
| `SESSION_END` | User session terminated normally | Low |
| `SESSION_TIMEOUT` | Session expired due to inactivity | Medium |

### 2.5 Emergency Access (Healthcare Mode)

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `EMERGENCY_ACCESS_REQUESTED` | Emergency access requested | High |
| `EMERGENCY_ACCESS_APPROVED` | Emergency access approved by administrator | Critical |
| `EMERGENCY_ACCESS_DENIED` | Emergency access request denied | High |
| `EMERGENCY_ACCESS_REVOKED` | Emergency access revoked | High |
| `EMERGENCY_ACCESS_USED` | Emergency access credentials used | Critical |

### 2.6 User Management

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `USER_CREATE` | New user account created | Medium |
| `USER_UPDATE` | User account modified | Medium |
| `USER_DELETE` | User account deleted/anonymized | High |

### 2.7 Multi-Factor Authentication

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `MFA_ENROLLED` | MFA enrollment completed | Medium |
| `MFA_VERIFIED` | MFA code verified successfully | Low |
| `MFA_VERIFICATION_FAILED` | MFA verification failed | High |
| `MFA_DISABLED` | MFA disabled for user account | High |
| `MFA_BACKUP_USED` | MFA backup code used | Medium |
| `MFA_BACKUP_REGENERATED` | MFA backup codes regenerated | Medium |

### 2.8 System and Administrative Events

| Event Type | Description | PHI Risk |
|------------|-------------|----------|
| `CONFIG_CHANGE` | System configuration modified | High |
| `AUDIT_EXPORT` | Audit logs exported | Critical |
| `AUDIT_INTEGRITY_CHECK` | Audit log integrity verification | High |
| `SYSTEM_CLEANUP` | Temporary file cleanup operation | Low |
| `SYSTEM_BACKUP` | System backup operation | Medium |
| `SYSTEM_EVENT` | General system event (purge, maintenance) | Low |

---

## 3. Audit Log Format

### 3.1 Storage Format

PDFSigner uses **JSON Lines (JSONL)** format for audit logs:

- **One event per line** as a complete JSON object
- **Human and machine readable**
- **Efficient streaming and parsing**
- **Monthly rotation**: `audit_YYYY-MM.jsonl`

**Example:**
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "sign_success",
  "timestamp": "2026-02-01T14:30:45.123456",
  "user_cn": "John Smith",
  "user_id": "user_12345",
  "session_id": "sess_abc123",
  "hostname": "workstation-01",
  "document_path": "/path/to/patient_report.pdf",
  "document_hash_sha256": "abc123...",
  "certificate_serial": "1234567890",
  "certificate_issuer": "CN=Healthcare CA",
  "status": "SUCCESS",
  "ip_address": "192.168.1.100",
  "user_agent": "PDFSigner-API/1.1.0",
  "phi_accessed": true,
  "record_hash": "def456...",
  "previous_hash": "789ghi...",
  "hmac_signature": "jkl012...",
  "details": {
    "signature_level": "PAdES-B-LTA",
    "ltv_enabled": true,
    "tsa_url": "https://tsa.example.com"
  }
}
```

### 3.2 Required Fields

Every audit event MUST contain:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | UUID | Unique event identifier | `550e8400-e29b-41d4-a716-446655440000` |
| `event_type` | String | Event category (see Section 2) | `sign_success` |
| `timestamp` | ISO 8601 | Event occurrence time (UTC) | `2026-02-01T14:30:45.123456Z` |
| `hostname` | String | System hostname | `workstation-01` |
| `status` | String | Event outcome | `SUCCESS`, `FAILURE`, `ERROR` |

### 3.3 Context Fields

| Field | Type | Description | Required When |
|-------|------|-------------|---------------|
| `user_cn` | String | Certificate Common Name | User authenticated |
| `user_id` | String | Unique user identifier | Healthcare mode enabled |
| `session_id` | String | Session identifier | Healthcare mode enabled |
| `ip_address` | String | Client IP address | API access |
| `user_agent` | String | Client application | API access |
| `phi_accessed` | Boolean | PHI was accessed/modified | Document operations |

### 3.4 Document Context Fields

| Field | Type | Description | Required When |
|-------|------|-------------|---------------|
| `document_path` | String | File path or identifier | Document operations |
| `document_hash_sha256` | String | SHA-256 hash of document | Document operations |
| `certificate_serial` | String | Certificate serial number | Signing operations |
| `certificate_issuer` | String | Certificate issuing authority | Signing operations |

### 3.5 Integrity Fields

| Field | Type | Description | Purpose |
|-------|------|-------------|---------|
| `record_hash` | String | SHA-256 hash of this record | Tamper detection |
| `previous_hash` | String | Hash of previous record | Chain integrity |
| `hmac_signature` | String | HMAC-SHA256 signature | Authenticity verification |

### 3.6 Additional Details

| Field | Type | Description |
|-------|------|-------------|
| `details` | Object | Event-specific metadata (JSON) |
| `error_message` | String | Error description for failures |

---

## 4. Retention Requirements

### 4.1 Standard Retention Period

**Default:** 90 days (configurable: 1-3650 days)

```toml
audit_retention_days = 90
```

### 4.2 Healthcare/HIPAA Retention

**Required:** 6 years (2,190 days) per 45 CFR §164.316(b)(2)

```toml
audit_retention_days = 2190  # 6 years for HIPAA compliance
```

### 4.3 GDPR Retention

**Recommended:** 90 days for operational logs, longer for legal hold

```toml
audit_retention_days = 90
gdpr_enabled = true
gdpr_retention_days = 2190  # Align with HIPAA
```

### 4.4 Regulatory Comparison

| Regulation | Minimum Retention | PDFSigner Setting |
|------------|-------------------|-------------------|
| HIPAA | 6 years | `audit_retention_days = 2190` |
| GDPR | "No longer necessary" | `gdpr_retention_days = 2190` |
| SOX | 7 years (financial) | `audit_retention_days = 2555` |
| ISO 27001 | Organization-defined | `audit_retention_days = 365+` |

### 4.5 Automated Cleanup

PDFSigner automatically purges logs older than `audit_retention_days`:

- **Execution:** Monthly rotation triggers cleanup
- **Method:** `AuditLogger.cleanup_old_logs()`
- **Logging:** Deletion actions are logged to current audit log
- **Recovery:** No recovery after deletion (ensure backups)

**Configuration:**
```toml
audit_retention_days = 2190
```

### 4.6 Legal Hold

When documents are under legal hold:

1. **Disable** automatic cleanup:
   ```toml
   audit_retention_days = 3650  # Maximum allowed
   ```
2. **Export** affected audit records to secure storage
3. **Document** legal hold in compliance records
4. **Restore** normal retention after hold lifted

---

## 5. Audit Review Procedures

### 5.1 Daily Reviews

**Responsibility:** Security Operations Center (SOC) / Security Administrator

**Frequency:** Daily (within 24 hours)

**Scope:**
- Failed authentication attempts (>3 per user)
- Emergency access requests and usage
- Access denied events (unexpected)
- Encryption/decryption failures
- System configuration changes

**Method:**
```bash
# Query failed authentication events
uv run pdfsigner audit query \
  --event-type ACCESS_DENIED \
  --event-type TOKEN_LOGIN \
  --status FAILURE \
  --last 24h

# Check emergency access
uv run pdfsigner audit query \
  --event-type EMERGENCY_ACCESS_* \
  --last 24h
```

**Escalation:** Report anomalies to Security Manager within 4 hours

### 5.2 Weekly Reviews

**Responsibility:** Security Administrator

**Frequency:** Weekly

**Scope:**
- PHI access patterns (unusual volume or timing)
- Session timeout trends
- MFA verification failures
- User management changes
- Document export activities

**Method:**
```bash
# PHI access audit
uv run pdfsigner audit query \
  --phi-accessed true \
  --last 7d \
  --output report_phi_access_$(date +%Y%m%d).csv

# User activity summary
uv run pdfsigner audit summary \
  --by user \
  --last 7d
```

**Documentation:** Weekly audit review report in compliance records

### 5.3 Monthly Reviews

**Responsibility:** Compliance Officer / CISO

**Frequency:** Monthly

**Scope:**
- Audit log integrity verification
- Retention compliance check
- SIEM integration status
- Backup verification
- Policy compliance review
- Trend analysis (YoY, MoM)

**Method:**
```bash
# Verify audit integrity
uv run pdfsigner audit verify \
  --all-files \
  --output integrity_report_$(date +%Y%m).json

# Export monthly audit summary
uv run pdfsigner audit export \
  --start $(date -d "1 month ago" +%Y-%m-01) \
  --end $(date +%Y-%m-%d) \
  --format json \
  --output monthly_audit_$(date +%Y%m).jsonl
```

**Deliverable:** Monthly compliance report to executive management

### 5.4 Quarterly Reviews

**Responsibility:** Compliance Officer + External Auditor

**Frequency:** Quarterly

**Scope:**
- Comprehensive audit trail review
- Compliance gap analysis
- Policy effectiveness assessment
- Incident response testing
- Third-party audit preparation

**Documentation:** Quarterly compliance certification

### 5.5 Annual Reviews

**Responsibility:** CISO + Board of Directors

**Frequency:** Annual

**Scope:**
- Full audit policy review and update
- Risk assessment update
- Regulatory compliance certification
- Audit system architecture review
- Budget allocation for audit infrastructure

**Deliverable:** Annual audit and accountability report

---

## 6. Alert Thresholds and Monitoring

### 6.1 Critical Alerts (Immediate Response)

**Response Time:** < 15 minutes

| Alert Condition | Threshold | Action |
|----------------|-----------|--------|
| **Emergency access approved** | Any occurrence | Notify CISO + Security team |
| **Audit log tampering detected** | Any integrity failure | Lock audit system, investigate |
| **Multiple failed authentications** | 5 attempts in 10 minutes | Lock user account, notify Security |
| **Privileged account created** | Any admin/root creation | Verify authorization with IT Director |
| **MFA disabled** | Any occurrence | Require re-enrollment, investigate |
| **Mass document export** | >50 documents in 1 hour | Potential data exfiltration, alert SOC |
| **Configuration changes** | Audit/security settings modified | Verify change request, rollback if unauthorized |

### 6.2 High Priority Alerts (Response < 1 hour)

| Alert Condition | Threshold | Action |
|----------------|-----------|--------|
| **Repeated access denials** | 10+ in 1 hour | Investigate potential attack |
| **Failed decryption attempts** | 3+ on same document | Possible unauthorized access |
| **Session anomalies** | Session >4 hours | Validate user activity |
| **Off-hours activity** | PHI access 10pm-6am | Review with user/manager |
| **Geographic anomaly** | IP change >100km in <1hr | Potential account compromise |
| **Encryption failures** | 5+ in 1 hour | Check system health |

### 6.3 Medium Priority Alerts (Response < 4 hours)

| Alert Condition | Threshold | Action |
|----------------|-----------|--------|
| **High signature volume** | >100 signatures/day/user | Review with user |
| **Validation failures** | >10% failure rate | Check certificate validity |
| **Session timeouts** | >20% of sessions | Evaluate timeout settings |
| **Audit export** | Any occurrence | Verify authorization |
| **System cleanup failures** | 2+ consecutive failures | Check disk space, permissions |

### 6.4 Low Priority Alerts (Response < 24 hours)

| Alert Condition | Threshold | Action |
|----------------|-----------|--------|
| **MFA backup code used** | Any usage | Remind user to regenerate |
| **Document view without action** | >10 views, no signing | Training opportunity |
| **Slow TSA responses** | >5 seconds | Monitor TSA service |
| **SIEM export failures** | 3+ consecutive failures | Check SIEM connectivity |

### 6.5 Alerting Configuration

**SIEM Integration:**
```toml
[siem]
enabled = true
format = "cef"  # or "leef", "json"
syslog_host = "siem.example.com"
syslog_port = 514
syslog_protocol = "tls"
```

**Alert Destinations:**
- SIEM dashboard (Splunk, QRadar, ArcSight)
- Email notifications to security team
- Slack/Teams integration (high/critical only)
- PagerDuty for critical alerts

### 6.6 Alert Suppression

To avoid alert fatigue:

- **Whitelist known patterns** (e.g., scheduled backups)
- **Aggregate similar events** within time windows
- **Tune thresholds** based on baseline behavior
- **Review alert effectiveness** monthly

---

## 7. SIEM Integration

### 7.1 Supported Formats

PDFSigner supports multiple SIEM formats for enterprise security monitoring:

| Format | Description | Best For |
|--------|-------------|----------|
| **CEF** (Common Event Format) | ArcSight standard, Splunk-compatible | ArcSight, Splunk, Elastic SIEM |
| **LEEF** (Log Event Extended Format) | IBM QRadar standard | IBM QRadar |
| **JSON** | Structured JSON logs | Elasticsearch, custom parsers |
| **Syslog** | RFC 5424 compliant | Traditional syslog servers |

### 7.2 CEF Format

**Format:** `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`

**Example:**
```
CEF:0|PDFSigner|PDFSigner|1.1.0|SIGN_SUCCESS|PDF Signature Success|5|
rt=Feb 01 2026 14:30:45 UTC
suser=john.smith@example.com
src=192.168.1.100
fname=/path/to/patient_report.pdf
fileHash=abc123...
msg=Document signed successfully with PAdES-B-LTA
cs1Label=SessionID cs1=sess_abc123
cs2Label=CertificateSerial cs2=1234567890
```

**Configuration:**
```toml
siem_enabled = true
siem_format = "cef"
siem_syslog_host = "splunk.example.com"
siem_syslog_port = 514
siem_syslog_protocol = "tls"
```

### 7.3 LEEF Format

**Format:** `LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Key-Value Pairs`

**Example:**
```
LEEF:2.0|PDFSigner|PDFSigner|1.1.0|SIGN_SUCCESS|^|
devTime=2026-02-01T14:30:45Z^
usrName=john.smith@example.com^
src=192.168.1.100^
resource=/path/to/patient_report.pdf^
resourceHash=abc123...^
cat=Document Operations^
sev=5^
msg=Document signed successfully with PAdES-B-LTA
```

**Configuration:**
```toml
siem_format = "leef"
siem_syslog_host = "qradar.example.com"
siem_syslog_port = 514
```

### 7.4 Syslog Transport

**Protocols:**
- **UDP (Port 514)**: Fast, connectionless, potential packet loss
- **TCP (Port 514/601)**: Reliable, ordered delivery
- **TLS (Port 6514)**: Encrypted, authenticated (recommended for PHI)

**TLS Configuration:**
```toml
siem_syslog_protocol = "tls"
siem_syslog_port = 6514
siem_tls_cert_path = "/etc/pdfsigner/siem-ca.crt"
siem_tls_verify = true
```

### 7.5 File Export

For SIEM systems without direct syslog integration:

```toml
siem_enabled = true
siem_file_path = "/var/log/pdfsigner/siem_export.log"
siem_file_rotation_mb = 100  # Rotate at 100MB
siem_file_retention_days = 90
```

**File Formats:**
- CEF format (one event per line)
- LEEF format (one event per line)
- JSON Lines (one JSON object per line)

**Integration:**
- Use SIEM file collector (Splunk Universal Forwarder, Filebeat, etc.)
- Configure file monitoring on `siem_file_path`
- Set up log rotation handling

### 7.6 SIEM Parsing Rules

**Example Splunk Source Type:**
```
[pdfsigner]
SHOULD_LINEMERGE = false
TRUNCATE = 0
TIME_PREFIX = rt=
TIME_FORMAT = %b %d %Y %H:%M:%S %Z
MAX_TIMESTAMP_LOOKAHEAD = 32
KV_MODE = none
```

**Example QRadar Log Source:**
- Log Source Type: PDFSigner
- Protocol: Syslog
- Log Source Identifier: PDFSigner host
- Parse LEEF format automatically

### 7.7 SIEM Use Cases

1. **Real-time Alerting**
   - Failed authentication attempts
   - Emergency access usage
   - Unusual PHI access patterns

2. **Compliance Reporting**
   - HIPAA access logs
   - User activity summaries
   - Document signing audit trail

3. **Threat Detection**
   - Credential stuffing attacks
   - Data exfiltration attempts
   - Insider threat indicators

4. **Forensics**
   - Incident investigation timeline
   - User action reconstruction
   - Chain of custody evidence

### 7.8 Testing SIEM Integration

```bash
# Test syslog connectivity
uv run pdfsigner audit test-siem

# Send test event
uv run pdfsigner audit test-event \
  --event-type SYSTEM_EVENT \
  --details '{"test": "SIEM integration test"}'

# Verify event in SIEM
# Check SIEM dashboard for test event within 1 minute
```

---

## 8. HIPAA and NIST Compliance Mapping

### 8.1 HIPAA §164.312(b) - Audit Controls

**Requirement:** Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.

**PDFSigner Implementation:**

| HIPAA Requirement | Implementation | Evidence |
|-------------------|----------------|----------|
| Record access to ePHI | All document operations logged with `phi_accessed=true` | Audit logs in `~/.local/share/pdfsigner/audit/` |
| Identify user/entity | `user_id`, `user_cn`, `certificate_serial` fields | User registry + certificate binding |
| Track date/time | ISO 8601 timestamp in UTC | `timestamp` field in every event |
| Record event type | Comprehensive event taxonomy | 30+ event types (Section 2) |
| Record outcome | `status` field (SUCCESS/FAILURE/ERROR) | Every event includes outcome |
| Log security events | Authentication, authorization, emergency access | Events: TOKEN_LOGIN, ACCESS_DENIED, EMERGENCY_ACCESS_* |

**Audit Query Example:**
```bash
# HIPAA audit report: All PHI access in last 30 days
uv run pdfsigner audit query \
  --phi-accessed true \
  --last 30d \
  --output hipaa_access_report_$(date +%Y%m%d).csv
```

### 8.2 HIPAA §164.308(a)(1)(ii)(D) - Information System Activity Review

**Requirement:** Implement procedures to regularly review records of information system activity, such as audit logs, access reports, and security incident tracking reports.

**PDFSigner Implementation:**

| Review Level | Frequency | Procedure | Section Reference |
|--------------|-----------|-----------|-------------------|
| Daily | Every 24h | Failed auth, emergency access, config changes | §5.1 |
| Weekly | Every 7d | PHI access patterns, session anomalies | §5.2 |
| Monthly | Every 30d | Integrity verification, retention compliance | §5.3 |
| Quarterly | Every 90d | Comprehensive review, gap analysis | §5.4 |
| Annual | Yearly | Policy review, risk assessment | §5.5 |

### 8.3 NIST SP 800-53 Rev. 5 - AU Family

| Control | Name | Implementation |
|---------|------|----------------|
| **AU-2** | Event Logging | 30+ event types covering all security-relevant activities |
| **AU-3** | Content of Audit Records | Required fields: event ID, type, timestamp, user, status, outcome |
| **AU-4** | Audit Log Storage | Monthly rotation, configurable retention (1-3650 days) |
| **AU-5** | Response to Audit Logging Process Failures | Error handling, fallback to local logs if SIEM fails |
| **AU-6** | Audit Record Review | Daily/weekly/monthly procedures (Section 5) |
| **AU-7** | Audit Record Reduction | Query filters by date, event type, user, status, PHI access |
| **AU-8** | Time Stamps | ISO 8601 UTC timestamps from system clock |
| **AU-9** | Protection of Audit Information | HMAC signing, chain hashing, file permissions (0600) |
| **AU-10** | Non-repudiation | Digital signature on events (optional HMAC) |
| **AU-11** | Audit Record Retention | Configurable 1-3650 days, HIPAA default 2190 days |
| **AU-12** | Audit Record Generation | Automatic logging at each security-relevant event |

**Example Configuration for NIST Compliance:**
```toml
# AU-2, AU-3, AU-12: Comprehensive logging
audit_enabled = true
audit_sign_events = true  # AU-9, AU-10: Integrity protection

# AU-4, AU-11: Retention
audit_retention_days = 2190  # 6 years

# AU-6: SIEM integration for automated review
siem_enabled = true
siem_format = "cef"
siem_syslog_host = "siem.example.com"
siem_syslog_protocol = "tls"  # AU-9: Protected transmission
```

### 8.4 ISO 27001:2022 - A.8.15 Logging

**Requirement:** Logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.

**PDFSigner Implementation:**

| ISO 27001 Control | Implementation | Evidence |
|-------------------|----------------|----------|
| **A.8.15.1** - Event logging | 30+ event types, comprehensive coverage | `AuditEventType` enum |
| **A.8.15.2** - Protection of log information | HMAC signing, chain hashing, access controls | `AuditIntegrityManager` |

### 8.5 GDPR Article 30 - Records of Processing Activities

**Requirement:** Each controller shall maintain a record of processing activities under its responsibility.

**PDFSigner Implementation:**

| GDPR Requirement | Implementation |
|------------------|----------------|
| Name and contact details of controller | Configurable in system settings |
| Purposes of processing | Logged in `event_type` and `details` |
| Categories of data subjects | `user_id`, `user_cn` fields |
| Categories of personal data | `phi_accessed` flag for PHI/sensitive data |
| Recipients of personal data | `ip_address`, `hostname` for data flow |
| Time limits for erasure | `gdpr_retention_days` setting |
| Technical and organizational security measures | This policy document + implementation |

---

## 9. Audit Chain Integrity

### 9.1 Cryptographic Chain Hashing

PDFSigner implements a **blockchain-inspired integrity mechanism** to detect tampering:

**Chain Structure:**
```
Event 1 → Hash₁ → Event 2 → Hash₂ → Event 3 → Hash₃ → ...
          ↓                  ↓                  ↓
       (HMAC)            (HMAC)            (HMAC)
```

Each audit record contains:
1. **Record Hash** (`record_hash`): SHA-256 hash of the event content
2. **Previous Hash** (`previous_hash`): Hash of the previous event (creates the chain)
3. **HMAC Signature** (`hmac_signature`): HMAC-SHA256 signature for authenticity

### 9.2 Hash Calculation

**Step 1: Calculate Record Hash**
```python
# Exclude integrity fields from hash calculation
event_data = {
    "event_id": "550e8400-...",
    "event_type": "sign_success",
    "timestamp": "2026-02-01T14:30:45.123456",
    "user_cn": "John Smith",
    # ... all fields except record_hash, hmac_signature
    "previous_hash": "789ghi..."  # Included to bind to chain
}

# SHA-256 hash of canonical JSON
record_hash = SHA256(json.dumps(event_data, sort_keys=True))
```

**Step 2: Calculate HMAC Signature**
```python
# HMAC-SHA256 using secret key
hmac_signature = HMAC-SHA256(secret_key, record_hash)
```

**Step 3: Store Event**
```json
{
  "event_id": "550e8400-...",
  "event_type": "sign_success",
  "timestamp": "2026-02-01T14:30:45.123456",
  "user_cn": "John Smith",
  "record_hash": "def456...",
  "previous_hash": "789ghi...",
  "hmac_signature": "jkl012...",
  ...
}
```

### 9.3 Verification Procedures

#### 9.3.1 Single Event Verification

```bash
# Verify individual event integrity
uv run pdfsigner audit verify-event \
  --event-id 550e8400-e29b-41d4-a716-446655440000
```

**Checks:**
1. ✅ Record hash matches recalculated hash
2. ✅ HMAC signature is valid
3. ✅ No fields modified since creation

**Possible Results:**
- ✅ **Valid**: Event integrity intact
- ❌ **Record hash mismatch**: Content modified
- ❌ **HMAC invalid**: Signature tampered or wrong key
- ❌ **Missing integrity fields**: Event not signed

#### 9.3.2 Chain Verification

```bash
# Verify entire audit log chain
uv run pdfsigner audit verify \
  --file ~/.local/share/pdfsigner/audit/audit_2026-02.jsonl
```

**Checks:**
1. ✅ Each event passes single event verification
2. ✅ Each `previous_hash` matches previous event's `record_hash`
3. ✅ No gaps or missing events in sequence
4. ✅ Timestamps are monotonically increasing

**Example Report:**
```json
{
  "file": "/home/user/.local/share/pdfsigner/audit/audit_2026-02.jsonl",
  "verified_at": "2026-02-01T15:00:00.000000Z",
  "total_records": 1250,
  "valid_records": 1250,
  "invalid_records": 0,
  "chain_intact": true,
  "issues": []
}
```

#### 9.3.3 Tamper Detection

**Scenario 1: Content Modification**
```json
// Attacker modifies user_cn field
{
  "user_cn": "Attacker Name",  // Changed
  "record_hash": "def456...",  // Original hash (now invalid)
  "hmac_signature": "jkl012..."
}
```

**Detection:**
```
❌ Record hash mismatch - content may have been modified
   Expected: def456...
   Actual:   xyz789...
```

**Scenario 2: Event Deletion**
```
Event 1 → Hash₁ → [Event 2 DELETED] → Event 3 → Hash₃
                                       ↑
                        previous_hash points to Hash₁ (should be Hash₂)
```

**Detection:**
```
❌ Chain broken - previous_hash mismatch
   Event 3 expected previous_hash: def456... (Event 2)
   Event 3 actual previous_hash:   abc123... (Event 1)
```

**Scenario 3: Event Injection**
```
Event 1 → Hash₁ → [Injected Event] → Event 2 → Hash₂
                  (no valid HMAC)     ↑
                             previous_hash points to injected hash
```

**Detection:**
```
❌ HMAC signature invalid - record may have been tampered
❌ Chain broken at Event 2
```

### 9.4 Secret Key Management

**Key Generation:**
```python
# Default: Derived from machine-specific data
secret_key = SHA256(f"{hostname}-{mac_address}")
```

**Custom Key (Recommended for Production):**
```toml
[audit]
sign_events = true
secret_key_file = "/etc/pdfsigner/audit_signing_key"
```

**Key Rotation:**
1. Generate new key: `uv run pdfsigner audit generate-key`
2. Update configuration with new key
3. New events signed with new key
4. Old events remain valid with old key (store key archive)

**Key Security:**
- **Permissions**: 0400 (read-only, owner only)
- **Storage**: Encrypted filesystem or HSM
- **Backup**: Secure off-site storage
- **Rotation**: Annual or after suspected compromise

### 9.5 Integrity Verification Schedule

| Frequency | Scope | Responsibility |
|-----------|-------|----------------|
| **Real-time** | Each event after write | `AuditLogger` |
| **Daily** | Current month's log | Automated cron job |
| **Monthly** | All logs for past month | Security Administrator |
| **Quarterly** | Full audit history | Compliance Officer |
| **Ad-hoc** | After suspected breach | Incident Response Team |

**Automated Verification (Cron):**
```bash
# /etc/cron.daily/pdfsigner-audit-verify
#!/bin/bash
uv run pdfsigner audit verify --all-files \
  --output /var/log/pdfsigner/integrity_check_$(date +%Y%m%d).json
```

### 9.6 Incident Response for Integrity Failures

**When integrity verification fails:**

1. **Immediate Actions** (within 15 minutes):
   - Stop all audit log writes
   - Preserve current state (snapshot filesystem)
   - Alert Security Incident Response Team (SIRT)
   - Isolate affected system from network

2. **Investigation** (within 1 hour):
   - Identify scope of tampering (which events, time range)
   - Extract valid events before corruption point
   - Review system access logs for unauthorized access
   - Check backup integrity

3. **Remediation** (within 4 hours):
   - Restore from last known good backup
   - Re-key audit signing system
   - Implement additional monitoring
   - Document findings in incident report

4. **Post-Incident** (within 24 hours):
   - Notify affected parties if PHI was accessed
   - Report to regulatory bodies if required (HIPAA breach notification)
   - Update security procedures
   - Schedule root cause analysis

---

## 10. Evidence Preservation for Legal and Compliance

### 10.1 Legal Hold Procedures

When audit records become subject to litigation, investigation, or regulatory inquiry:

#### 10.1.1 Initiation

**Trigger Events:**
- Legal subpoena or court order
- Regulatory investigation notice
- Internal investigation (fraud, data breach)
- Employment dispute involving data access

**Actions:**
1. **Immediate suspension** of automatic log deletion
   ```toml
   audit_retention_days = 3650  # Maximum retention
   ```

2. **Identify scope** of legal hold
   - Date range of relevant events
   - Users involved
   - Documents/systems affected
   - Event types of interest

3. **Document legal hold** in compliance tracking system
   - Case reference number
   - Initiating party (legal, HR, regulator)
   - Scope and duration
   - Authorization (General Counsel signature)

#### 10.1.2 Export and Preservation

```bash
# Export audit logs for legal hold
uv run pdfsigner audit export \
  --start 2025-06-01 \
  --end 2026-02-01 \
  --user john.smith@example.com \
  --phi-accessed true \
  --format json \
  --output legal_hold_12345_audit_export.jsonl

# Verify integrity before export
uv run pdfsigner audit verify \
  --all-files \
  --start 2025-06-01 \
  --end 2026-02-01 \
  --output legal_hold_12345_integrity_report.json

# Create chain of custody record
uv run pdfsigner audit chain-of-custody \
  --file legal_hold_12345_audit_export.jsonl \
  --custodian "Jane Doe, Compliance Officer" \
  --case "Case #12345" \
  --output chain_of_custody_12345.pdf
```

**Export Package Contents:**
1. **Audit events** (JSONL format)
2. **Integrity verification report** (JSON)
3. **Chain of custody form** (PDF)
4. **Export metadata** (date, user, scope, hash)
5. **Schema documentation** (field definitions)

#### 10.1.3 Secure Storage

**Requirements:**
- **Read-only storage** (WORM - Write Once Read Many)
- **Encrypted at rest** (AES-256)
- **Access logging** (who accessed, when)
- **Geographic redundancy** (off-site backup)
- **Integrity verification** (monthly hash checks)

**Media Options:**
- Dedicated legal hold server (isolated network)
- Cloud archival storage (AWS S3 Glacier, Azure Archive)
- Optical media (M-DISC, expected life 1000+ years)
- Tape backup (LTO-8, capacity 12TB per tape)

#### 10.1.4 Access Controls

**Authorized Roles:**
- General Counsel
- Compliance Officer
- Designated Legal Hold Custodian
- External legal counsel (with authorization)

**Access Logging:**
```bash
# Log all access to legal hold files
uv run pdfsigner audit log \
  --event-type AUDIT_EXPORT \
  --details '{
    "legal_hold": "Case #12345",
    "accessed_by": "jane.doe@example.com",
    "reason": "Response to subpoena",
    "exported_records": 1250
  }'
```

### 10.2 Chain of Custody

**Purpose:** Establish unbroken trail of evidence handling for court admissibility.

**Required Documentation:**

| Field | Description | Example |
|-------|-------------|---------|
| **Case Identifier** | Unique case reference | Case #12345, Subpoena XYZ-2026 |
| **Evidence Description** | What is being preserved | Audit logs: 2025-06-01 to 2026-02-01 |
| **Custodian** | Person responsible | Jane Doe, Compliance Officer |
| **Collection Date/Time** | When evidence collected | 2026-02-01 15:30:00 UTC |
| **Collection Method** | How evidence obtained | PDFSigner audit export command |
| **Hash/Signature** | Cryptographic proof of integrity | SHA-256: abc123... |
| **Storage Location** | Where evidence stored | Legal hold server: /vault/case_12345/ |
| **Access Log** | Who accessed, when, why | See attached access log |
| **Transfer Log** | If transferred to third party | Delivered to counsel on 2026-02-05 |

**Chain of Custody Template:**
```
CHAIN OF CUSTODY RECORD

Case: [Case #12345 - Patient Data Access Investigation]
Evidence ID: [LEGAL_HOLD_12345]
Description: [PDFSigner audit logs containing PHI access records]

Initial Collection:
  Date/Time: 2026-02-01 15:30:00 UTC
  Collected By: Jane Doe, Compliance Officer
  Method: PDFSigner audit export CLI
  File: legal_hold_12345_audit_export.jsonl
  SHA-256 Hash: abc123def456...

Storage:
  Location: Legal Hold Server - /vault/case_12345/
  Encryption: AES-256 (FIPS 140-2 compliant)
  Access Controls: General Counsel + Compliance Officer only

Integrity Verification:
  [✓] 2026-02-01 15:35:00 - Initial hash verification passed
  [✓] 2026-02-08 09:00:00 - Weekly verification passed
  [✓] 2026-02-15 09:00:00 - Weekly verification passed

Access Log:
  2026-02-01 15:30:00 | Jane Doe | Export for legal hold
  2026-02-03 10:15:00 | John Smith (General Counsel) | Review for subpoena response
  2026-02-05 14:00:00 | Jane Doe | Copy to external counsel (encrypted USB)

Transfer Log:
  2026-02-05 14:00:00 | Jane Doe → External Counsel (Smith & Associates)
    Method: Hand-delivered encrypted USB drive
    Received By: Attorney Robert Smith
    Signature: [Signature]
    Hash Verified: abc123def456... ✓

I certify that this evidence has been handled in accordance with established
procedures and the chain of custody has been maintained.

Custodian Signature: ______________________ Date: __________
                     Jane Doe, Compliance Officer
```

### 10.3 Compliance Evidence Package

For regulatory audits (HIPAA, GDPR, ISO 27001), prepare standardized evidence package:

**Package Contents:**

1. **Audit Policy Document** (this document)
2. **Configuration Evidence**
   ```bash
   uv run pdfsigner config export --output config_evidence.toml
   ```
3. **Audit Log Samples** (last 3 months)
4. **Integrity Verification Reports** (monthly)
5. **Review Logs** (daily/weekly/monthly review records)
6. **Incident Response Documentation** (if applicable)
7. **Training Records** (staff trained on audit procedures)
8. **SIEM Integration Evidence** (screenshots, test events)
9. **Access Control Matrix** (who can access audit logs)
10. **Retention Policy Compliance Certificate**

**Delivery Format:**
- PDF compilation with digital signature
- Encrypted archive (7z with AES-256)
- Cloud sharing with access logging (Box, Citrix ShareFile)

### 10.4 E-Discovery Considerations

**Format:** Export in JSON Lines for machine readability

**Filtering:** Support e-discovery queries
```bash
# Filter by user
uv run pdfsigner audit query --user john.smith@example.com

# Filter by date range
uv run pdfsigner audit query --start 2025-06-01 --end 2026-02-01

# Filter by event type
uv run pdfsigner audit query --event-type SIGN_SUCCESS

# Filter by document
uv run pdfsigner audit query --document patient_report.pdf

# Combine filters
uv run pdfsigner audit query \
  --user john.smith@example.com \
  --start 2025-06-01 \
  --event-type SIGN_SUCCESS \
  --phi-accessed true
```

**Redaction:** For sensitive fields not relevant to case
```bash
# Export with PII/PHI redaction
uv run pdfsigner audit export \
  --redact-fields user_id,session_id,ip_address \
  --output redacted_audit_export.jsonl
```

### 10.5 Admissibility Requirements

For audit records to be admissible as evidence in legal proceedings:

| Requirement | PDFSigner Implementation |
|-------------|-------------------------|
| **Authenticity** | HMAC signatures, chain hashing |
| **Integrity** | Cryptographic verification, tamper detection |
| **Completeness** | Monthly rotation, no gaps in timestamps |
| **Reliability** | Automated logging (no manual entry) |
| **Trustworthiness** | Business records exception (Federal Rules of Evidence 803(6)) |
| **Best Evidence** | Original digital files, not printouts |
| **Chain of Custody** | Documented collection, storage, access |
| **Expert Testimony** | Technical documentation (this policy + architecture docs) |

**Supporting Documentation for Court:**
- System architecture diagrams
- Audit event schema (JSON format specification)
- Integrity verification algorithm (HMAC, chain hashing)
- Administrator training records
- Policy compliance audits
- Expert witness affidavit (if needed)

---

## 11. Roles and Responsibilities

| Role | Responsibilities |
|------|------------------|
| **CISO / Security Officer** | - Approve audit policy<br>- Review critical alerts<br>- Annual policy review<br>- Incident response oversight |
| **Compliance Officer** | - Monthly/quarterly audits<br>- Regulatory reporting<br>- Legal hold management<br>- External audit coordination |
| **Security Administrator** | - Daily/weekly reviews<br>- Alert configuration and tuning<br>- SIEM integration maintenance<br>- User access management |
| **System Administrator** | - Audit system installation and configuration<br>- Backup management<br>- Storage capacity monitoring<br>- Log rotation maintenance |
| **Application Users** | - Understand audit policy<br>- Report suspicious activity<br>- Comply with security procedures<br>- Cooperate with investigations |
| **External Auditors** | - Quarterly/annual compliance reviews<br>- Evidence examination<br>- Recommendations for improvement |

---

## 12. Exceptions and Waivers

### 12.1 Exception Process

Exceptions to this policy require:

1. **Written justification** (business need, technical limitation)
2. **Risk assessment** (impact of deviation)
3. **Compensating controls** (alternative safeguards)
4. **Approval** by CISO or Compliance Officer
5. **Time limit** (exceptions expire after 90 days)
6. **Documentation** in compliance tracking system

### 12.2 Common Exceptions

| Scenario | Justification | Compensating Control |
|----------|---------------|---------------------|
| **Development/testing environments** | Non-production data, no PHI | Reduced retention (30 days), separate SIEM |
| **Embedded systems with limited storage** | Hardware constraint | Daily export to central server |
| **Air-gapped systems** | No network connectivity | Manual export monthly, encrypted USB transfer |

---

## 13. Training Requirements

All personnel with access to audit systems must complete:

| Audience | Training Topic | Frequency |
|----------|----------------|-----------|
| **All Staff** | Audit policy overview, user responsibilities | Annual |
| **Security Team** | Advanced audit review, SIEM query language, incident response | Quarterly |
| **Compliance Team** | Regulatory requirements, evidence preservation, legal hold | Bi-annual |
| **System Administrators** | Audit system configuration, backup procedures | Annual + on hire |
| **Executives** | Audit reporting, compliance obligations, breach notification | Annual |

---

## 14. Policy Review and Updates

### 14.1 Review Schedule

- **Annual**: Comprehensive policy review
- **Quarterly**: Alert threshold tuning, SIEM integration health check
- **Ad-hoc**: After security incident, regulatory change, or system upgrade

### 14.2 Change Management

Policy changes require:
1. Draft revision with tracked changes
2. Stakeholder review (Security, Compliance, Legal, IT)
3. Impact assessment
4. Approval by CISO
5. Communication to all affected parties
6. Training update (if material changes)
7. Version control (semantic versioning)

### 14.3 Version History

Maintain version history in document header (Section: Document Control).

---

## 15. Related Documents

| Document | Description | Location |
|----------|-------------|----------|
| **Information Security Policy** | Overall security governance | `docs/security/information-security-policy.md` |
| **Incident Response Plan** | Handling security incidents | `docs/security/incident-response-plan.md` |
| **HIPAA Security Policy** | Healthcare-specific requirements | `docs/security/hipaa-security-policy.md` |
| **System Security Plan (SSP)** | NIST 800-171 compliance | `docs/security/SSP.md` |
| **Audit Trail Technical Documentation** | Implementation details | `docs/audit_trail.md` |
| **API Security Documentation** | REST API security controls | `docs/API_SECURITY.md` |
| **GDPR Compliance Plan** | Data protection procedures | `GDPR_COMPLIANCE_PLAN.md` |

---

## 16. Contact Information

| Role | Contact |
|------|---------|
| **Security Officer** | security@example.com |
| **Compliance Officer** | compliance@example.com |
| **Legal Counsel** | legal@example.com |
| **Privacy Officer** | privacy@example.com |
| **Incident Response (24/7)** | incident@example.com / +1-555-SECURITY |

---

## Appendix A: Audit Event Reference

See **Section 2** for complete event taxonomy (30+ event types).

---

## Appendix B: Configuration Examples

### B.1 Standard Deployment (Non-Healthcare)

```toml
[audit]
audit_enabled = true
audit_retention_days = 90
audit_sign_events = false

[siem]
siem_enabled = true
siem_format = "cef"
siem_syslog_host = "splunk.example.com"
siem_syslog_port = 514
siem_syslog_protocol = "tcp"
```

### B.2 Healthcare Deployment (HIPAA)

```toml
[audit]
audit_enabled = true
audit_retention_days = 2190  # 6 years
audit_sign_events = true

[healthcare]
healthcare_mode = true
healthcare_session_timeout_minutes = 15

[siem]
siem_enabled = true
siem_format = "leef"
siem_syslog_host = "qradar.healthcare.org"
siem_syslog_port = 6514
siem_syslog_protocol = "tls"
siem_tls_verify = true
```

### B.3 Government Deployment (NIST 800-53)

```toml
[audit]
audit_enabled = true
audit_retention_days = 2555  # 7 years
audit_sign_events = true

[siem]
siem_enabled = true
siem_format = "json"
siem_file_path = "/var/log/pdfsigner/siem_export.jsonl"
siem_file_rotation_mb = 100
siem_file_retention_days = 2555
```

---

## Appendix C: Audit Query Cookbook

### C.1 Failed Login Attempts
```bash
uv run pdfsigner audit query \
  --event-type TOKEN_LOGIN \
  --status FAILURE \
  --last 24h
```

### C.2 All PHI Access by User
```bash
uv run pdfsigner audit query \
  --user-id user_12345 \
  --phi-accessed true \
  --last 30d \
  --output phi_access_report.csv
```

### C.3 Emergency Access Audit
```bash
uv run pdfsigner audit query \
  --event-type EMERGENCY_ACCESS_APPROVED \
  --event-type EMERGENCY_ACCESS_USED \
  --start 2026-01-01 \
  --output emergency_access_report.json
```

### C.4 Document Signing Activity
```bash
uv run pdfsigner audit query \
  --event-type SIGN_SUCCESS \
  --document patient_report.pdf \
  --start 2025-06-01 \
  --end 2026-02-01
```

### C.5 Configuration Changes
```bash
uv run pdfsigner audit query \
  --event-type CONFIG_CHANGE \
  --last 90d \
  --output config_changes_report.json
```

### C.6 Session Timeout Patterns
```bash
uv run pdfsigner audit query \
  --event-type SESSION_TIMEOUT \
  --last 7d \
  --group-by user_id \
  --output timeout_analysis.csv
```

---

## Appendix D: Integrity Verification Report Sample

```json
{
  "file": "/home/user/.local/share/pdfsigner/audit/audit_2026-02.jsonl",
  "verified_at": "2026-02-01T16:00:00.000000Z",
  "total_records": 1250,
  "valid_records": 1250,
  "invalid_records": 0,
  "chain_intact": true,
  "verification_time_ms": 145,
  "issues": [],
  "summary": {
    "first_event": "2026-02-01T00:00:15.123456Z",
    "last_event": "2026-02-01T23:59:45.987654Z",
    "unique_users": 42,
    "event_types": {
      "sign_success": 650,
      "sign_failure": 5,
      "validate_success": 520,
      "session_start": 42,
      "session_end": 40,
      "session_timeout": 2,
      "token_login": 42,
      "encrypt_success": 10
    }
  },
  "verification_signature": {
    "algorithm": "HMAC-SHA256",
    "signature": "abc123def456...",
    "verified_by": "AuditIntegrityManager v1.1.0"
  }
}
```

---

**END OF DOCUMENT**

---

**Approval Signatures:**

Chief Information Security Officer: ______________________ Date: __________

Compliance Officer: ______________________ Date: __________

Legal Counsel: ______________________ Date: __________

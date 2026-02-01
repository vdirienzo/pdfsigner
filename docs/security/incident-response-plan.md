# Incident Response Plan - PDFSigner

**Document Version:** 2.0
**Effective Date:** 2026-02-01
**Last Review:** 2026-02-01
**Next Review:** 2026-08-01
**Classification:** Internal - Restricted
**Owner:** Security Team

---

## 1. Executive Summary

This Incident Response Plan (IRP) establishes procedures for identifying, responding to, and recovering from security incidents affecting the PDFSigner digital signature platform. The plan ensures compliance with HIPAA §164.308(a)(6) - Security incident procedures and enables rapid containment of threats to Protected Health Information (PHI).

### 1.1 Purpose

- Establish clear procedures for incident detection, analysis, containment, eradication, and recovery
- Define roles and responsibilities for incident response team members
- Ensure regulatory compliance (HIPAA breach notification, GDPR Article 33)
- Minimize business disruption and data loss
- Enable continuous improvement through post-incident reviews

### 1.2 Scope

This plan covers all security incidents affecting:
- PDFSigner infrastructure (GUI, CLI, REST API)
- Audit logs and integrity verification systems
- User accounts and authentication systems (PKCS#11 tokens)
- Encrypted documents and cryptographic keys
- Healthcare-related data (PHI/PII)
- Development and production environments

---

## 2. Incident Classification

### 2.1 Severity Levels

| Level | Name | Description | Response Time | Escalation |
|-------|------|-------------|---------------|------------|
| **1** | **Critical** | Active PHI breach, ransomware, system compromise, regulatory violation | Immediate (< 15 min) | CISO, Legal, CEO |
| **2** | **High** | Unauthorized access attempt, malware detection, audit log tampering, failed emergency access | < 1 hour | Security Manager, IT Director |
| **3** | **Medium** | Suspicious activity, policy violation, failed authentication spike, service degradation | < 4 hours | Security Team Lead |
| **4** | **Low** | Minor policy violation, configuration drift, informational alerts | < 8 hours | On-call Engineer |
| **5** | **Informational** | Routine events requiring documentation only | < 24 hours | Security Analyst |

### 2.2 Incident Types

#### A. Data Breach (PHI/PII Exposure)
**Definition:** Unauthorized access, acquisition, or disclosure of Protected Health Information.

**Examples:**
- Unsigned PDFs containing PHI exfiltrated
- Audit logs showing unauthorized document decryption
- PKCS#11 token compromise
- Certificate binding bypass

**Severity:** Level 1-2 (automatic escalation if > 500 records)

**HIPAA Breach Notification:**
- **Tier 1 (< 500 individuals):** Notify affected individuals within 60 days
- **Tier 2 (≥ 500 individuals):** Notify HHS and media within 60 days, individuals without unreasonable delay
- **Tier 3 (Unauthorized access by workforce):** Risk assessment required, notification if probable compromise

#### B. Unauthorized Access
**Definition:** Access to PDFSigner resources without authorization or exceeding granted permissions.

**Examples:**
- Failed authentication attempts exceeding threshold (10+ in 5 min)
- RBAC bypass attempt
- Emergency access without approval
- Session hijacking or token theft
- Privilege escalation

**Severity:** Level 2-3 (escalate to Level 1 if successful PHI access)

**PDFSigner Detection:**
```bash
# Query audit logs for unauthorized access
GET /api/v1/audit/events?event_type=ACCESS_DENIED&start_date=2026-02-01T00:00:00Z

# Check failed authentication
GET /api/v1/audit/events?event_type=AUTH_FAILURE&limit=100

# Verify audit integrity
uv run python -c "from pdfsigner.core.audit.audit_integrity import verify_audit_integrity; \
print(verify_audit_integrity('~/.local/share/pdfsigner/audit/audit_2026-02.jsonl'))"
```

#### C. Malware/Ransomware
**Definition:** Malicious software detected on systems running PDFSigner.

**Examples:**
- Ransomware encrypting signed PDFs
- Trojan stealing PKCS#11 PINs
- Keylogger targeting certificate credentials
- PDF exploit (malformed signature fields)

**Severity:** Level 1-2

**PDFSigner Impact:**
- Potential compromise of signing keys
- Audit log corruption or deletion
- Encrypted backup compromise
- User registry database corruption

#### D. Service Disruption (DoS/DDoS)
**Definition:** Degradation or unavailability of PDFSigner services.

**Examples:**
- API endpoint flooding
- Database connection exhaustion
- TSA timeout attacks
- Session table overflow

**Severity:** Level 2-4 (depending on duration and scope)

**PDFSigner Indicators:**
- API response time > 5 seconds (normal: < 500ms)
- Session count > 100 concurrent per user
- TSA connection failures > 10% of requests
- Audit log write latency > 1 second

#### E. Insider Threat
**Definition:** Malicious or negligent actions by authorized users.

**Examples:**
- Abuse of emergency access procedures
- Unauthorized PHI document decryption
- Audit log deletion attempts
- Certificate binding manipulation
- Sharing PKCS#11 PINs

**Severity:** Level 1-3

**PDFSigner Detection:**
```python
# Flag suspicious emergency access
GET /api/v1/emergency/requests?status=APPROVED&requester_id={user_id}

# Detect abnormal document access patterns
GET /api/v1/audit/events?phi_accessed=true&user_id={user_id}&start_date={7_days_ago}

# Check audit integrity tampering
GET /api/v1/compliance/status  # Check "audit_integrity" status
```

---

## 3. Incident Response Team

### 3.1 Roles and Responsibilities

| Role | Primary | Backup | Contact | Responsibilities |
|------|---------|--------|---------|------------------|
| **Incident Commander** | [Name] | [Name] | incident-cmd@example.com<br>+1-XXX-XXX-XXXX | Overall coordination, decision authority, stakeholder communication |
| **Security Lead** | [Name] | [Name] | security-lead@example.com<br>+1-XXX-XXX-XXXX | Technical investigation, forensics, threat analysis, SIEM coordination |
| **IT Operations** | [Name] | [Name] | ops-oncall@example.com<br>+1-XXX-XXX-XXXX | System access, backup restoration, service recovery, log collection |
| **Compliance Officer** | [Name] | [Name] | compliance@example.com<br>+1-XXX-XXX-XXXX | HIPAA breach assessment, regulatory notification, documentation |
| **Legal Counsel** | [Name] | [Name] | legal@example.com<br>+1-XXX-XXX-XXXX | Legal risk assessment, law enforcement liaison, contract review |
| **Communications Lead** | [Name] | [Name] | pr@example.com<br>+1-XXX-XXX-XXXX | Internal/external communications, media relations, patient notification |
| **Clinical Representative** | [Name] | [Name] | clinical-admin@example.com<br>+1-XXX-XXX-XXXX | Patient impact assessment (healthcare deployments only) |

### 3.2 Escalation Matrix

| Severity | Notify Within | Initial Notification | Full Activation | External Notification |
|----------|---------------|---------------------|-----------------|----------------------|
| **Level 1** | 15 minutes | Incident Commander, Security Lead, Compliance | All roles | CISO, Legal, CEO (immediate) |
| **Level 2** | 1 hour | Security Lead, IT Ops, Compliance | Incident Commander, Legal (as needed) | IT Director (< 2h) |
| **Level 3** | 4 hours | Security Team, IT Ops | Security Lead (if escalated) | None (unless escalated) |
| **Level 4** | 8 hours | On-call Engineer | Security Team (for tracking) | None |
| **Level 5** | 24 hours | Security Analyst | None | None |

### 3.3 Communication Channels

**Primary (Secure):**
- Signal group: "PDFSigner-IRT" (end-to-end encrypted)
- Secure conference bridge: +1-XXX-XXX-XXXX, PIN: [Secure Store]
- War room: Building A, Room 501 (physical)

**Backup:**
- Encrypted email: irt@example.com (PGP required for sensitive data)
- Microsoft Teams: "Incident Response" channel (for coordination only, no PHI)

**Evidence Collection:**
- Secure file share: `sftp://forensics.example.com/incidents/` (TLS 1.3)
- Chain of custody forms: `/docs/security/templates/chain-of-custody.pdf`

---

## 4. Response Procedures

### 4.1 Phase 1: Identification (Detect & Analyze)

**Objective:** Confirm incident occurrence, classify severity, initiate response.

#### Step 1.1: Detection Sources

| Source | PDFSigner Integration | Alert Threshold |
|--------|----------------------|----------------|
| **SIEM** | `core/audit/audit_logger.py` (SIEMExporter) | Real-time event streaming |
| **Audit Logs** | `~/.local/share/pdfsigner/audit/audit_YYYY-MM.jsonl` | Query API: `/api/v1/audit/events` |
| **Compliance Dashboard** | `/api/v1/compliance/status` | Daily automated scan |
| **User Reports** | `security@example.com` | Manual review within 1 hour |
| **Integrity Verification** | `verify_audit_integrity()` | Daily cron job |
| **API Monitoring** | Prometheus metrics (if configured) | Response time > 5s, error rate > 5% |

#### Step 1.2: Initial Assessment Checklist

```
[ ] Detection timestamp: ___________
[ ] Detection source: ___________
[ ] Affected systems: [ ] GUI  [ ] API  [ ] CLI  [ ] Audit  [ ] Tokens  [ ] Database
[ ] Incident type: [ ] Data Breach  [ ] Unauthorized Access  [ ] Malware  [ ] DoS  [ ] Insider
[ ] Preliminary severity (1-5): ___
[ ] PHI involved: [ ] Yes  [ ] No  [ ] Unknown
[ ] Estimated affected records: ___________
[ ] Systems isolated: [ ] Yes  [ ] No  [ ] N/A
[ ] Incident Commander notified: [ ] Yes  Time: ___________
[ ] Incident ticket created: INC-________
```

#### Step 1.3: Evidence Preservation (Immediate)

**PDFSigner Forensic Data Collection:**

```bash
# 1. Snapshot current audit logs (before rotation)
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="/secure/forensics/${INCIDENT_ID}"
mkdir -p "${EVIDENCE_DIR}"

# 2. Copy audit logs with integrity verification
cp -r ~/.local/share/pdfsigner/audit/ "${EVIDENCE_DIR}/audit/"
sha256sum "${EVIDENCE_DIR}/audit/"*.jsonl > "${EVIDENCE_DIR}/audit-checksums.txt"

# 3. Export audit events (last 7 days)
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.example.com/api/v1/audit/export?start_date=$(date -d '7 days ago' -I)&format=json" \
  > "${EVIDENCE_DIR}/audit-export-$(date -I).json"

# 4. Verify audit integrity
uv run python << EOF
from pdfsigner.core.audit.audit_integrity import verify_audit_integrity
from pathlib import Path
import json

audit_dir = Path.home() / ".local/share/pdfsigner/audit"
results = {}
for log_file in audit_dir.glob("audit_*.jsonl"):
    is_valid, report = verify_audit_integrity(log_file)
    results[str(log_file)] = report

with open("${EVIDENCE_DIR}/integrity-report.json", "w") as f:
    json.dump(results, f, indent=2)
EOF

# 5. Capture system state
uv run pdfsigner --version > "${EVIDENCE_DIR}/version.txt"
ss -tunap | grep pdfsigner > "${EVIDENCE_DIR}/network-connections.txt"
ps aux | grep pdfsigner > "${EVIDENCE_DIR}/processes.txt"
env | grep -i pdf > "${EVIDENCE_DIR}/environment.txt"

# 6. Dump active sessions
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/sessions/" \
  > "${EVIDENCE_DIR}/active-sessions.json"

# 7. Export user registry
sqlite3 ~/.local/share/pdfsigner/users.db \
  ".dump" > "${EVIDENCE_DIR}/users-dump.sql"

# 8. Capture emergency access records
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/emergency/requests?start_date=$(date -d '30 days ago' -I)" \
  > "${EVIDENCE_DIR}/emergency-access-history.json"

# 9. Calculate checksums for chain of custody
find "${EVIDENCE_DIR}" -type f -exec sha256sum {} + > "${EVIDENCE_DIR}/evidence-manifest.txt"

# 10. Set immutable flag (Linux)
chattr +i "${EVIDENCE_DIR}"/*.{txt,json,sql,jsonl} 2>/dev/null || true
```

**Chain of Custody:**
- Document: `/docs/security/templates/chain-of-custody.pdf`
- Required fields: Incident ID, collector name, timestamp, signature
- Store in: Secure evidence locker (physical) + encrypted vault (digital)

#### Step 1.4: Severity Classification Decision Tree

```
START
  |
  +-> PHI confirmed exposed?
       |
       YES --> Level 1 (Critical) --> Activate full IRT
       |
       NO
         |
         +-> System compromise or ransomware?
              |
              YES --> Level 1 (Critical)
              |
              NO
                |
                +-> Unauthorized access successful?
                     |
                     YES --> Level 2 (High)
                     |
                     NO
                       |
                       +-> Service disruption > 4 hours?
                            |
                            YES --> Level 2 (High)
                            |
                            NO --> Level 3-5 (Medium/Low/Info)
```

---

### 4.2 Phase 2: Containment (Short-term & Long-term)

**Objective:** Limit damage and prevent incident spread.

#### Step 2.1: Short-term Containment Actions (< 1 hour)

**For Data Breach / Unauthorized Access:**

```bash
# 1. Disable compromised user account
curl -X PATCH -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/users/${COMPROMISED_USER_ID}" \
  -d '{"active": false, "reason": "INC-20260201-001"}'

# 2. Terminate active sessions for user
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/sessions/user/${COMPROMISED_USER_ID}"

# 3. Revoke API keys
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/auth/api-keys/${KEY_ID}"

# 4. Enable enhanced audit logging
# Update config.toml:
[hipaa.audit]
enhanced = true
log_ip = true
log_user_agent = true
integrity_protection = true

# 5. Block IP address at firewall (if known attacker)
sudo iptables -A INPUT -s ${ATTACKER_IP} -j DROP

# 6. Isolate affected API server (if multi-server)
# Remove from load balancer pool
```

**For Malware/Ransomware:**

```bash
# 1. IMMEDIATE: Disconnect affected system from network
sudo ip link set eth0 down

# 2. DO NOT shut down (RAM contains evidence)
# Take memory dump if trained:
sudo dd if=/dev/mem of=/secure/forensics/${INCIDENT_ID}/memory.dump bs=1M

# 3. Document running processes
ps auxww > /secure/forensics/${INCIDENT_ID}/processes-detailed.txt

# 4. Identify malware process
lsof -p $(pgrep -f suspicious_process) > /secure/forensics/${INCIDENT_ID}/malware-lsof.txt

# 5. Quarantine malware sample (if safe)
mkdir /quarantine/${INCIDENT_ID}
cp /path/to/malware /quarantine/${INCIDENT_ID}/sample.bin
sha256sum /quarantine/${INCIDENT_ID}/sample.bin
```

**For Service Disruption (DoS):**

```bash
# 1. Enable rate limiting (if not already active)
# API middleware: src/pdfsigner/api/middleware/rate_limit.py
# Set aggressive limits:
RATE_LIMIT_PER_MINUTE=10

# 2. Block attacking IPs
tail -f /var/log/pdfsigner/api.log | grep "429 Too Many Requests" | \
  awk '{print $1}' | sort -u | while read IP; do
    sudo iptables -A INPUT -s $IP -j DROP
  done

# 3. Enable CAPTCHA for authentication endpoints (if available)

# 4. Contact upstream ISP for DDoS mitigation
```

#### Step 2.2: Long-term Containment Actions (1-24 hours)

**System Hardening:**

1. **Patch vulnerable components**
   ```bash
   # Update PDFSigner
   uv sync
   uv run pip list --outdated

   # Check for security advisories
   uv run pip-audit
   ```

2. **Rotate credentials**
   ```bash
   # Generate new JWT signing key
   openssl rand -hex 32 > /secure/jwt-secret-new.key

   # Update config.toml
   [api]
   jwt_secret_key = "file:///secure/jwt-secret-new.key"

   # Restart API server
   systemctl restart pdfsigner-api
   ```

3. **Strengthen access controls**
   ```python
   # Temporarily require emergency access approval for all decrypt operations
   # Update: src/pdfsigner/config/settings.py
   healthcare_emergency_require_approval = True
   healthcare_session_timeout_minutes = 10  # Reduce from 15
   ```

4. **Deploy additional monitoring**
   ```bash
   # Enable file integrity monitoring on audit logs
   aide --init
   aide --check

   # Increase audit log retention
   # config.toml:
   [hipaa.retention]
   audit_days = 2555  # 7 years (exceed HIPAA 6 years)
   ```

---

### 4.3 Phase 3: Eradication (Remove Threat)

**Objective:** Eliminate root cause and restore systems to known-good state.

#### Step 3.1: Root Cause Analysis

**Investigation Techniques:**

```bash
# 1. Analyze audit logs for attack vector
uv run python << EOF
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.audit.audit_event import AuditEventType
from datetime import datetime, timedelta

logger = AuditLogger.get_instance()
start = datetime.now() - timedelta(hours=24)

# Get all failed auth attempts
failed_auth = logger.get_events_filtered(
    start_date=start,
    event_types=[AuditEventType.AUTH_FAILURE],
    limit=1000
)

# Identify pattern
ips = {}
for event in failed_auth:
    ip = event.details.get('ip_address')
    if ip:
        ips[ip] = ips.get(ip, 0) + 1

# Print top 10 attacking IPs
for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"{ip}: {count} attempts")
EOF

# 2. Check for privilege escalation
grep -i "permission denied\|unauthorized\|privilege" /var/log/pdfsigner/*.log

# 3. Identify compromised accounts
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/audit/events?event_type=ACCESS_GRANTED&start_date=$(date -d '7 days ago' -I)" | \
  jq '.events[] | select(.details.from_ip | test("^(?!10\\.0\\.)")) | .user_id' | \
  sort | uniq -c | sort -rn

# 4. Validate audit log integrity
uv run python -c "
from pdfsigner.core.audit.audit_integrity import get_audit_integrity_manager
from pathlib import Path

manager = get_audit_integrity_manager()
audit_dir = Path.home() / '.local/share/pdfsigner/audit'

for log_file in sorted(audit_dir.glob('audit_*.jsonl')):
    is_valid, report = manager.verify_audit_file(log_file)
    if not is_valid:
        print(f'❌ {log_file.name}: COMPROMISED')
        print(f'   Issues: {report[\"issues\"]}')
    else:
        print(f'✅ {log_file.name}: Valid')
"
```

**Common Attack Vectors:**

| Vector | PDFSigner Component | Detection | Remediation |
|--------|---------------------|-----------|-------------|
| **Weak PKCS#11 PIN** | `core/token/nss_handler.py` | Repeated AUTH_FAILURE for same user | Force PIN change, enable lockout policy |
| **JWT secret leaked** | `api/middleware/auth.py` | Valid tokens for non-existent sessions | Rotate JWT secret, invalidate all sessions |
| **SQL injection** | `core/users/user_repository.py` | Unexpected SQL errors in logs | Verify parameterized queries, patch |
| **Path traversal** | `api/routes/sign.py` | Access to files outside workspace | Verify `path_sanitize()` usage |
| **Audit log tampering** | `core/audit/audit_logger.py` | Integrity verification failures | Restore from backup, investigate insider |
| **Emergency access abuse** | `core/emergency/break_glass.py` | Emergency requests without approval | Suspend user, require dual approval |

#### Step 3.2: Remediation Actions

**For Malware:**
```bash
# 1. Boot from clean media
# 2. Run antimalware scan
clamscan -r --infected --remove /home/user/
sudo rkhunter --check --sk

# 3. Verify PDFSigner binary integrity
sha256sum $(which pdfsigner)
# Compare with known-good hash from: https://github.com/yourusername/pdfsigner/releases

# 4. Reinstall from trusted source
uv pip uninstall pdfsigner
uv pip install --force-reinstall pdfsigner==2.0.0

# 5. Restore configuration from backup (if corrupted)
cp /backups/pdfsigner/config.toml.$(date -d yesterday +%Y%m%d) \
   ~/.config/pdfsigner/config.toml
```

**For Compromised Certificates:**
```bash
# 1. Revoke certificate (coordinate with CA)
openssl ca -revoke /path/to/cert.pem -keyfile ca-key.pem -cert ca-cert.pem

# 2. Generate CRL
openssl ca -gencrl -out crl.pem -keyfile ca-key.pem -cert ca-cert.pem

# 3. Update PDFSigner CRL cache
rm -f ~/.cache/pdfsigner/crl/*
# Next signature verification will fetch fresh CRL

# 4. Remove certificate binding
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/users/${USER_ID}/certificates/${CERT_SERIAL}"

# 5. Issue new certificate to user
```

---

### 4.4 Phase 4: Recovery (Restore Operations)

**Objective:** Restore systems to normal operations with enhanced security.

#### Step 4.1: Service Restoration Checklist

```
[ ] Malware removed and system clean (antimalware scan: ______ )
[ ] Vulnerabilities patched (version: ______ )
[ ] Credentials rotated (JWT secret, API keys, PKCS#11 PINs)
[ ] Audit logs verified intact (integrity check: PASS / FAIL)
[ ] Backup restoration tested (dry-run date: ______ )
[ ] Monitoring enhanced (SIEM rules deployed: ______ )
[ ] Access controls validated (RBAC test: PASS / FAIL)
[ ] Emergency access procedures reviewed
[ ] User accounts reviewed (disabled count: ______ )
[ ] Systems restarted in production mode
[ ] Smoke tests passed (GUI, API, CLI)
[ ] Incident Commander approval: __________ (signature)
```

#### Step 4.2: PDFSigner Service Restoration

```bash
# 1. Verify system integrity
uv run pytest tests/unit/ -v  # All tests must pass
uv run pytest tests/integration/ -v

# 2. Restore from encrypted backup (if needed)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/backup/restore" \
  -d '{
    "backup_id": "backup-20260131-120000",
    "restore_components": ["config", "audit_logs", "user_database"],
    "verify_integrity": true
  }'

# 3. Verify audit log continuity
uv run python << EOF
from pdfsigner.core.audit.audit_logger import AuditLogger
from datetime import datetime, timedelta

logger = AuditLogger.get_instance()
end = datetime.now()
start = end - timedelta(days=7)

events = logger.get_events(start_date=start, end_date=end)
print(f"Total events in last 7 days: {len(events)}")

# Check for gaps
for i in range(1, len(events)):
    gap = (events[i].timestamp - events[i-1].timestamp).total_seconds()
    if gap > 3600:  # 1 hour gap
        print(f"⚠️  Gap detected: {events[i-1].timestamp} -> {events[i].timestamp}")
EOF

# 4. Restart services
systemctl restart pdfsigner-api
# Wait for health check
for i in {1..30}; do
  if curl -f http://localhost:8000/health; then
    echo "✅ API is healthy"
    break
  fi
  sleep 2
done

# 5. Validate functionality
# Test GUI
uv run pdfsigner-gui &
sleep 5 && killall pdfsigner-gui

# Test CLI (dry-run)
uv run pdfsigner --dry-run sign /tmp/test.pdf

# Test API
TOKEN=$(curl -X POST http://localhost:8000/auth/token \
  -d '{"username":"test","password":"test"}' | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/certificates/

# 6. Enable production monitoring
# Deploy SIEM rules (Splunk example)
index=pdfsigner event_type=AUTH_FAILURE
| stats count by user_id
| where count > 10
| alert_action=email

# 7. Notify users of service restoration
# Send via template: docs/security/templates/service-restored-notification.txt
```

#### Step 4.3: Post-Recovery Validation (24-72 hours)

**Monitoring Checklist:**
- [ ] No new unauthorized access attempts
- [ ] Audit log integrity checks passing (automated daily)
- [ ] API error rate < 0.1%
- [ ] No emergency access without approval
- [ ] User authentication success rate > 95%
- [ ] Session timeout working correctly
- [ ] SIEM alerts triaged (no false negatives)

---

### 4.5 Phase 5: Lessons Learned (Post-Incident Review)

**Objective:** Improve security posture and prevent recurrence.

#### Step 5.1: Post-Incident Review Meeting

**Schedule:** Within 5 business days of incident closure

**Attendees:** All IRT members + stakeholders

**Agenda Template:**
1. **Incident Timeline** (15 min)
   - Detection time
   - Containment time
   - Eradication time
   - Recovery time
   - Total impact duration

2. **What Went Well** (10 min)
   - Effective detection mechanisms
   - Successful containment actions
   - Team coordination strengths

3. **What Went Wrong** (15 min)
   - Detection delays
   - Communication gaps
   - Tool/process failures
   - Resource constraints

4. **Root Cause Analysis** (20 min)
   - Technical root cause
   - Process/policy gaps
   - Human factors
   - Third-party factors

5. **Action Items** (20 min)
   - Technical improvements (code patches, config changes)
   - Process improvements (update IRP, training)
   - Tool acquisitions (SIEM enhancements, forensic tools)
   - Assign owners and deadlines

6. **Regulatory Compliance** (10 min)
   - HIPAA breach notification status
   - Documentation completeness
   - Legal/compliance review

#### Step 5.2: Incident Report Template

```markdown
# INCIDENT REPORT: [INC-YYYYMMDD-NNN]

## Executive Summary
- **Incident Type:** [Data Breach / Unauthorized Access / Malware / etc.]
- **Severity:** Level [1-5]
- **Detection Date:** YYYY-MM-DD HH:MM:SS UTC
- **Resolution Date:** YYYY-MM-DD HH:MM:SS UTC
- **Total Duration:** [X hours/days]
- **PHI Affected:** [Yes/No] ([N] records)
- **Financial Impact:** $[amount] (estimated)

## Incident Timeline
| Time (UTC) | Event | Actor |
|------------|-------|-------|
| 2026-02-01 03:15 | Initial compromise detected (SIEM alert) | Automated |
| 2026-02-01 03:22 | Incident Commander notified | Security Analyst |
| 2026-02-01 03:30 | Affected user account disabled | IT Ops |
| ... | ... | ... |

## Technical Details
### Attack Vector
[Detailed description of how attacker gained access]

### Affected Systems
- PDFSigner API v2.0.0 (server: prod-api-01)
- Audit logs: audit_2026-02.jsonl (integrity: INTACT)
- User accounts affected: [list user IDs]

### Evidence Collected
- Audit log snapshots: /secure/forensics/INC-20260201-001/audit/
- Network captures: /secure/forensics/INC-20260201-001/pcap/
- Memory dumps: /secure/forensics/INC-20260201-001/memory.dump

### Root Cause
[5 Whys analysis...]

## Response Actions Taken
### Containment
- [List containment actions]

### Eradication
- [List eradication actions]

### Recovery
- [List recovery actions]

## Regulatory Notifications
- [ ] HIPAA Breach Notification to HHS (if ≥500 records)
- [ ] Individual notifications sent (if PHI breach)
- [ ] GDPR notification to supervisory authority (if EU data)
- [ ] Law enforcement notification (if criminal activity)

## Lessons Learned
### What Worked
- Audit integrity verification immediately detected tampering attempt
- SIEM alert triggered within 2 minutes of anomaly
- Incident response team activated within 15 minutes

### What Needs Improvement
- Rate limiting was not enabled on authentication endpoint
- No automated backup verification was running
- Emergency access approval workflow had bypass vulnerability

### Action Items
| ID | Action | Owner | Deadline | Status |
|----|--------|-------|----------|--------|
| INC-001-01 | Enable rate limiting on /auth/token | DevOps | 2026-02-05 | DONE |
| INC-001-02 | Deploy automated backup validation | IT Ops | 2026-02-10 | IN PROGRESS |
| INC-001-03 | Patch emergency access bypass (CVE-2026-XXXX) | Dev Team | 2026-02-03 | DONE |
| INC-001-04 | Conduct security training for all users | HR/Security | 2026-02-28 | PLANNED |

## Cost Analysis
- **Response Time:** 24 engineer-hours × $150/hr = $3,600
- **System Downtime:** 4 hours × $500/hr lost productivity = $2,000
- **Forensic Services:** External consultant = $5,000
- **Notification Costs:** 1,500 letters × $2 = $3,000
- **Legal Review:** 10 hours × $300/hr = $3,000
- **TOTAL ESTIMATED COST:** $16,600

## Approvals
- Incident Commander: _________________ Date: _______
- CISO: _________________ Date: _______
- Compliance Officer: _________________ Date: _______

## Distribution
- Internal: IRT members, Executive Team, Compliance
- External: Auditors (if requested), Legal counsel
- Classification: Internal - Restricted
```

---

## 5. Escalation Procedures

### 5.1 Internal Escalation

**Decision Criteria:**

| Escalate to CISO if: | Escalate to CEO/Board if: |
|---------------------|--------------------------|
| ✓ PHI breach confirmed | ✓ PHI breach > 5,000 records |
| ✓ Ransomware attack | ✓ Ransom demand received |
| ✓ Insider threat (employee) | ✓ Senior executive involved |
| ✓ Audit log tampering | ✓ Regulatory investigation likely |
| ✓ Response cost > $50,000 | ✓ Media coverage expected |
| ✓ Service downtime > 8 hours | ✓ Legal action threatened |

**Escalation Template (Email):**
```
TO: ciso@example.com
CC: incident-commander@example.com
SUBJECT: [URGENT] Security Incident Escalation - INC-[ID]
CLASSIFICATION: Internal - Restricted

INCIDENT SUMMARY:
- Incident ID: INC-20260201-001
- Severity: Level 1 (Critical)
- Type: Data Breach - PHI Exposure
- Detection Time: 2026-02-01 03:15 UTC
- Status: Containment phase

IMPACT:
- PHI Records Affected: 1,247 patient records
- Systems Compromised: Production API server
- Estimated Breach Window: 2026-01-31 22:00 - 2026-02-01 03:15 UTC (5.25 hours)

ACTIONS TAKEN:
- Affected server isolated from network (03:22 UTC)
- Compromised user account disabled (03:30 UTC)
- Evidence preserved in /secure/forensics/INC-20260201-001/
- Audit log integrity verified: INTACT

ESCALATION REASON:
- PHI breach exceeds 500 records → HIPAA breach notification required
- Potential unauthorized access to diagnostic reports

RECOMMENDATION:
- Activate legal counsel for breach notification coordination
- Initiate HIPAA breach risk assessment
- Prepare patient notification letters

INCIDENT COMMANDER: John Doe (john.doe@example.com, +1-XXX-XXX-XXXX)
NEXT UPDATE: 2026-02-01 06:00 UTC (every 3 hours until resolved)
```

### 5.2 External Escalation

**Law Enforcement Contact (FBI Cyber Division):**
- **When to contact:** Ransomware, extortion, nation-state attack, criminal activity
- **Contact:** IC3.gov (Internet Crime Complaint Center) or local FBI field office
- **Prepare:** Incident report, evidence manifest, legal counsel review

**HHS Office for Civil Rights (HIPAA Breach):**
- **When to contact:** Confirmed PHI breach (any size within 60 days)
- **Portal:** https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf
- **Required info:** Breach discovery date, affected individuals count, breach type, safeguards in place
- **PDFSigner evidence:** Audit log export, integrity verification report, user access logs

**GDPR Supervisory Authority (if EU individuals affected):**
- **When to contact:** Personal data breach (within 72 hours of discovery)
- **Contact:** National DPA (e.g., ICO in UK, CNIL in France)
- **Required info:** Nature of breach, affected data subjects, consequences, mitigation measures

---

## 6. Communication Templates

### 6.1 Internal Notification (All Staff)

**Subject:** [URGENT] Security Incident - Action Required

**Body:**
```
To: all-staff@example.com
From: security@example.com
Subject: [URGENT] Security Incident Notification - INC-20260201-001
Classification: Internal - Business Sensitive

Dear Team,

We are responding to a security incident affecting PDFSigner. This message contains important actions for all staff.

INCIDENT SUMMARY:
- Type: [Unauthorized Access Attempt / Malware Detection / etc.]
- Status: Contained
- Impact: [Brief description - no sensitive details]

ACTIONS REQUIRED:
1. Change your PDFSigner password immediately at: https://portal.example.com/reset
2. Review recent document access for unauthorized activity: https://portal.example.com/audit
3. Report any suspicious emails or system behavior to security@example.com
4. Do NOT discuss this incident on social media or with external parties

SYSTEMS AFFECTED:
- PDFSigner API: Operational (some features temporarily disabled)
- GUI Application: Operational
- Audit Logging: Operational

EXPECTED RESOLUTION: [Date/Time]

CONTACT:
- Security questions: security@example.com
- System access issues: helpdesk@example.com
- Media inquiries: pr@example.com

We take security seriously and are working to resolve this incident. Thank you for your cooperation.

Security Team
```

### 6.2 External Notification (Patients/Customers)

**Subject:** Important Notice Regarding Your Health Information

**Body (HIPAA Breach Notification Template - Tier 1 < 500 individuals):**
```
[Letterhead: Organization Name, Address]

[Date]

[Patient Name]
[Address]

RE: Notice of Data Security Incident

Dear [Patient Name],

We are writing to inform you of a data security incident that may have affected your protected health information (PHI). We take the privacy and security of your information very seriously and are providing this notice to explain what happened, what information was involved, and the steps we are taking.

WHAT HAPPENED:
On [Date], we discovered that an unauthorized individual may have gained access to our PDFSigner electronic signature system. We immediately launched an investigation and took steps to secure our systems.

WHAT INFORMATION WAS INVOLVED:
The potentially affected information includes: [List types: name, date of birth, medical record number, diagnosis codes, etc. - BE SPECIFIC]

We have no evidence that your information has been misused.

WHAT WE ARE DOING:
- We disabled the affected account immediately upon discovery
- We conducted a comprehensive security review of our systems
- We notified law enforcement and appropriate regulatory authorities
- We are enhancing our security measures, including:
  * Implementing additional access controls
  * Increasing audit monitoring
  * Requiring multi-factor authentication for all users

WHAT YOU CAN DO:
- Review your Explanation of Benefits (EOB) statements for unauthorized services
- Monitor your credit reports for unusual activity
- Consider placing a fraud alert or security freeze on your credit file
- Contact your health insurance provider if you notice suspicious claims

We have arranged for [12 months] of complimentary credit monitoring services through [Provider]. To enroll, please visit [URL] and use enrollment code: [CODE]

FOR MORE INFORMATION:
If you have questions, please contact our dedicated incident response line:
- Phone: 1-800-XXX-XXXX (Monday-Friday, 8am-8pm EST)
- Email: incident-response@example.com

We sincerely apologize for this incident and any concern it may cause. Protecting your privacy is our top priority.

Sincerely,

[Name]
[Title]
[Organization]

RESOURCES:
- Federal Trade Commission (FTC): www.identitytheft.gov, 1-877-ID-THEFT
- Credit Bureaus:
  * Equifax: 1-800-525-6285, www.equifax.com
  * Experian: 1-888-397-3742, www.experian.com
  * TransUnion: 1-800-680-7289, www.transunion.com
```

**Delivery Method:**
- First-class mail (required by HIPAA)
- Backup email (if patient email on file and confirmed secure)

### 6.3 Regulatory Notification (HHS)

**HIPAA Breach Notification - OCR Portal Submission:**

```
BREACH NOTIFICATION TO HHS OFFICE FOR CIVIL RIGHTS
(Submit via: https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf)

COVERED ENTITY INFORMATION:
Name: [Organization Name]
Address: [Street, City, State, ZIP]
Contact: [Name, Title, Phone, Email]
Type: [Health Care Provider / Health Plan / Business Associate]

BREACH INFORMATION:
Date of Breach Discovery: 2026-02-01
Breach Occurrence Date: 2026-01-31 (estimated)
Number of Individuals Affected: 1,247

Type of Breach:
[✓] Unauthorized Access/Disclosure
[ ] Theft
[ ] Loss
[ ] Improper Disposal
[ ] Hacking/IT Incident
[ ] Other

Location of Breach:
[✓] Electronic Medical Record
[ ] Paper Records/Films
[ ] Laptop
[ ] Other Portable Electronic Device
[✓] Network Server

SAFEGUARDS IN PLACE:
- PDFSigner uses PAdES B-LTA digital signatures (eIDAS compliant)
- PKCS#11 hardware token authentication required
- Role-based access control (RBAC) enforced
- Comprehensive audit logging with HMAC integrity protection
- Automatic session timeout (15 minutes inactivity)
- TLS 1.2+ encryption for all API communications
- Daily audit log integrity verification

SAFEGUARDS THAT FAILED:
- Rate limiting was not enabled on authentication endpoint
- Attacker performed credential stuffing attack (10,000+ attempts over 2 hours)
- User account lockout policy was set to 20 attempts (should be 10)

INFORMATION COMPROMISED:
[✓] Names
[✓] Dates of Birth
[✓] Medical Record Numbers
[✓] Diagnosis Codes (ICD-10)
[ ] Social Security Numbers
[ ] Financial Information
[ ] Treatment Information (narrative notes)

MITIGATION ACTIONS:
- Disabled compromised account within 7 minutes of detection
- Isolated affected server within 15 minutes
- Verified audit log integrity (HMAC signatures intact)
- Rotated all authentication credentials
- Deployed rate limiting (10 attempts / 5 minutes)
- Enhanced monitoring (SIEM alerting on authentication anomalies)

NOTIFICATION TO INDIVIDUALS:
Date of Notification: 2026-03-15 (within 60 days of discovery)
Method: First-class mail
Letter Content: [Attach PDF of notification letter]

BUSINESS ASSOCIATE INVOLVED: [Yes/No]
If Yes: [BA Name, Contact, Notification Date]

SUBMITTED BY:
Name: [Compliance Officer Name]
Title: Compliance Officer
Date: 2026-02-15
Signature: ___________________
```

### 6.4 Media Statement (If Public Disclosure Required)

**Press Release Template:**

```
FOR IMMEDIATE RELEASE
Contact: [Name, Title, Phone, Email]

[ORGANIZATION NAME] ANNOUNCES DATA SECURITY INCIDENT

[CITY, STATE] - [Date] - [Organization Name] is notifying patients and regulatory authorities about a data security incident involving our PDFSigner electronic signature system.

On [Date], we discovered that an unauthorized individual gained access to our system between [Date] and [Date]. We immediately launched an investigation with the assistance of third-party cybersecurity experts and law enforcement.

INFORMATION INVOLVED:
The incident potentially affected [Number] individuals. The information involved may include names, dates of birth, medical record numbers, and diagnosis codes. We have no evidence that Social Security numbers or financial information was accessed.

OUR RESPONSE:
We took immediate action to secure our systems and prevent further unauthorized access. We have:
- Disabled the affected accounts
- Enhanced our security controls and monitoring
- Notified law enforcement and regulatory authorities
- Arranged complimentary credit monitoring services for affected individuals

PROTECTING PATIENTS:
Affected individuals will receive notification letters via U.S. mail with detailed information and resources. Individuals can contact our dedicated incident response line at 1-800-XXX-XXXX or visit [website] for more information.

ABOUT [ORGANIZATION]:
[Boilerplate]

###
```

---

## 7. Evidence Preservation & Forensics

### 7.1 Evidence Collection Procedures

**Chain of Custody Requirements:**
- Every evidence transfer must be documented
- Use template: `/docs/security/templates/chain-of-custody.pdf`
- Required fields: Date/time, collector, custodian, witness, hash values

**PDFSigner-Specific Evidence:**

| Evidence Type | Location | Collection Command | Priority |
|---------------|----------|-------------------|----------|
| **Audit Logs** | `~/.local/share/pdfsigner/audit/*.jsonl` | See "Forensic Data Collection" (Section 4.1.3) | CRITICAL |
| **Integrity Reports** | Generated on-demand | `verify_audit_integrity()` | CRITICAL |
| **User Database** | `~/.local/share/pdfsigner/users.db` | `sqlite3 .dump` | HIGH |
| **Session Data** | API: `/api/v1/sessions/` | `curl` export | HIGH |
| **Emergency Access Logs** | API: `/api/v1/emergency/requests` | `curl` export | HIGH |
| **Configuration** | `~/.config/pdfsigner/config.toml` | `cp` with hash | MEDIUM |
| **Application Logs** | `/var/log/pdfsigner/*.log` | `cp` with hash | MEDIUM |
| **API Access Logs** | Nginx/Apache logs | `cp` relevant date ranges | MEDIUM |
| **Network Traffic** | Live capture or PCAP | `tcpdump -i eth0 -w incident.pcap port 8000` | LOW |
| **Memory Dump** | Live system RAM | `dd if=/dev/mem` (requires root) | LOW |

### 7.2 Forensic Analysis Workflow

**Step 1: Isolate evidence (read-only mount)**
```bash
# Mount audit log directory as read-only
sudo mount -o ro,loop /secure/forensics/INC-001/audit.img /mnt/evidence

# Alternative: Use write blocker hardware for physical media
```

**Step 2: Generate timeline**
```python
# Extract timeline from audit logs
uv run python << EOF
from pdfsigner.core.audit.audit_logger import AuditLogger
from datetime import datetime
import json

logger = AuditLogger.get_instance(log_dir="/mnt/evidence/audit")

# Get all events during incident window
start = datetime(2026, 1, 31, 22, 0)
end = datetime(2026, 2, 1, 6, 0)
events = logger.get_events(start_date=start, end_date=end)

# Generate CSV timeline
with open("/secure/forensics/INC-001/timeline.csv", "w") as f:
    f.write("Timestamp,Event Type,User,IP,Document,Status\n")
    for e in events:
        f.write(f"{e.timestamp.isoformat()},{e.event_type.value},{e.user_id},"
                f"{e.details.get('ip_address', 'N/A')},{e.document_path},{e.status}\n")

print(f"Timeline generated: {len(events)} events")
EOF
```

**Step 3: Identify anomalies**
```bash
# Detect suspicious patterns
grep -E "AUTH_FAILURE|ACCESS_DENIED|EMERGENCY_ACCESS" /mnt/evidence/audit/*.jsonl | \
  jq -r '[.timestamp, .event_type, .user_id, .details.ip_address] | @csv' | \
  sort | uniq -c | sort -rn > /secure/forensics/INC-001/anomalies.txt

# Find unusual hours (outside 8am-6pm)
jq -r 'select(.timestamp | . < "2026-02-01T08:00:00" or . > "2026-02-01T18:00:00") |
  [.timestamp, .event_type, .user_id] | @csv' \
  /mnt/evidence/audit/*.jsonl > /secure/forensics/INC-001/after-hours-access.csv
```

**Step 4: Correlate with SIEM (if integrated)**
```bash
# Splunk query example
splunk search 'index=pdfsigner earliest="2026-01-31T22:00:00" latest="2026-02-01T06:00:00"
  | stats count by event_type, user_id, src_ip
  | where count > 100
  | table _time event_type user_id src_ip count'
```

### 7.3 Legal Hold Procedures

**When to initiate legal hold:**
- Litigation anticipated or filed
- Regulatory investigation opened
- Criminal investigation underway
- Breach exceeds 5,000 records

**Legal Hold Process:**

1. **Notify Legal Counsel** (within 24 hours of incident detection if legal hold likely)

2. **Preserve all evidence** (no deletions or modifications):
   ```bash
   # Set immutable flag on Linux
   sudo chattr +i /secure/forensics/INC-001/*

   # Backup to write-once media (WORM)
   tar czf - /secure/forensics/INC-001/ | \
     ssh backup-server "cat > /worm/incidents/INC-001-$(date +%Y%m%d).tar.gz"
   ```

3. **Suspend automated cleanup**:
   ```bash
   # Disable audit log rotation/cleanup for affected period
   # Temporarily set retention to 10 years
   # Update config.toml:
   [hipaa.retention]
   audit_days = 3650  # 10 years
   ```

4. **Document legal hold**:
   - Issue legal hold notice to all custodians (IT, Security, DevOps)
   - Template: `/docs/security/templates/legal-hold-notice.pdf`
   - Track acknowledgments

5. **Segregate evidence**:
   - Move to separate storage outside normal retention policies
   - Label clearly: "LEGAL HOLD - DO NOT DELETE - INC-YYYYMMDD-NNN"

---

## 8. Post-Incident Review Process

### 8.1 Review Meeting Metrics

**Key Performance Indicators:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **MTTD** (Mean Time to Detect) | < 5 min | Time from event to first alert |
| **MTTC** (Mean Time to Contain) | < 1 hour | Time from detection to containment |
| **MTTR** (Mean Time to Recover) | < 4 hours | Time from detection to full recovery |
| **False Positive Rate** | < 10% | Alerts that were false positives |
| **Action Item Completion** | > 90% | Post-incident action items completed on time |

**PDFSigner-Specific Security Metrics:**

```python
# Generate quarterly security dashboard
uv run python << EOF
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.audit.audit_event import AuditEventType
from datetime import datetime, timedelta
import json

logger = AuditLogger.get_instance()
end = datetime.now()
start = end - timedelta(days=90)  # Last quarter

events = logger.get_events_filtered(start_date=start, end_date=end)

metrics = {
    "total_events": len(events),
    "auth_failures": len([e for e in events if e.event_type == AuditEventType.AUTH_FAILURE]),
    "emergency_access": len([e for e in events if "EMERGENCY" in e.event_type.value]),
    "access_denied": len([e for e in events if "DENIED" in e.event_type.value]),
    "phi_accessed": len([e for e in events if e.phi_accessed]),
    "integrity_violations": 0,  # Check audit integrity
}

# Check audit integrity
from pdfsigner.core.audit.audit_integrity import get_audit_integrity_manager
from pathlib import Path

manager = get_audit_integrity_manager()
audit_dir = Path.home() / ".local/share/pdfsigner/audit"

for log_file in audit_dir.glob("audit_2026-*.jsonl"):
    is_valid, report = manager.verify_audit_file(log_file)
    if not is_valid:
        metrics["integrity_violations"] += 1

print(json.dumps(metrics, indent=2))
EOF
```

---

## 9. Regulatory Notification Requirements

### 9.1 HIPAA Breach Notification Rule (45 CFR §164.400)

**Timeline Requirements:**

| Notification To | Timeframe | Method | Trigger |
|----------------|-----------|--------|---------|
| **Affected Individuals** | Within 60 days of breach discovery | First-class mail (or email if agreed) | Any size breach |
| **HHS Office for Civil Rights** | Within 60 days | OCR Portal (https://ocrportal.hhs.gov) | < 500 individuals |
| **HHS + Media** | Within 60 days | OCR Portal + prominent media outlets | ≥ 500 individuals |
| **Business Associates** | Without unreasonable delay | Any secure method | If BA caused breach |

**Breach Discovery Date:**
- The first day on which the breach is known or should reasonably have been known by the covered entity
- For PDFSigner: Date SIEM alert triggered OR date audit log anomaly detected (whichever is earlier)

**Risk Assessment (Low Probability of Compromise = No Notification Required):**

Must consider:
1. **Nature and extent of PHI involved** (SSN vs diagnosis code)
2. **Unauthorized person who accessed PHI** (IT staff vs external attacker)
3. **Was PHI actually acquired or viewed?** (logs must prove)
4. **Extent of risk mitigation** (immediate containment, encryption, etc.)

**PDFSigner Risk Assessment Template:**
```
BREACH RISK ASSESSMENT: INC-20260201-001

1. NATURE OF PHI:
   [✓] Low Risk: Diagnosis codes only (ICD-10)
   [ ] Medium Risk: Medical record numbers + demographics
   [ ] High Risk: SSN, financial info, treatment narratives

2. UNAUTHORIZED PERSON:
   [ ] Low Risk: Internal workforce (accidental access)
   [ ] Medium Risk: Former employee
   [✓] High Risk: External attacker (unknown identity)

3. PHI ACTUALLY ACQUIRED/VIEWED:
   Audit logs show:
   - 1,247 PDFs accessed via GET /api/v1/documents/{id}/download
   - Timestamps: 2026-01-31 22:15 - 2026-02-01 03:10 UTC
   - Source IP: 203.0.113.45 (Russia)
   - Authentication: Valid stolen credentials
   [✓] YES - Acquisition confirmed via audit trail

4. RISK MITIGATION:
   [✓] Immediate containment (7 minutes after detection)
   [ ] Encrypted at rest (PDFs were NOT encrypted)
   [✓] Certificate-based access (but stolen credentials bypassed)
   [✓] Full audit trail intact (no tampering detected)

CONCLUSION:
High probability of compromise → HIPAA breach notification REQUIRED
- External attacker with stolen credentials
- PHI acquisition confirmed (1,247 records)
- PDFs not encrypted
- Must notify individuals + HHS within 60 days
```

### 9.2 GDPR Breach Notification (Article 33)

**Timeline: 72 hours from breach awareness**

**Notification to Supervisory Authority (e.g., ICO, CNIL):**

Required information:
1. Nature of personal data breach
2. Contact point for more information (DPO)
3. Likely consequences of the breach
4. Measures taken or proposed to address the breach

**Notification to Data Subjects (Article 34):**
Required if breach likely results in "high risk" to rights and freedoms.

**High Risk Factors:**
- Identity theft risk
- Financial loss risk
- Discrimination or reputational damage
- Loss of confidentiality of health data

**Exemptions (no individual notification needed):**
- Encrypted data (and key not compromised)
- Immediate measures taken to eliminate high risk
- Disproportionate effort (may use public communication instead)

**PDFSigner Context:**
- If EU patients/clinics use PDFSigner → GDPR applies
- PHI breach = health data = high risk → notify individuals + SA
- Use encrypted email or secure portal for notification (not plain email)

---

## 10. Integration with PDFSigner Systems

### 10.1 Audit Trail Integration

**Real-Time Monitoring:**

```python
# Deploy SIEM export configuration
# File: ~/.config/pdfsigner/config.toml

[siem]
enabled = true
export_format = "cef"  # Common Event Format (ArcSight, Splunk)
destination = "syslog://siem.example.com:514"
export_realtime = true
export_batch_size = 100

[siem.filters]
# Only export security-relevant events
include_event_types = [
    "AUTH_FAILURE",
    "ACCESS_DENIED",
    "EMERGENCY_ACCESS",
    "DOCUMENT_DECRYPT",
    "AUDIT_INTEGRITY_FAILURE",
    "SESSION_TIMEOUT",
]
```

**SIEM Alert Rules (Splunk Example):**

```spl
# Alert: Credential Stuffing Attack
index=pdfsigner event_type=AUTH_FAILURE
| stats count by user_id, src_ip
| where count > 10
| alert action=email subject="[SECURITY] Possible Credential Stuffing" priority=high

# Alert: Audit Log Tampering
index=pdfsigner event_type=AUDIT_INTEGRITY_FAILURE
| alert action=pagerduty priority=critical

# Alert: Emergency Access Without Approval
index=pdfsigner event_type=EMERGENCY_ACCESS approved_by=null
| alert action=email subject="[CRITICAL] Unauthorized Emergency Access" priority=critical

# Alert: After-Hours PHI Access
index=pdfsigner phi_accessed=true
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| alert action=email subject="[SECURITY] After-Hours PHI Access" priority=medium
```

### 10.2 Automated Incident Detection

**Deploy automated health checks:**

```bash
# /etc/cron.d/pdfsigner-security-checks
# Run every 5 minutes

*/5 * * * * root /usr/local/bin/pdfsigner-security-check.sh

# /usr/local/bin/pdfsigner-security-check.sh
#!/bin/bash
set -euo pipefail

LOG="/var/log/pdfsigner/security-checks.log"

# 1. Verify audit log integrity
echo "[$(date -Iseconds)] Running audit integrity check..." >> "$LOG"
uv run python -c "
from pdfsigner.core.audit.audit_integrity import verify_audit_integrity
from pathlib import Path
from datetime import datetime
import sys

audit_dir = Path.home() / '.local/share/pdfsigner/audit'
current_month = f'audit_{datetime.now().strftime(\"%Y-%m\")}.jsonl'

if (audit_dir / current_month).exists():
    is_valid, report = verify_audit_integrity(audit_dir / current_month)
    if not is_valid:
        print(f'❌ ALERT: Audit integrity check FAILED', file=sys.stderr)
        # Trigger incident
        sys.exit(1)
" 2>> "$LOG" || {
    # Send alert
    curl -X POST https://alerts.example.com/api/incidents \
      -d '{"severity":"critical","type":"AUDIT_INTEGRITY_FAILURE"}'
}

# 2. Check for excessive auth failures
FAILURES=$(grep -c "AUTH_FAILURE" ~/.local/share/pdfsigner/audit/*.jsonl 2>/dev/null | tail -100 | awk '{sum+=$1} END {print sum}' || echo "0")
if [ "$FAILURES" -gt 100 ]; then
    echo "[$(date -Iseconds)] ALERT: Excessive auth failures: $FAILURES" >> "$LOG"
    # Send alert
fi

# 3. Check compliance status
uv run python -c "
from pdfsigner.core.compliance.status_checker import ComplianceStatusChecker
checker = ComplianceStatusChecker()
status = checker.check_all()
if not status.get('all_compliant', False):
    print('⚠️  COMPLIANCE ISSUE DETECTED')
" >> "$LOG"

echo "[$(date -Iseconds)] Security checks complete" >> "$LOG"
```

---

## 11. Training & Awareness

### 11.1 IRT Training Requirements

**Mandatory Training (Annual):**

| Role | Training Module | Duration | Certification |
|------|----------------|----------|---------------|
| All IRT Members | Incident Response Fundamentals | 4 hours | Required |
| All IRT Members | HIPAA Breach Notification | 2 hours | Required |
| Security Lead | Digital Forensics & Evidence Handling | 16 hours | GCFE, GCFA, or equivalent |
| Security Lead | Threat Hunting & Malware Analysis | 8 hours | Recommended |
| Incident Commander | Crisis Communication | 4 hours | Required |
| Compliance Officer | HIPAA Privacy Rule Deep Dive | 8 hours | Required |
| IT Operations | PDFSigner Architecture & Security Controls | 4 hours | Required |

**Quarterly Tabletop Exercises:**

**Exercise Template:**

```
TABLETOP EXERCISE: RANSOMWARE ATTACK ON PDFSIGNER

Date: 2026-Q2
Duration: 2 hours
Participants: Full IRT + Executive Sponsor
Facilitator: External Consultant (recommended) or CISO

SCENARIO:
Friday 2:00 PM: Helpdesk receives reports that PDFSigner API is returning errors.
Investigation reveals all signed PDFs in /var/pdfsigner/documents/ are encrypted with
.locked extension. A ransom note demands 50 BTC within 48 hours.

TIMELINE:
- T+0 (14:00): Initial reports of API errors
- T+15: IT identifies ransomware on production server
- T+30: Incident Commander assembles IRT
- [PAUSE: What do you do next?]

DISCUSSION QUESTIONS:
1. Who needs to be notified immediately?
2. What evidence should be preserved?
3. Should we isolate the server? What's the impact?
4. Are backups available? How do we verify they're not infected?
5. Do we pay the ransom? Who decides?
6. What PHI was potentially affected?
7. Is this a HIPAA breach? When must we notify?
8. How do we restore service?

SUCCESS CRITERIA:
✓ Incident classified correctly (Level 1, Data Breach + Malware)
✓ CISO notified within 15 minutes
✓ Evidence preservation started within 30 minutes
✓ Backups identified and verified clean
✓ Recovery plan developed within 2 hours
✓ Communication plan developed for patients/staff
✓ Regulatory notification timeline understood (60 days HIPAA)

LESSONS LEARNED:
[Document during debrief]
```

### 11.2 End-User Security Awareness

**Annual Mandatory Training (All Staff):**
- Phishing recognition
- Password security (12+ characters, unique passwords)
- PKCS#11 token protection (don't share PINs)
- Reporting suspicious activity
- PHI handling procedures

**Quarterly Security Tips (Email/Posters):**
- Month 1: "Lock your workstation when stepping away (Ctrl+Alt+L)"
- Month 2: "Never share your PKCS#11 PIN or token"
- Month 3: "Verify before clicking: Phishing emails are getting sophisticated"
- Month 4: "Report security incidents to security@example.com immediately"

---

## 12. Plan Maintenance

### 12.1 Review Schedule

| Review Type | Frequency | Owner | Trigger |
|-------------|-----------|-------|---------|
| **Full Review** | Annually | CISO | Calendar |
| **Post-Incident Review** | After each Level 1-2 incident | Incident Commander | Incident closure |
| **Regulatory Updates** | As needed | Compliance Officer | New regulations |
| **Contact Updates** | Quarterly | Security Manager | Personnel changes |
| **Tabletop Exercise** | Quarterly | Security Team | Calendar |

### 12.2 Version Control

**Document History:**

| Version | Date | Author | Changes | Approval |
|---------|------|--------|---------|----------|
| 1.0 | 2025-06-01 | Security Team | Initial version | CISO |
| 1.5 | 2025-12-15 | Security Team | Added GDPR section | CISO, Legal |
| 2.0 | 2026-02-01 | Security Team (with Claude Code assistance) | Major update: PDFSigner v2.0 HIPAA compliance, added forensic procedures, enhanced templates | CISO |

**Change Control Process:**
1. Propose changes via pull request (if IRP in version control) or email to security@example.com
2. Security Team reviews for technical accuracy
3. Compliance Officer reviews for regulatory compliance
4. CISO approves
5. Distribute updated version to all IRT members
6. Update training materials if necessary

### 12.3 Distribution List

**Internal Distribution (controlled):**
- All IRT members (primary + backup)
- Executive team (CISO, CEO, COO, CFO, General Counsel)
- IT Operations managers
- Compliance team
- Internal audit

**External Distribution (sanitized version):**
- External auditors (upon request)
- Penetration testing firms (relevant sections)
- Insurance carrier (cyber liability policy)

**Access Control:**
- Full version: Internal - Restricted (encrypted storage)
- Sanitized version: Internal - Business Sensitive (redact contact info, tool details)

---

## 13. Appendices

### A. Glossary

| Term | Definition |
|------|------------|
| **Break-Glass** | Emergency access procedure bypassing normal authentication |
| **CEF** | Common Event Format (SIEM standard) |
| **Chain of Custody** | Documented trail of evidence handling |
| **CRL** | Certificate Revocation List |
| **DSS** | Document Security Store (PAdES B-LT) |
| **HMAC** | Hash-based Message Authentication Code |
| **IRT** | Incident Response Team |
| **JSONL** | JSON Lines (newline-delimited JSON) |
| **MTTC** | Mean Time to Contain |
| **MTTD** | Mean Time to Detect |
| **MTTR** | Mean Time to Recover |
| **PAdES B-LTA** | PDF Advanced Electronic Signature - Baseline Long-Term Archival |
| **PHI** | Protected Health Information |
| **PKCS#11** | Public-Key Cryptography Standard #11 (hardware token interface) |
| **RBAC** | Role-Based Access Control |
| **SIEM** | Security Information and Event Management |

### B. Contact Information (Template)

**Emergency Contacts:**

| Role | Name | Phone (Office) | Phone (Mobile) | Email | Signal |
|------|------|----------------|----------------|-------|--------|
| Incident Commander | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |
| Security Lead | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |
| IT Operations Lead | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |
| Compliance Officer | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |
| Legal Counsel | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |
| Communications Lead | [PLACEHOLDER] | +1-XXX-XXX-XXXX | +1-XXX-XXX-XXXX | [PLACEHOLDER] | [PLACEHOLDER] |

**External Contacts:**

| Organization | Contact | Phone | Email | Account # |
|-------------|---------|-------|-------|-----------|
| FBI Cyber Division | [Local Field Office] | 1-800-CALL-FBI | [PLACEHOLDER] | N/A |
| HHS Office for Civil Rights | OCR Headquarters | 1-800-368-1019 | OCRComplaint@hhs.gov | N/A |
| Cyber Insurance Carrier | [Company Name] | 1-XXX-XXX-XXXX | claims@insurance.com | [Policy #] |
| Forensic Consultant | [Company Name] | 1-XXX-XXX-XXXX | emergency@forensics.com | [Contract #] |
| Credit Monitoring Service | [Provider] | 1-XXX-XXX-XXXX | support@provider.com | [Account #] |

### C. Quick Reference Checklist

**Level 1 Incident Response (First 60 Minutes):**

```
DETECTION (0-15 min):
[ ] Verify incident is real (not false positive)
[ ] Classify severity (Level 1 = Critical)
[ ] Note detection time: __________
[ ] Create incident ticket: INC-__________

NOTIFICATION (15-30 min):
[ ] Call Incident Commander: __________
[ ] Notify Security Lead: __________
[ ] Notify Compliance Officer: __________
[ ] Notify CISO: __________
[ ] Conference bridge activated: 1-XXX-XXX-XXXX

CONTAINMENT (30-60 min):
[ ] Disable compromised accounts: __________
[ ] Terminate suspicious sessions
[ ] Isolate affected systems (if safe to do so)
[ ] Block attacker IP addresses: __________
[ ] Enable enhanced audit logging
[ ] Document all actions in incident ticket

EVIDENCE PRESERVATION (0-60 min, parallel):
[ ] Snapshot audit logs: /secure/forensics/INC-________/
[ ] Export session data
[ ] Export emergency access records
[ ] Calculate checksums (chain of custody)
[ ] Set immutable flags
[ ] Verify audit log integrity

NEXT STEPS (60+ min):
[ ] Begin root cause analysis
[ ] Develop eradication plan
[ ] Assess PHI impact (HIPAA breach determination)
[ ] Prepare status update for executives
[ ] Schedule IRT sync (every 3 hours until contained)
```

### D. PDFSigner Command Reference

```bash
# Verify audit log integrity
uv run python -c "from pdfsigner.core.audit.audit_integrity import verify_audit_integrity; \
print(verify_audit_integrity('/path/to/audit.jsonl'))"

# Export audit events (API)
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.example.com/api/v1/audit/events?start_date=2026-01-01&end_date=2026-02-01&format=json"

# Disable user account (API)
curl -X PATCH -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/users/$USER_ID" \
  -d '{"active": false}'

# Terminate all user sessions (API)
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/sessions/user/$USER_ID"

# Check compliance status (API)
curl -H "Authorization: Bearer $TOKEN" \
  "https://api.example.com/api/v1/compliance/status"

# Restore from backup (API)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://api.example.com/api/v1/backup/restore" \
  -d '{"backup_id": "backup-20260131-120000"}'
```

---

## Document Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Author** | Security Team (with Claude Code) | _________________ | 2026-02-01 |
| **Reviewer** | Compliance Officer | _________________ | _________ |
| **Reviewer** | Legal Counsel | _________________ | _________ |
| **Approver** | CISO | _________________ | _________ |

**Next Review Date:** 2026-08-01

---

**END OF DOCUMENT**

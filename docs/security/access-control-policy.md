# Access Control Policy

## Document Control

| Field | Value |
|-------|-------|
| **Version** | 1.0 |
| **Effective Date** | 2026-02-01 |
| **Last Review** | 2026-02-01 |
| **Next Review** | 2027-02-01 |
| **Owner** | Security Officer |
| **Approved By** | [CISO/Authorizing Official] |

---

## 1. Purpose

This Access Control Policy establishes the requirements and procedures for controlling access to PDFSigner systems, applications, and data. The policy ensures that only authorized users have access to appropriate resources based on their role and business need, in compliance with HIPAA, GDPR, NIST 800-53, and organizational security requirements.

---

## 2. Scope

This policy applies to:
- All users of PDFSigner (GUI, CLI, and API)
- System administrators and security personnel
- Third-party integrators and auditors
- All PDFSigner deployments (local, server, cloud)
- All data processed by PDFSigner (documents, audit logs, credentials)

---

## 3. Policy Statements

### 3.1 General Access Control Principles

**3.1.1 Least Privilege**
Users shall be granted the minimum level of access necessary to perform their job functions. Permissions beyond those required must be explicitly justified and approved.

**3.1.2 Separation of Duties**
Critical functions shall be divided among different users to prevent fraud and error. No single user shall have permissions that allow complete control over critical processes without oversight.

**3.1.3 Need-to-Know**
Access to data and resources shall be granted only when there is a legitimate business need. Users shall not access information beyond what is required for their duties.

**3.1.4 Defense in Depth**
Multiple layers of access controls shall be implemented:
- Authentication (who you are)
- Authorization (what you can do)
- Audit (what you did)

### 3.2 Role-Based Access Control (RBAC)

**3.2.1 Standard Roles**

PDFSigner implements five standard roles with defined permissions:

| Role | Permissions | Use Case | Justification Required |
|------|-------------|----------|----------------------|
| **Viewer** | VIEW, VALIDATE | Read-only access to documents | No |
| **Signer** | VIEW, SIGN, VALIDATE, ENCRYPT, DECRYPT | Standard document signing operations | No |
| **Auditor** | VIEW, VALIDATE, AUDIT_VIEW, EXPORT | Compliance and audit review | Yes |
| **Admin** | All except EMERGENCY_ACCESS | System administration and user management | Yes |
| **Emergency** | EMERGENCY_ACCESS + temporary elevated permissions | Break-glass access for critical situations | Yes + Time-limited |

**3.2.2 Permission Definitions**

| Permission | Description | Sensitive? |
|-----------|-------------|-----------|
| VIEW | View documents and signatures | No |
| SIGN | Create digital signatures | Yes |
| VALIDATE | Verify signature validity | No |
| ENCRYPT | Encrypt PDF documents | Yes |
| DECRYPT | Decrypt PDF documents | Yes |
| EXPORT | Export reports and audit logs | Yes |
| ADMIN_USERS | Create, modify, delete user accounts | Critical |
| ADMIN_CONFIG | Modify system configuration | Critical |
| AUDIT_VIEW | View complete audit trail | Sensitive |
| EMERGENCY_ACCESS | Break-glass elevated access | Critical |

**3.2.3 Role Assignment**
- Role assignments must be approved by a System Administrator
- Role changes must be documented with business justification
- Elevated roles (Auditor, Admin, Emergency) require written approval
- All role assignments are logged to the audit trail

### 3.3 User Account Management

**3.3.1 Account Provisioning**

User accounts shall be provisioned according to the following process:

1. **Request:** Manager or authorized personnel submits access request
2. **Approval:** System Administrator approves based on role requirements
3. **Creation:** User account created with appropriate role assignment
4. **Certificate Binding:** User's X.509 certificate linked to account
5. **Notification:** User notified of account creation
6. **Documentation:** All actions logged to audit trail

**Automated Provisioning:**
- First-time PKCS#11 token users automatically receive "Signer" role
- Certificate subject used as initial username
- Admin review required within 30 days to confirm role appropriateness

**3.3.2 Account Activation**

New accounts shall:
- Remain inactive until user completes security training
- Require initial PIN/password setup
- Be bound to a specific hardware token or certificate
- Have an expiration date (if temporary access)

**3.3.3 Account Modification**

Changes to user accounts require:
- Written justification for role changes
- Admin approval for privilege escalation
- Immediate effect (no delayed implementation)
- Audit log entry with before/after states

**3.3.4 Account Deactivation**

User accounts shall be deactivated (not deleted) when:
- User separates from organization
- User changes roles and no longer requires access
- Account compromised or suspicious activity detected
- Account inactive for 90 days

**Deactivation Process:**
1. Revoke all active sessions immediately
2. Disable authentication (invalidate certificates/API keys)
3. Preserve account data for audit retention period
4. Log deactivation event with reason
5. Notify user (unless security incident)

**3.3.5 Account Deletion**

Accounts may only be deleted after:
- Audit retention period expires (6 years for HIPAA)
- Legal hold requirements satisfied
- Security Officer approval obtained
- Complete audit trail export performed

**3.3.6 Privileged Accounts**

Accounts with Admin or Emergency roles shall:
- Require written justification and approval
- Be reviewed quarterly for continued need
- Have all actions logged with enhanced detail
- Be subject to stricter password policies (if applicable)
- Require annual re-approval

### 3.4 Authentication Requirements

**3.4.1 Primary Authentication Methods**

| Method | Use Case | Requirements |
|--------|----------|--------------|
| **PKCS#11 Hardware Token** | GUI/CLI users | PIN protection, retry limit (3-5 attempts) |
| **JWT Bearer Token** | API authentication | 30-minute expiration, secure transmission (HTTPS) |
| **API Key** | Machine-to-machine | Cryptographically random (32+ bytes), secure storage |
| **mTLS Certificate** | API clients | Valid certificate chain, CRL/OCSP check |

**3.4.2 Authentication Standards**

- Hardware tokens: FIPS 140-2 Level 2 or higher (recommended)
- Certificates: RSA 2048+ or ECDSA P-256+
- API keys: 256+ bits of entropy
- JWT tokens: RS256 signing algorithm
- PIN/Password: Minimum 12 characters (if used)

**3.4.3 Multi-Factor Authentication (MFA)**

MFA is:
- **Required** for Admin and Emergency roles
- **Recommended** for Auditor role
- **Optional** for Signer and Viewer roles
- Implemented via TOTP (RFC 6238) compatible with Google Authenticator

**3.4.4 Authentication Failures**

After 5 consecutive failed authentication attempts:
- Account is automatically locked for 30 minutes
- Security Officer is notified
- User is notified (if contact information available)
- Audit event is logged

Manual unlock requires Admin approval with justification.

### 3.5 Session Management

**3.5.1 Session Establishment**

Sessions shall:
- Be created only after successful authentication
- Have unique session identifiers (32+ bytes cryptographically random)
- Be bound to user, IP address, and authentication method
- Have defined expiration times

**3.5.2 Session Timeouts**

| Environment | Idle Timeout | Maximum Duration | Warning Period |
|------------|-------------|-----------------|----------------|
| GUI (Standard) | 15 minutes | 8 hours | 2 minutes |
| GUI (Healthcare Mode) | 15 minutes | 4 hours | 2 minutes |
| API | 30 minutes | 12 hours | N/A |
| Emergency Access | 5 minutes | 4 hours | 1 minute |

**3.5.3 Concurrent Sessions**

Users are limited to:
- Standard users: 3 concurrent sessions
- Admin users: 2 concurrent sessions
- Emergency access: 1 session only

Exceeding limits terminates the oldest session.

**3.5.4 Session Termination**

Sessions shall be immediately terminated when:
- User explicitly logs out
- Idle timeout is reached
- Maximum duration is reached
- Account is deactivated or locked
- Security incident is detected
- Admin manually terminates session

All session terminations are logged.

### 3.6 Emergency Access Procedures

**3.6.1 Break-Glass Access**

Emergency access is authorized only for:
- Critical patient care situations (healthcare)
- Security incident response
- System recovery operations
- Legal/regulatory compliance requirements

**3.6.2 Emergency Access Request Process**

1. **Request Submission**
   - User submits emergency access request
   - Justification must be detailed and specific
   - Documents/resources requiring access must be identified

2. **Approval** (if required by configuration)
   - Admin reviews request immediately
   - Approval or denial documented with reason
   - Security Officer notified of all requests

3. **Access Grant**
   - Temporary elevated permissions assigned
   - Duration: 4 hours maximum (configurable 1-24 hours)
   - Cannot be extended without new request

4. **Monitoring**
   - All actions during emergency access logged with "EMERGENCY" flag
   - Real-time alerts sent to Security Officer
   - Session cannot be transferred or shared

5. **Expiration**
   - Access automatically revoked after duration
   - User returned to standard role
   - Post-access review scheduled

**3.6.3 Emergency Access Review**

Within 24 hours of emergency access expiration:
- Security Officer reviews all actions taken
- Appropriateness of access evaluated
- Anomalies or policy violations investigated
- Report generated and filed

### 3.7 Access Reviews

**3.7.1 Regular Access Reviews**

| Review Type | Frequency | Scope | Performed By |
|------------|-----------|-------|--------------|
| User Access Rights | Quarterly | All users | System Administrator |
| Privileged Access | Monthly | Admin/Auditor/Emergency roles | Security Officer |
| Emergency Access | After each use | Specific emergency session | Security Officer |
| Inactive Accounts | Monthly | Accounts with no activity for 60+ days | System Administrator |
| Certification | Annually | All access for all users | User's Manager + Admin |

**3.7.2 Access Review Process**

1. Generate access report from User Registry
2. Manager reviews each user's assigned role and permissions
3. Manager certifies appropriateness or requests changes
4. Admin implements approved changes
5. Results documented and filed

**3.7.3 Access Review Documentation**

Access reviews shall document:
- Date of review
- Reviewer name and role
- Users/accounts reviewed
- Findings (appropriate, excessive, insufficient)
- Changes implemented
- Sign-off by reviewer

### 3.8 Remote Access

**3.8.1 API Remote Access Requirements**

Remote access to PDFSigner API requires:
- TLS 1.2 or higher encryption
- Valid authentication (JWT or API key)
- Source IP restriction (optional, recommended)
- Rate limiting (60 requests/minute per client)
- Audit logging of all requests

**3.8.2 VPN Requirements**

If PDFSigner API is deployed on internal network:
- VPN connection required for remote access
- VPN must use strong encryption (AES-256)
- Multi-factor authentication required for VPN
- VPN logs integrated with PDFSigner audit trail

**3.8.3 Prohibited Remote Access**

The following are explicitly prohibited:
- Remote desktop (RDP/VNC) to PDFSigner GUI
- Unencrypted HTTP connections
- Public WiFi without VPN
- Screen sharing for PIN entry
- Shared credentials for remote access

### 3.9 Department-Based Access

**3.9.1 Department Segregation**

Organizations may implement department-based access controls:
- Users assigned to specific departments
- Documents tagged with department ownership
- Cross-department access requires approval
- Department admins manage their users

**3.9.2 Department Access Rules**

- Users can sign documents in their department by default
- Viewing documents in other departments requires VIEW permission
- Auditors have access to all departments
- Admins have access to all departments

### 3.10 API Access Control

**3.10.1 API Authentication**

All API requests must include:
- JWT bearer token (via `Authorization: Bearer` header), OR
- API key (via `X-API-Key` header), OR
- Valid mTLS client certificate

Anonymous access is prohibited.

**3.10.2 API Authorization**

Each API endpoint requires specific permissions:

| Endpoint | Required Permission |
|----------|-------------------|
| `POST /api/v1/sign/` | SIGN |
| `POST /api/v1/validate/` | VALIDATE |
| `POST /api/v1/encrypt/` | ENCRYPT |
| `GET /api/v1/audit/` | AUDIT_VIEW |
| `POST /api/v1/users/` | ADMIN_USERS |
| `PUT /api/v1/config/` | ADMIN_CONFIG |
| `POST /api/v1/emergency/` | EMERGENCY_ACCESS |

**3.10.3 Rate Limiting**

API rate limits:
- Authenticated users: 60 requests/minute, 1000 requests/hour
- Per endpoint: 30 requests/minute
- Burst allowance: 10 requests
- Exceeded limits: 429 Too Many Requests response

**3.10.4 API Key Management**

API keys shall:
- Be generated with 256+ bits of entropy
- Be stored securely (environment variables, key vault)
- Have optional expiration dates
- Be rotatable without service interruption
- Be revocable immediately if compromised
- Have descriptive names (e.g., "Production CI/CD Pipeline")

---

## 4. Roles and Responsibilities

### 4.1 System Administrator

- Provision and deprovision user accounts
- Assign and modify user roles
- Perform quarterly access reviews
- Investigate access-related incidents
- Maintain documentation of access decisions
- Approve emergency access requests

### 4.2 Security Officer

- Define and update access control policies
- Review privileged account activity monthly
- Investigate access violations
- Approve Admin and Auditor role assignments
- Conduct annual access certification
- Report access control metrics to management

### 4.3 User Manager

- Request access for team members
- Certify access appropriateness annually
- Report role changes promptly
- Ensure terminated employees' access removed
- Document business justification for access requests

### 4.4 End Users

- Protect authentication credentials (PINs, API keys)
- Report lost/stolen hardware tokens immediately
- Do not share accounts or credentials
- Log out when finished
- Report suspicious access attempts
- Complete annual security training

### 4.5 Auditors

- Monitor access control effectiveness
- Review access logs for anomalies
- Report access control deficiencies
- Maintain independence (no access to production signing)
- Verify compliance with this policy

---

## 5. Enforcement

### 5.1 Violations

Violations of this policy include:
- Sharing credentials or accounts
- Attempting unauthorized access
- Failing to report lost/stolen tokens
- Abusing emergency access procedures
- Circumventing access controls
- Failing to complete access reviews

### 5.2 Consequences

| Violation Severity | First Offense | Second Offense | Third Offense |
|-------------------|---------------|----------------|---------------|
| **Minor** (e.g., late access review) | Written warning | Documented warning | Privilege suspension |
| **Moderate** (e.g., sharing credentials) | Privilege suspension | Privilege revocation | Termination referred |
| **Severe** (e.g., unauthorized access) | Immediate suspension | Termination referred | Legal action |

### 5.3 Incident Response

Access control violations trigger:
1. Immediate investigation by Security Officer
2. Preservation of audit logs as evidence
3. Temporary suspension of involved accounts
4. Management notification
5. Remediation plan development
6. Policy/control updates as needed

---

## 6. Compliance and Audit

### 6.1 Regulatory Mapping

| Regulation | Requirement | Policy Section |
|-----------|-------------|---------------|
| HIPAA §164.312(a)(1) | Access control | 3.2, 3.3 |
| HIPAA §164.312(a)(2)(i) | Unique user ID | 3.3.1 |
| HIPAA §164.312(a)(2)(ii) | Emergency access | 3.6 |
| HIPAA §164.312(a)(2)(iii) | Auto logoff | 3.5.2 |
| HIPAA §164.312(d) | Person authentication | 3.4 |
| NIST 800-53 AC-2 | Account management | 3.3 |
| NIST 800-53 AC-3 | Access enforcement | 3.2 |
| NIST 800-53 AC-7 | Unsuccessful logon attempts | 3.4.4 |
| NIST 800-53 AC-11 | Session lock | 3.5.2 |
| NIST 800-53 AC-12 | Session termination | 3.5.4 |
| GDPR Art. 32 | Security of processing | 3.1, 3.4 |

### 6.2 Audit Evidence

Compliance with this policy is demonstrated through:
- User Registry database exports
- Audit log records (LOGIN, LOGOUT, PERMISSION_DENIED events)
- Access review documentation
- Role assignment approvals
- Emergency access justifications
- Session timeout configurations
- Authentication failure logs

### 6.3 Metrics and Reporting

Monthly metrics shall include:
- Total active users by role
- Privileged account count
- Failed authentication attempts
- Account lockouts
- Emergency access uses
- Access review completion rate
- Average session duration

---

## 7. Exceptions

### 7.1 Exception Request Process

Exceptions to this policy require:
1. Written justification with business need
2. Risk assessment by Security Officer
3. Compensating controls identified
4. Time-limited approval (maximum 6 months)
5. Executive approval for critical exceptions
6. Documented review before expiration

### 7.2 Temporary Elevated Access

Temporary elevated access (non-emergency) may be granted for:
- Audit support (Auditor role for limited time)
- Training and demonstrations
- Troubleshooting and support
- Project-based needs

Requires Admin approval and is limited to 30 days maximum.

---

## 8. Related Documents

- System Security Plan (SSP)
- Audit and Accountability Policy
- Incident Response Plan
- Acceptable Use Policy
- Security Awareness Training Materials
- User Onboarding Checklist

---

## 9. Policy Maintenance

### 9.1 Review Schedule

This policy shall be reviewed:
- Annually (scheduled)
- After significant security incidents
- When regulatory requirements change
- When system capabilities change
- After failed audits

### 9.2 Approval Authority

Changes to this policy require approval from:
- Security Officer (policy owner)
- System Administrator (implementation)
- Legal/Compliance (regulatory alignment)
- CISO or designee (final approval)

### 9.3 Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-01 | Security Team | Initial release |

---

## 10. Appendix: Access Request Form Template

```
ACCESS REQUEST FORM

Requestor Information:
  Name: _______________________
  Email: ______________________
  Department: _________________
  Manager: ____________________

Access Details:
  User Account: ________________
  Requested Role: [ ] Viewer  [ ] Signer  [ ] Auditor  [ ] Admin  [ ] Emergency
  Additional Permissions: ______________________________

  Justification:
  _______________________________________________________________
  _______________________________________________________________

  Duration:  [ ] Permanent  [ ] Temporary (specify end date: ______)

Approvals:
  Manager Signature: _____________________ Date: __________
  Admin Signature: _______________________ Date: __________
  Security Officer (if elevated): _________ Date: __________

Implementation:
  Account Created: _____________ (date)
  Role Assigned: ______________ (date)
  User Notified: ______________ (date)
  Implemented By: _____________ (admin name)
```

---

**Policy Owner:** Security Officer
**Approved By:** [CISO/Authorizing Official]
**Effective Date:** 2026-02-01
**Next Review:** 2027-02-01

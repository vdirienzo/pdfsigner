# System Security Plan (SSP)

## PDFSigner Digital Signature Platform

---

## Document Control

| Field | Value |
|-------|-------|
| **Document Title** | System Security Plan |
| **System Name** | PDFSigner |
| **Version** | 1.0 |
| **Date** | 2026-02-01 |
| **Classification** | Confidential |
| **Owner** | Security Officer |
| **Status** | Draft |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-01 | Security Team | Initial draft |

---

## Approvals

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Information System Owner | [Name] | ___________ | _______ |
| Authorizing Official | [Name] | ___________ | _______ |
| Chief Information Security Officer | [Name] | ___________ | _______ |

---

## Table of Contents

1. [System Description](01-system-description.md)
2. [Security Objectives](02-security-objectives.md)
3. [System Environment](03-system-environment.md)
4. [System Interconnections](04-system-interconnections.md)
5. [Control Implementation](05-control-implementation/)
   - Access Control (AC)
   - Audit and Accountability (AU)
   - Identification and Authentication (IA)
   - System and Communications Protection (SC)
   - [Additional families...]
6. [Contingency Plan](06-contingency-plan.md)
7. [Appendices](07-appendices/)

---

## Executive Summary

PDFSigner is a digital PDF signing platform designed for regulated environments requiring HIPAA, NIST 800-53, FedRAMP, and eIDAS compliance. This System Security Plan documents the security controls implemented to protect the confidentiality, integrity, and availability of the system and the data it processes.

### Key Security Features

- **Authentication**: Multi-factor authentication (TOTP + backup codes), PKCS#11 token support
- **Authorization**: Role-Based Access Control (5 roles, 10+ permissions)
- **Cryptography**: FIPS 140-2 validated algorithms, AES-256 encryption
- **Audit**: HMAC-signed audit logs with tamper detection, SIEM integration
- **Signatures**: PAdES B-LTA compliant digital signatures
- **Compliance**: HIPAA, eIDAS, GDPR, NIST 800-53 controls implemented

### Impact Level

| Impact Category | Level |
|-----------------|-------|
| Confidentiality | MODERATE |
| Integrity | MODERATE |
| Availability | LOW |
| **Overall** | **MODERATE** |

---

## FedRAMP Authorization Boundary

The authorization boundary includes:

- PDFSigner application (GUI, CLI, API)
- REST API server (FastAPI)
- SQLite databases (audit, MFA, users)
- Configuration files
- Temporary file storage
- Integration with external TSA services

The boundary excludes:

- Client workstations
- PKCS#11 tokens/HSMs (separate authorization)
- External timestamp authorities
- Network infrastructure

---

*This document is part of the PDFSigner FedRAMP authorization package.*

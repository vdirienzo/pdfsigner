# 1. System Description

## 1.1 System Overview

PDFSigner is a digital PDF signing platform that enables organizations to create legally binding electronic signatures compliant with PAdES (PDF Advanced Electronic Signatures) standards, EU eIDAS regulation, and US federal requirements.

### 1.1.1 System Purpose

The system provides:

1. **Digital Signature Creation**: PAdES B-B, B-T, B-LT, and B-LTA level signatures
2. **Signature Validation**: Verification of existing signatures with revocation checking
3. **Certificate Management**: PKCS#11 token integration for secure key storage
4. **Audit Trail**: Comprehensive logging with tamper detection
5. **Electronic Seals**: Organization-level seals per eIDAS Article 35-40

### 1.1.2 System Type

| Attribute | Value |
|-----------|-------|
| **Deployment Model** | On-premises / Private Cloud |
| **Service Model** | Software |
| **Data Classification** | CUI / PHI / PII |
| **FISMA Impact Level** | Moderate |

## 1.2 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Authorization Boundary                      │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │   PDFSigner      │  │   REST API       │  │   CLI         │ │
│  │   GUI (GTK4)     │  │   (FastAPI)      │  │   Interface   │ │
│  └────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘ │
│           │                      │                    │          │
│           └──────────────────────┼────────────────────┘          │
│                                  │                               │
│                    ┌─────────────▼─────────────┐                │
│                    │      Core Services        │                │
│                    │  ┌─────────────────────┐  │                │
│                    │  │ Signer (pyHanko)    │  │                │
│                    │  │ Validator           │  │                │
│                    │  │ Encryptor (AES-256) │  │                │
│                    │  │ Audit Logger        │  │                │
│                    │  └─────────────────────┘  │                │
│                    └─────────────┬─────────────┘                │
│                                  │                               │
│  ┌───────────────┐  ┌───────────▼────────────┐  ┌────────────┐ │
│  │   PKCS#11     │  │      Data Stores       │  │   Config   │ │
│  │   (NSS/HSM)   │  │  ┌──────────────────┐  │  │   (TOML)   │ │
│  │               │◄─┤  │ Audit (SQLite)   │  │  │            │ │
│  │               │  │  │ Users (SQLite)   │  │  │            │ │
│  │               │  │  │ MFA (SQLite)     │  │  │            │ │
│  └───────────────┘  │  │ Sessions         │  │  └────────────┘ │
│                     │  └──────────────────┘  │                  │
│                     └────────────────────────┘                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    External Services      │
                    │  (Outside Boundary)       │
                    │  ┌─────────────────────┐  │
                    │  │ TSA (Timestamp)     │  │
                    │  │ OCSP (Revocation)   │  │
                    │  │ CRL (Distribution)  │  │
                    │  │ EU TSL (eIDAS)      │  │
                    │  └─────────────────────┘  │
                    └───────────────────────────┘
```

## 1.3 Software Components

### 1.3.1 Core Modules

| Module | Purpose | Technology |
|--------|---------|------------|
| `core/signer/` | PDF signing engine | pyHanko, cryptography |
| `core/validator/` | Signature validation | pyHanko |
| `core/encryption/` | Document encryption | PyMuPDF, AES-256 |
| `core/audit/` | Audit logging | SQLite, HMAC-SHA256 |
| `core/auth/` | Authentication | Argon2, TOTP |
| `core/eidas/` | eIDAS compliance | X.509, TSL |
| `core/rbac/` | Access control | Custom RBAC |
| `api/` | REST API | FastAPI |
| `gui/` | Desktop interface | GTK4, libadwaita |

### 1.3.2 External Dependencies

| Component | Version | Purpose | License |
|-----------|---------|---------|---------|
| Python | 3.12+ | Runtime | PSF |
| pyHanko | 0.25+ | PDF signing | MIT |
| cryptography | 41+ | Crypto ops | BSD |
| FastAPI | 0.100+ | REST API | MIT |
| GTK4 | 4.12+ | GUI | LGPL |
| SQLite | 3.35+ | Data storage | Public Domain |
| pyotp | 2.9+ | TOTP MFA | MIT |
| argon2-cffi | 21+ | Password hashing | MIT |

## 1.4 Data Flow

### 1.4.1 Signature Creation Flow

```
User → GUI/API → Authentication → Authorization Check →
  → PDF Load → Field Creation → Signature Creation →
  → PKCS#11 Signing → Timestamp Request (TSA) →
  → DSS Embedding (LTV) → Archive Timestamp (LTA) →
  → Output PDF → Audit Log
```

### 1.4.2 Data Types Processed

| Data Type | Sensitivity | Encryption | Retention |
|-----------|-------------|------------|-----------|
| PDF Documents | HIGH | At-rest optional | User-controlled |
| Digital Signatures | HIGH | Within PDF | Permanent |
| Audit Logs | MEDIUM | HMAC integrity | 90 days default |
| User Credentials | HIGH | Argon2 hashed | Active duration |
| MFA Secrets | HIGH | Base64 (MVP) | Active duration |
| Session Data | MEDIUM | Memory only | 15 min timeout |

## 1.5 User Categories

### 1.5.1 Internal Users

| Role | Description | Permissions |
|------|-------------|-------------|
| ADMIN | System administrator | All permissions |
| AUDITOR | Compliance reviewer | Read audit logs, generate reports |
| SIGNER | Document signer | Sign, validate documents |
| VIEWER | Read-only access | View signatures, reports |
| OPERATOR | Batch operations | Bulk signing, validation |

### 1.5.2 External Interfaces

| Interface | Type | Authentication |
|-----------|------|----------------|
| REST API | HTTPS | JWT / API Key |
| CLI | Local | System user |
| GUI | Desktop | PKCS#11 PIN + optional MFA |

## 1.6 Network Interfaces

### 1.6.1 Inbound Connections

| Port | Protocol | Purpose | Authentication |
|------|----------|---------|----------------|
| 8000 | HTTPS | REST API | JWT/API Key |
| 8443 | HTTPS | REST API (TLS) | mTLS optional |

### 1.6.2 Outbound Connections

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| TSA servers | HTTPS | RFC 3161 timestamps |
| OCSP responders | HTTP/HTTPS | Revocation checking |
| CRL distribution | HTTP/HTTPS | Revocation lists |
| EU LOTL | HTTPS | eIDAS TSL updates |

## 1.7 Security Controls Summary

### 1.7.1 Technical Controls

| Control Area | Implementation |
|--------------|----------------|
| **Authentication** | PKCS#11 + PIN, Password (Argon2), MFA (TOTP) |
| **Authorization** | RBAC with 5 roles, permission-based access |
| **Encryption** | AES-256 (documents), TLS 1.2+ (transport) |
| **Integrity** | HMAC-SHA256 (audit logs), SHA-256/384/512 (signatures) |
| **Non-repudiation** | Digital signatures, timestamps |
| **Audit** | Comprehensive logging with chain hashing |

### 1.7.2 Operational Controls

| Control Area | Implementation |
|--------------|----------------|
| **Session Management** | 15-minute timeout, concurrent session limits |
| **Account Lockout** | 5 failed attempts, 30-minute duration |
| **Password Policy** | 12+ chars, complexity, 12 history, 90-day expiry |
| **Emergency Access** | Break-glass with admin approval, 4-hour duration |

### 1.7.3 Compliance Status

| Standard | Coverage | Key Controls |
|----------|----------|--------------|
| HIPAA | 97% | Encryption, audit, access control |
| NIST 800-53 | 78% | All 17 families addressed |
| eIDAS | 95% | QES validation, TSL integration |
| GDPR | 90% | Data portability, erasure |
| PAdES | 95% | B-B, B-T, B-LT, B-LTA |

---

*Section 2: [Security Objectives](02-security-objectives.md)*

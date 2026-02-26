# eIDAS 2 Implementation Plan — PDFSigner

> **Regulation:** EU 2024/1183 (amending EU 910/2014)
> **Created:** 2026-02-26
> **Target:** Full eIDAS 2 compliance by Q1 2027

---

## Executive Summary

PDFSigner has solid eIDAS 1 foundations (~85%) but critical gaps for eIDAS 2 (~40%).
This plan addresses gaps in 6 phases over ~17 weeks (14 with parallelism).

**Key discovery:** pyHanko 0.30.0+ already implements EUTL validation, QcStatements
evaluation, and CSC API signing — we're on >=0.21.0 and not leveraging these features.

### Deadlines

| Date | Milestone | Impact |
|------|-----------|--------|
| **Apr 29, 2026** | TLv6 mandatory (ETSI TS 119 612 V2.3.1+) | Phases 0+1 MUST complete |
| ~Mar 2026 | ETSI TS 119 432 v1.3.1 (CSC API v2 aligned) | Phase 3 reference |
| Already in force | CIR 2025/1929, 1942, 1945, 1946 | Phases 2+3 requirements |
| End 2026 | EU Member States must offer EUDI Wallets | Phase 5 target |
| End 2027 | Mandatory acceptance by VLOPs + financial institutions | Full compliance |

### Architecture Overview

```
Current:    PKCS#11 Token → PDFSigner → PAdES-LTA (local only)
                                      → Custom LOTL/TSL (incomplete)
                                      → Heuristic QcStatements (unreliable)

Target:     PKCS#11 Token ─┐
            CSC API v2 ────┤→ PDFSigner → PAdES-LTA
            EUDI Wallet ───┘             → pyHanko EUTL (TLv6, all EU/EEA)
                                         → ASN.1 QcStatements (real parsing)
                                         → CIR 2025/1945 validation
                                         → Validation reports (TS 119 102-2)
```

---

## Phase 0: Foundation Fixes

> **Priority:** URGENT | **Duration:** 3 weeks | **Deadline:** March 15, 2026
> **Goal:** Fix critical bugs in existing eIDAS 1 implementation

### Why First

The current implementation has **4 critical defects** that make eIDAS validation
unreliable. These must be fixed before any eIDAS 2 work because all subsequent
phases depend on correct certificate analysis and revocation checking.

### Tasks

#### 0.1 — Real QcStatements ASN.1 Parsing

**Standard:** ETSI EN 319 412-5 V2.5.1 (2025-06)
**File:** `src/pdfsigner/core/eidas/qualified_validator.py` (lines 460-523)
**Problem:** Uses heuristics (subject DN keywords, hardcoded issuer names) instead
of ASN.1 parsing. The code itself acknowledges: *"This is a simplified check —
production would need ASN.1 parsing"*.

**Implementation:**
```python
# Using asn1crypto (already transitive dep via pyHanko)
from asn1crypto import core, x509

class QcStatement(core.Sequence):
    _fields = [
        ('statement_id', core.ObjectIdentifier),
        ('statement_info', core.Any, {'optional': True}),
    ]

class QcStatements(core.SequenceOf):
    _child_spec = QcStatement
```

**New file:** `src/pdfsigner/core/eidas/qc_statements_parser.py`

**OIDs to parse (arc 0.4.0.1862.1.x):**

| OID | Name | Data Type |
|-----|------|-----------|
| 0.4.0.1862.1.1 | QcCompliance | None (presence = True) |
| 0.4.0.1862.1.2 | QcLimitValue | SEQUENCE {currency, amount, exponent} |
| 0.4.0.1862.1.3 | QcRetentionPeriod | INTEGER |
| 0.4.0.1862.1.4 | QcSSCD | None (presence = True) |
| 0.4.0.1862.1.5 | QcPDS | SEQUENCE OF {url, language} |
| 0.4.0.1862.1.6 | QcType | SEQUENCE OF OID |
| 0.4.0.1862.1.7 | QcCClegislation | SEQUENCE OF PrintableString |

**Sub-OIDs for QcType:**
- 0.4.0.1862.1.6.1 → esign (electronic signature)
- 0.4.0.1862.1.6.2 → eseal (electronic seal)
- 0.4.0.1862.1.6.3 → web (website authentication)

**Acceptance criteria:**
- [ ] All 7 QcStatement OIDs parsed correctly from real certificate DER bytes
- [ ] QcType sub-OIDs (esign/eseal/web) resolved correctly
- [ ] Graceful handling of unknown/malformed QcStatements
- [ ] Zero hardcoded issuer name fallbacks remaining
- [ ] 100% backward compatibility: existing tests still pass

---

#### 0.2 — Wire RevocationChecker into QualifiedSignatureValidator

**Standard:** CIR 2025/1945 (revocation freshness: max 24h)
**File:** `src/pdfsigner/core/eidas/qualified_validator.py` (line 285)
**Problem:** `_check_revocation()` is a stub that always returns `True`.

**Implementation:**
- Import existing `RevocationChecker` from `core/certificate/revocation_checker.py`
- Extract issuer certificate from the signature's certificate chain
- Call `RevocationChecker.check_revocation(cert, issuer_cert)`
- Respect `settings.revocation_check_enabled`
- If revocation check fails and `ltv_fail_open=False` → mark as INDETERMINATE
- If revocation check fails and `ltv_fail_open=True` → warn but continue

**Files to modify:**
- `src/pdfsigner/core/eidas/qualified_validator.py`
- `tests/unit/test_eidas.py`
- `tests/unit/test_eidas_production.py`

**Acceptance criteria:**
- [ ] `_check_revocation()` actually checks OCSP/CRL
- [ ] Issuer certificate correctly extracted from chain
- [ ] Revoked certificate → QES validation returns INVALID
- [ ] Network failure with fail_open=True → INDETERMINATE (not VALID)
- [ ] Network failure with fail_open=False → INVALID

---

#### 0.3 — Integrate QualifiedSignatureValidator into PDFValidator

**File:** `src/pdfsigner/core/validator/pdf_validator.py`
**Problem:** PDFValidator and QualifiedSignatureValidator are completely decoupled.
Main validation never checks eIDAS qualification level.

**Implementation:**
- After standard signature validation, if `settings.eidas_enabled`:
  - Run `QualifiedSignatureValidator.validate_signature_level()` per signature
  - Add `eidas_level` field to `SignatureValidationResult` (QES/AdES-QC/AdES/Basic)
  - Add `qualified_tsp` field (TSP name from EUTL, if found)
- Result enrichment, not replacement of existing validation

**Files to modify:**
- `src/pdfsigner/core/validator/pdf_validator.py`
- `src/pdfsigner/core/eidas/qualified_validator.py`
- `tests/unit/test_eidas.py`

**Acceptance criteria:**
- [ ] `validate()` returns eIDAS level when `eidas_enabled=True`
- [ ] `validate()` behavior unchanged when `eidas_enabled=False`
- [ ] GUI shows qualification level in validation results
- [ ] No performance degradation when eIDAS disabled

---

#### 0.4 — Expand TSP Registry to All EU/EEA

**File:** `src/pdfsigner/core/eidas/tsp_registry.py` (line 172)
**Problem:** Hard-limited to 8 countries (DE, FR, IT, ES, NL, BE, AT, PL).
Missing 19+ EU member states and EEA countries.

**Implementation:**
- Remove `PRIORITY_COUNTRIES` hard limit
- Fetch ALL TSL pointers from LOTL
- Add configurable country filter via `settings.eidas_eutl_territories`
- Add progress callback for GUI (loading 27+ TSLs takes time)
- Parallel fetching with configurable concurrency

**New setting:** `eidas_eutl_territories: list[str] = []` (empty = all EU/EEA)

**Acceptance criteria:**
- [ ] All 27 EU member states + EEA fetched when no filter
- [ ] Country filter works correctly
- [ ] Progress callback fires for GUI
- [ ] Graceful handling of individual country TSL fetch failures

---

#### 0.5 — Foundation Tests

**New/modified test files:**
- `tests/unit/test_qc_statements_parser.py` (NEW)
- `tests/unit/test_eidas.py` (modify)
- `tests/unit/test_eidas_production.py` (modify)

**Test certificates needed:**
- Certificate with QcCompliance + QcSSCD + QcType=esign (typical QES cert)
- Certificate with QcCompliance + QcType=eseal (qualified seal cert)
- Certificate with QcCompliance only (AdES-QC cert, no QSCD)
- Certificate with no QcStatements extension (non-qualified)
- Certificate with malformed QcStatements (error handling)

**Acceptance criteria:**
- [ ] Each QcStatement OID tested individually
- [ ] Edge cases: empty extension, unknown OIDs, truncated data
- [ ] Revocation integration tested with mock OCSP/CRL responders
- [ ] PDFValidator + QualifiedSignatureValidator integration tested

---

## Phase 1: pyHanko EUTL Integration

> **Priority:** CRITICAL | **Duration:** 3 weeks | **Deadline:** April 15, 2026
> **Goal:** Replace custom TSL code with pyHanko's native EUTL support
> **Hard deadline:** TLv6 mandatory April 29, 2026 — no transition period

### Why

pyHanko 0.30.0+ implements EU Trusted Lists with:
- XML signature validation (our code doesn't validate!)
- FileSystemTLCache with automatic refresh
- `lotl_to_registry()` for building trust anchors
- TLv6 format support (ETSI TS 119 612 V2.3.1+)
- AdES validation engine per EN 319 102-1

We're on pyHanko >=0.21.0. Upgrading gives us all this for free.

### Tasks

#### 1.1 — Upgrade pyHanko to >=0.33.0

**File:** `pyproject.toml`

**Changes:**
```toml
dependencies = [
    "pyhanko[pkcs11,etsi]>=0.33.0",  # was: "pyhanko[pkcs11]>=0.21.0"
    # etsi extras: xsdata, aiohttp
]
```

**Risk:** 12 minor versions gap (0.21 → 0.33). Breaking changes possible.
**Mitigation:** Review pyHanko CHANGELOG, run full test suite, fix deprecations.

**Acceptance criteria:**
- [ ] `pyproject.toml` updated with `pyhanko[pkcs11,etsi]>=0.33.0`
- [ ] `uv lock` succeeds
- [ ] All existing tests pass (or are updated for API changes)
- [ ] Signing flow works: PAdES B-B/T/LT/LTA
- [ ] Validation flow works

---

#### 1.2 — Replace Custom LOTL/TSL with pyHanko EUTL

**Standard:** ETSI TS 119 612 V2.3.1+ (TLv6)
**New file:** `src/pdfsigner/core/eidas/eutl_adapter.py`

**Implementation:**
```python
from pyhanko.sign.validation.qualified.eutl_fetch import (
    FileSystemTLCache,
    lotl_to_registry,
)
from pyhanko.sign.validation.qualified.tsp import TSPTrustManager

class EUTLAdapter:
    """Adapter between pyHanko EUTL and PDFSigner's EUTSPRegistry interface."""

    async def initialize(self, territories: list[str] | None = None):
        cache_dir = Path("~/.config/pdfsigner/eutl_cache").expanduser()
        self.tl_cache = FileSystemTLCache(
            str(cache_dir),
            expire_after=timedelta(days=settings.eidas_cache_days)
        )
        self.registry, errors = await lotl_to_registry(
            client, self.tl_cache,
            only_territories=",".join(territories) if territories else None
        )
        self.trust_manager = TSPTrustManager(tsp_registry=self.registry)
```

**Deprecate (keep for fallback):**
- `src/pdfsigner/core/eidas/lotl_fetcher.py`
- `src/pdfsigner/core/eidas/tsl_parser.py`

**Keep and adapt:**
- `src/pdfsigner/core/eidas/tsp_registry.py` → thin wrapper over EUTLAdapter

**Acceptance criteria:**
- [ ] LOTL loads with XML signature validation (pyHanko built-in)
- [ ] All EU/EEA country TSLs fetched
- [ ] Cache works (FileSystemTLCache)
- [ ] Existing `EUTSPRegistry` interface preserved for backward compat
- [ ] TLv6 format handled correctly

---

#### 1.3 — Use pyHanko AdES Validation Engine

**Standard:** ETSI EN 319 102-1 V1.4.1 (2024-06)
**File:** `src/pdfsigner/core/validator/pdf_validator.py`

**Implementation:**
- Replace custom PAdES level detection with pyHanko's `ades_lta_validation()`
- Use pyHanko's trust anchors from EUTL (from Task 1.2)
- Get AdES validation status directly from pyHanko

**Acceptance criteria:**
- [ ] PAdES level detection matches pyHanko's determination
- [ ] Trust anchors from EUTL used in validation
- [ ] Validation results include AdES status

---

#### 1.4 — TLv6 Compliance Verification

**Standard:** ETSI TS 119 612 V2.3.1 (2024-11) → V2.4.1 (2025-08)
**Deadline:** April 29, 2026

**Implementation:**
- Verify pyHanko 0.33.0 handles TLv6 format
- Test with current live EU LOTL
- If issues found, contribute patches or work around

**Acceptance criteria:**
- [ ] Live EU LOTL loads successfully
- [ ] At least 3 country TSLs (DE, FR, ES) parse correctly
- [ ] New TLv6 fields (ServiceSupplyPoint) accessible

---

#### 1.5 — Settings and Migration

**Files:**
- `src/pdfsigner/config/settings.py`
- `src/pdfsigner/gui/settings_pages/validation_page.py`

**New settings:**
```python
eidas_eutl_territories: list[str] = []      # Empty = all EU/EEA
eidas_validation_mode: str = "eutl"          # "eutl" | "custom" | "offline"
eidas_eutl_cache_dir: str = "~/.config/pdfsigner/eutl_cache"
```

**Migration:**
- Move old cache (`~/.pdfsigner/eidas_cache/`) to new location
- Preserve user's eIDAS settings

**Acceptance criteria:**
- [ ] New settings exposed in GUI
- [ ] Old cache migrated on first run
- [ ] Settings backward-compatible

---

## Phase 2: CIR 2025/1945 Standardized Validation

> **Priority:** HIGH | **Duration:** 3 weeks | **Target:** May 30, 2026
> **Goal:** Implement EU standardized validation procedure
> **Depends on:** Phase 1

### Standards

| Standard | Purpose |
|----------|---------|
| CIR (EU) 2025/1945 | Validation procedure for QES/QESeal/AdES-QC |
| ETSI EN 319 102-1 V1.4.1 | AdES creation and validation procedures |
| ETSI TS 119 102-2 V1.4.1 | Signature Validation Report format |
| ETSI TS 119 172-4 V1.1.1 | Validation policy using Trusted Lists |

### Tasks

#### 2.1 — Validation Procedure per CIR 2025/1945

**File:** `src/pdfsigner/core/validator/eidas_validator.py` (NEW)

**Requirements from CIR 2025/1945:**
- Revocation freshness: max **24 hours** for signing certificate revocation data
- **eitherCheck** for non-trust-anchor certificates (OCSP OR CRL, either suffices)
- Chain building to trust anchors extracted from EUTL
- Algorithm strength per SOGIS Agreed Cryptographic Mechanisms

**SOGIS Algorithm Policy:**

| Type | Accepted | Rejected |
|------|----------|----------|
| Hash | SHA-256, SHA-384, SHA-512 | SHA-1 (creation), MD5 |
| RSA | ≥2048 bits (PSS preferred) | <2048 bits |
| ECDSA | P-256, P-384, P-521 | <P-256 |
| EdDSA | Ed25519, Ed448 | — |

**Acceptance criteria:**
- [ ] 24h revocation freshness enforced
- [ ] eitherCheck mode works (OCSP fallback to CRL)
- [ ] Algorithm strength validated
- [ ] Weak algorithm → validation warning/failure (configurable)

---

#### 2.2 — Validation Reports per ETSI TS 119 102-2

**File:** `src/pdfsigner/core/validator/validation_report.py` (NEW)

**Implementation:**
- Use pyHanko's AdES validation report generation (etsi extras)
- Output structured JSON report including:
  - Signature status (TOTAL-PASSED / TOTAL-FAILED / INDETERMINATE)
  - Qualification level (QES / AdES-QC / AdES / not determined)
  - Certificate chain details
  - Timestamp validation
  - Revocation status and freshness
  - Algorithm strength assessment

**Acceptance criteria:**
- [ ] JSON report generated for each validation
- [ ] Report includes all required fields per TS 119 102-2
- [ ] Reports can be exported from GUI and API

---

#### 2.3 — Validation Policy per ETSI TS 119 172-4

**File:** `src/pdfsigner/core/validator/validation_policy.py` (NEW)

**Implementation:**
- Define signature applicability rules using EUTL
- Configurable policy constraints:
  - Minimum signature level (QES / AdES-QC / AdES / any)
  - Required PAdES level (B-LTA / B-LT / B-T / any)
  - Algorithm whitelist/blacklist
  - TSP country restrictions
- Default policy: accept QES and AdES-QC from any EU QTSP

**Acceptance criteria:**
- [ ] Validation policy configurable via settings
- [ ] Policy enforcement in validation flow
- [ ] Clear error messages when policy violated

---

#### 2.4 — Expose eIDAS Validation in REST API

**File:** `src/pdfsigner/api/routes/validate.py`
**File:** `src/pdfsigner/api/routes/compliance.py`

**New endpoints:**
- `POST /api/v1/validate/eidas` — Qualified signature validation
  - Input: PDF file
  - Output: Per-signature eIDAS level, EUTL status, validation report
- Update `GET /api/v1/compliance/standards` to include `"eIDAS"`

**Acceptance criteria:**
- [ ] `/api/v1/validate/eidas` returns qualification levels
- [ ] `/api/v1/compliance/standards` lists eIDAS
- [ ] OpenAPI docs updated

---

#### 2.5 — Update Compliance Checker

**File:** `src/pdfsigner/core/compliance/checker.py` (lines 1517-1641)
**File:** `src/pdfsigner/core/compliance/controls.py` (lines 503-547)

**Problem:** Current eIDAS checks only verify settings are enabled, not actual validation.

**Implementation:**
- Replace settings-based checks with real EUTL verification
- Add new controls:
  - `eIDAS-CIR2025-1945`: CIR 2025/1945 validation procedure compliance
  - `eIDAS-TLv6`: TLv6 Trusted Lists support
  - `eIDAS-SOGIS`: Algorithm strength compliance

**Acceptance criteria:**
- [ ] Compliance checks run real validation, not just settings checks
- [ ] New CIR 2025/1945 control implemented
- [ ] Compliance report accurately reflects eIDAS status

---

#### 2.6 — Comprehensive Validation Tests

**New file:** `tests/unit/test_eidas_validation.py`
**New file:** `tests/integration/test_eutl_validation.py` (optional, needs network)

**Test scenarios:**
- QES signature from known QTSP (e.g., Bundesdruckerei, DigiCert EU)
- AdES-QC signature (qualified cert, no QSCD)
- Non-qualified signature → correctly identified as Basic/AdES
- Revoked certificate → validation fails
- Expired revocation data (>24h) → freshness violation
- Weak algorithm (SHA-1) → algorithm warning
- Missing EUTL → graceful degradation

**Acceptance criteria:**
- [ ] All validation scenarios tested
- [ ] Integration test with live EUTL (behind `--network` flag)
- [ ] Validation report output verified

---

## Phase 3: Remote Signing via CSC API v2

> **Priority:** MEDIUM-HIGH | **Duration:** 5 weeks | **Target:** July 30, 2026
> **Goal:** Enable qualified remote signing through cloud QTSPs
> **Depends on:** Phase 1 | **Parallel with:** Phase 4

### Standards

| Standard | Purpose |
|----------|---------|
| CSC API V2.2 (Nov 2025) | Cloud Signature Consortium protocol |
| ETSI TS 119 432 V1.2.1 (current) / V1.3.1 (~Mar 2026) | Remote digital signature creation |
| ETSI TS 119 431-1 | TSP security requirements for signing components |
| CEN EN 419 241-1/2 | Trustworthy server signing / SAM for remote QSCD |
| CIR (EU) 2025/1567 | Management of remote QSCDs |

### CSC API v2.2 Endpoints

```
Base: https://<service>/csc/v2/

POST /info                          # Service capabilities
POST /oauth2/authorize              # Authorization Code flow
POST /oauth2/pushed_authorize       # Pushed Authorization Request (PAR)
POST /oauth2/token                  # Get access token
POST /credentials/list              # List signing certificates
POST /credentials/info              # Certificate details
POST /credentials/authorize         # Authorize credential use
POST /credentials/getChallenge      # Get auth challenge
POST /credentials/sendOTP           # Send OTP to user
POST /signatures/signHash           # Sign pre-computed hash(es)
POST /signatures/signDoc            # Sign document directly
POST /signatures/signPolling        # Poll async sign status
POST /signatures/timestamp          # Request timestamp token
```

### Tasks

#### 3.1 — CSC API v2 Client Module

**New file:** `src/pdfsigner/core/remote/csc_client.py`

**Implementation:**
- Async HTTP client using `aiohttp`
- All CSC API v2.2 endpoints
- Request/response models with Pydantic
- Error handling per CSC API error codes
- TLS certificate verification
- Request timeout configuration

**Acceptance criteria:**
- [ ] All CSC API v2 endpoints implemented
- [ ] Pydantic models for request/response
- [ ] Proper error handling and retry logic
- [ ] TLS verification enabled by default

---

#### 3.2 — OAuth 2.0 Authorization Flow

**New file:** `src/pdfsigner/core/remote/oauth_handler.py`

**Implementation:**
- Authorization Code flow with PKCE
- Pushed Authorization Requests (PAR)
- Token management (access/refresh, expiry tracking)
- Secure token storage (keyring or encrypted file)
- Support for multiple concurrent QTSP sessions

**Acceptance criteria:**
- [ ] Full OAuth 2.0 Authorization Code + PKCE flow
- [ ] Token refresh before expiry
- [ ] Secure storage of tokens
- [ ] Multiple QTSP sessions supported

---

#### 3.3 — Extend pyHanko CSCSigner for v2

**pyHanko already has:** `pyhanko.sign.signers.csc_signer.CSCSigner` (CSC v1.0.4.0)

**Implementation:**
- Create `CSCv2Signer` extending pyHanko's `CSCSigner`
- Override endpoints for v2 URL structure
- Implement `CSCAuthorizationManager` for interactive auth (PIN/OTP)
- Handle credential authorization with SAD (Signature Activation Data)
- Support batch signing (multiple hashes per session)

**Test server:** `certomancer-csc-dummy` (from pyHanko author)

**Acceptance criteria:**
- [ ] CSCv2Signer works with certomancer-csc-dummy
- [ ] Interactive authorization (PIN/OTP) supported
- [ ] Batch signing works
- [ ] Certificate chain properly retrieved from QTSP

---

#### 3.4 — Credential Management

**New file:** `src/pdfsigner/core/remote/credential_manager.py`

**Implementation:**
- List available certificates from QTSP
- Display certificate details (subject, issuer, validity, QcStatements)
- Cache credential metadata locally
- Handle ephemeral certificates (per-session, auto-generated by QTSP)
- Certificate chain retrieval and validation against EUTL

**Acceptance criteria:**
- [ ] Credentials listed from QTSP
- [ ] Certificate details displayed in GUI
- [ ] Ephemeral certificate flow supported
- [ ] EUTL validation of remote certificates

---

#### 3.5 — Remote Signing Integration

**Files to modify:**
- `src/pdfsigner/core/signer/pdf_signer.py`
- `src/pdfsigner/core/signer/batch_manager.py`

**Implementation:**
- Add `SigningMode` enum: `LOCAL_PKCS11` | `REMOTE_CSC`
- Phase 4 (sign) uses `CSCv2Signer` instead of PKCS#11 when mode is REMOTE_CSC
- Phases 1-3 and 5-6 remain unchanged (prep, fields, stamps, DSS, archive TS)
- DSS embedding still local (OCSP/CRL fetching)
- Archive timestamp still local (TSA request)

**Flow:**
```
prep → fields → stamps → sign(CSC v2 remote) → DSS(local) → archive_TS(local)
```

**Acceptance criteria:**
- [ ] Remote signing produces valid PAdES-LTA
- [ ] 6-phase flow maintained
- [ ] Batch signing works with remote signer
- [ ] Fallback to local PKCS#11 if remote fails (configurable)

---

#### 3.6 — GUI for Remote Signing

**New file:** `src/pdfsigner/gui/settings_pages/remote_signing_page.py`
**Modify:** `src/pdfsigner/gui/signing_handler.py`

**GUI elements:**
- QTSP configuration (service URL, auth method)
- "Sign with Cloud QTSP" option in signing dialog
- Credential selection dialog (list certificates from QTSP)
- PIN/OTP input dialog during signing authorization
- Progress bar for remote operations
- Error dialogs (network, auth, QTSP errors)

**Acceptance criteria:**
- [ ] QTSP configuration in settings
- [ ] Credential selection from remote QTSP
- [ ] PIN/OTP input during signing
- [ ] Progress feedback during remote operations

---

#### 3.7 — QTSP Presets

**New file:** `src/pdfsigner/gui/settings_pages/qtsp_presets.py`

**Pre-configured QTSPs:**

| QTSP | Country | CSC API URL (example) |
|------|---------|-----------------------|
| Swisscom Trust Services | CH | ais.swisscom.com |
| InfoCert | IT | (CSC endpoint) |
| A-Trust | AT | (CSC endpoint) |
| Universign (Signaturit) | FR | (CSC endpoint) |
| DigiCert EU | EU-wide | (CSC endpoint) |

*Note: Exact URLs to be determined during implementation via QTSP documentation.*

**Acceptance criteria:**
- [ ] At least 3 QTSP presets configured
- [ ] Preset selection in GUI
- [ ] Custom QTSP configuration supported

---

#### 3.8 — Remote Signing Tests

**New files:**
- `tests/unit/test_csc_client.py`
- `tests/unit/test_remote_signing.py`
- `tests/integration/test_csc_integration.py`

**Test scenarios:**
- Service info discovery
- OAuth2 authorization flow (mocked)
- Credential listing and selection
- Hash signing (single and batch)
- Document signing
- Network error handling
- Invalid credential handling
- Full flow: remote sign → validate → verify QES level

**Acceptance criteria:**
- [ ] Unit tests with mock CSC server
- [ ] Integration tests with certomancer-csc-dummy
- [ ] End-to-end remote signing validated

---

## Phase 4: Electronic Seals Production

> **Priority:** MEDIUM | **Duration:** 3 weeks | **Target:** August 30, 2026
> **Goal:** Replace mock seal implementation with production-ready code
> **Depends on:** Phase 0 (QcStatements) | **Parallel with:** Phase 3

### Tasks

#### 4.1 — Real Seal Creation with PKCS#11

**File:** `src/pdfsigner/core/eidas/seal_manager.py` (line 213)
**Problem:** Mock signer — *"Using mock signer - production requires PKCS#11 seal certificate"*

**Implementation:**
- Use same PKCS#11/NSS infrastructure as signature creation
- Detect seal certificate via QcType OID (from Phase 0 parser)
- Sign with seal certificate private key
- PAdES seal: same SubFilter (ETSI.CAdES.detached)

**Acceptance criteria:**
- [ ] Real PKCS#11 signing with seal certificate
- [ ] PAdES-compliant seal signature
- [ ] Mock signer removed from production path

---

#### 4.2 — Real QcType Detection (eseal)

**File:** `src/pdfsigner/core/eidas/seal_manager.py` (line 410)
**Problem:** `is_seal_certificate()` always returns `False`.

**Implementation:**
- Use `QcStatementsParser` from Phase 0 (Task 0.1)
- Check for QcType containing OID 0.4.0.1862.1.6.2 (id-etsi-qct-eseal)
- Return True/False based on real ASN.1 parsing

**Acceptance criteria:**
- [ ] Seal certificate correctly identified by QcType
- [ ] Non-seal certificate correctly rejected
- [ ] Certificate without QcStatements → False

---

#### 4.3 — Seal Validation Against EUTL

**File:** `src/pdfsigner/core/eidas/seal_manager.py` (line 254)
**Problem:** Mock validation returns hardcoded results.

**Implementation:**
- Verify seal signature cryptographically (pyHanko)
- Validate seal certificate against EUTL (from Phase 1)
- Check TSP is qualified for seal service type (CA/QC with eseal)
- Classify: QESeal / AdESeal-QC / AdESeal / Basic

**Acceptance criteria:**
- [ ] Real cryptographic verification of seal
- [ ] EUTL lookup for seal certificate TSP
- [ ] Correct qualification level determination

---

#### 4.4 — Seal GUI Improvements

**File:** `src/pdfsigner/gui/` (seal-related dialogs)

**Improvements:**
- Certificate type indicator (signature vs seal) in certificate selection
- Organization info auto-extraction from seal certificate subject
- Seal-specific appearance options in settings

**Acceptance criteria:**
- [ ] GUI distinguishes signature vs seal certificates
- [ ] Organization info populated from certificate

---

#### 4.5 — Seal API and Tests

**Files:**
- `src/pdfsigner/api/routes/seal.py`
- `tests/unit/test_seal.py` (update)
- `tests/unit/test_seal_production.py` (NEW)

**Acceptance criteria:**
- [ ] Seal API uses real signing
- [ ] Seal validation endpoint uses EUTL
- [ ] Tests cover real PKCS#11 flow (mock token)
- [ ] Tests cover QcType detection

---

## Phase 5: EUDIW Integration

> **Priority:** LOW (exploratory) | **Duration:** 6 weeks | **Target:** Q1 2027
> **Goal:** Support EU Digital Identity Wallet for signature creation
> **Depends on:** Phases 2 + 3 | **Status:** Exploratory — specs still evolving

### Context

The EUDI Wallet ecosystem is defined by:
- **ARF v2.8** (Feb 2026): Architecture Reference Framework
- **CIR 2024/2982**: Protocols and interfaces
- **CIR 2024/2979**: Wallet integrity and core functionalities
- **CIR 2025/1567**: Management of remote QSCDs

**GitHub:** `github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework`

### Two Signing Models

#### Wallet-Centric (User initiates from Wallet)
```
User → Wallet → CSC /credentials/info → QTSP
Wallet → SCA: calculate hash
Wallet → QTSP: /oauth2/authorize (with PID presentation via OpenID4VP)
QTSP → Wallet: authorization code
Wallet → QTSP: /signatures/signHash (with SAD + hashes)
Wallet → SCA: embed signature in document
```

#### QTSP-Centric (App initiates, Wallet authorizes)
```
PDFSigner → QTSP: document to sign
QTSP → User (OpenID4VP): request PID + consent
Wallet → User: show consent with transaction data
User → Wallet: authorize (biometric/PIN)
Wallet → QTSP: PID presentation + transaction data hashes
QTSP: creates ephemeral cert, signs document
QTSP → PDFSigner: signed document
```

### Tasks

#### 5.1 — Wallet-Issued Certificate Support

**Minimal viable integration — verify that certificates issued via wallet QTSPs
validate correctly against EUTL (should work automatically with Phase 1+2).**

**Acceptance criteria:**
- [ ] Certificates from pilot wallet QTSPs validate against EUTL
- [ ] QcStatements correctly parsed for wallet-issued certs
- [ ] No code changes needed (validation via Phases 1+2)

---

#### 5.2 — OpenID4VP Relying Party

**New module:** `src/pdfsigner/core/wallet/oid4vp_verifier.py`
**Standard:** OpenID for Verifiable Presentations 1.0 (Draft 25)
**Library:** Custom implementation (no mature Python library exists)

**Implementation:**
- Generate Authorization Request for PID presentation
- Support SD-JWT VC format
- Verify VP token (signature, key binding, claims)
- Extract identity data from PID

*Note: This is exploratory. Python ecosystem for OpenID4VP is immature.
May need to wrap Java reference implementation via subprocess.*

**Acceptance criteria:**
- [ ] Authorization Request generation
- [ ] VP token verification (basic)
- [ ] PID extraction from SD-JWT VC

---

#### 5.3 — SD-JWT VC Verification

**New module:** `src/pdfsigner/core/wallet/sdjwt_verifier.py`
**Standard:** RFC 9901 (SD-JWT) + draft-ietf-oauth-sd-jwt-vc-14
**Library:** `sd-jwt` (OpenWallet Foundation, PyPI)

**Implementation:**
- Verify SD-JWT VC issuer signature
- Validate selective disclosures
- Verify Key Binding JWT (KB-JWT) for proof of possession
- Extract claims (PID: name, birthdate, nationality, etc.)

**Acceptance criteria:**
- [ ] SD-JWT VC verification works
- [ ] Key Binding JWT verified
- [ ] Selective disclosure correctly resolved

---

#### 5.4 — Transaction Data Binding

**Implementation:**
- When initiating remote QES via EUDIW, include document hash as transaction data
- Hash included in OpenID4VP Authorization Request
- Wallet displays hash to user for informed consent
- Binds consent to specific document

**Acceptance criteria:**
- [ ] Document hash included in transaction data
- [ ] Transaction data binding verified in VP response

---

#### 5.5 — QEAA Support

**New module:** `src/pdfsigner/core/wallet/qeaa_handler.py`
**Standard:** CIR (EU) 2025/1569

**Implementation:**
- Parse QEAA attributes from wallet presentations
- Display signer's professional attributes in signature metadata
- Include attributes in validation results
- Types: professional qualifications, licenses, roles

**Acceptance criteria:**
- [ ] QEAA attributes extracted from presentations
- [ ] Attributes displayed in GUI validation results
- [ ] Attributes included in validation reports

---

#### 5.6 — Wallet GUI Integration

**Modify:** `src/pdfsigner/gui/signing_handler.py`

**GUI elements:**
- "Sign with EU Wallet" button
- QR code display for wallet connection (OpenID4VP)
- Deep link for mobile wallet invocation
- Real-time status during wallet-assisted signing

**Acceptance criteria:**
- [ ] Wallet signing option in GUI
- [ ] QR code / deep link generation
- [ ] Status feedback during wallet flow

---

#### 5.7 — Wallet API Endpoints

**New file:** `src/pdfsigner/api/routes/wallet.py`

**Endpoints:**
- `POST /api/v1/sign/wallet` — Initiate wallet-assisted signing
- `GET /api/v1/sign/wallet/{session_id}/status` — Check signing status
- `POST /api/v1/sign/wallet/{session_id}/callback` — Wallet callback
- WebSocket `/ws/sign/wallet/{session_id}` — Real-time updates

**Acceptance criteria:**
- [ ] Wallet signing API functional
- [ ] Session management for async wallet flow
- [ ] WebSocket status updates

---

#### 5.8 — EUDIW Integration Tests

**Test infrastructure:**
- Mock wallet server for OpenID4VP flows
- Test SD-JWT VCs for PID verification
- Test transaction data binding
- Test QEAA attribute extraction

**Acceptance criteria:**
- [ ] All wallet flows tested with mock server
- [ ] SD-JWT VC verification tested
- [ ] Integration test with pilot wallet (when available)

---

## Cross-Cutting Concerns

### Algorithm Policy (SOGIS)

Applies across ALL phases. New file: `src/pdfsigner/core/crypto/algorithm_policy.py`

| Type | Creation (must use) | Validation (accepted) | Rejected |
|------|--------------------|-----------------------|----------|
| Hash | SHA-256, SHA-384, SHA-512 | SHA-256+ (SHA-1 legacy only) | MD5 |
| RSA | ≥3072 bits (PSS preferred) | ≥2048 bits | <2048 bits |
| ECDSA | P-256, P-384, P-521 | P-256+ | <P-256 |
| EdDSA | Ed25519, Ed448 | Ed25519, Ed448 | — |

### Security

- LOTL/TSL XML signature validation (fixed in Phase 1 via pyHanko)
- SSRF protection on OCSP/CRL/CSC URLs (existing in revocation_checker.py)
- OAuth2 token secure storage (Phase 3)
- PIN/SAD handling for remote signing (Phase 3)
- No plaintext credentials in config or logs

### Performance

- EUTL loading: async with concurrency (aiohttp)
- Cache: pyHanko's FileSystemTLCache + configurable TTL
- Background refresh thread for EUTL (avoid blocking GUI)
- Remote signing: async with timeout configuration

### Audit Trail

- Log all eIDAS validation operations with timestamps
- Log EUTL updates and cache status
- Log remote signing operations (without sensitive data)
- Extend existing audit module (`core/audit/`)

---

## Dependency Graph

```
Phase 0 (Foundation) ───→ Phase 1 (pyHanko EUTL)
        │                         │
        │                         ├──→ Phase 2 (Validation CIR 2025/1945)
        │                         │              │
        │                         ├──→ Phase 3 ──┤──→ Phase 5 (EUDIW)
        │                              (CSC API) │
        └──→ Phase 4 (Seals) ───────────────────┘
             [parallel with Phase 3]
```

## Risk Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| pyHanko 0.21→0.33 breaking changes | HIGH | MEDIUM | Review CHANGELOG, phased upgrade, full test suite |
| TLv6 deadline (Apr 29) missed | HIGH | LOW | Phases 0+1 are top priority |
| ETSI TS 119 432 v1.3.1 delayed | MEDIUM | MEDIUM | Use CSC API v2.2 directly (stable) |
| No Python OpenID4VP library | MEDIUM | HIGH | Custom implementation or Java wrapper |
| QTSP test environments unavailable | MEDIUM | MEDIUM | certomancer-csc-dummy for unit tests |
| EUDI Wallet specs change | LOW | HIGH | Phase 5 is exploratory, adapt as specs stabilize |

## Milestones

| ID | Date | Phase | Deliverable | KPI |
|----|------|-------|-------------|-----|
| M0 | Mar 15 | Phase 0 | Foundation fixes | 100% QcStatements OIDs parsed, 0 stub methods |
| M1 | Apr 15 | Phase 1 | pyHanko EUTL | EUTL loads with XML sig validation, all EU/EEA |
| M2 | May 30 | Phase 2 | CIR 2025/1945 | Validation reports, algorithm policy enforced |
| M3 | Jul 30 | Phase 3 | Remote signing | QES creation with test QTSP (certomancer) |
| M4 | Aug 30 | Phase 4 | Production seals | Real seal creation/validation with PKCS#11 |
| M5 | Q1 2027 | Phase 5 | EUDIW integration | End-to-end wallet-assisted signing (pilot) |

## New Dependencies

```toml
# pyproject.toml additions per phase
[project]
dependencies = [
    # Phase 1: upgrade + etsi extras
    "pyhanko[pkcs11,etsi]>=0.33.0",   # was >=0.21.0
    # xsdata and aiohttp come via [etsi]

    # Phase 3: OAuth2
    "authlib>=1.3.0",                   # OAuth 2.0 client

    # Phase 5: SD-JWT (when needed)
    "sd-jwt>=0.11.0",                   # SD-JWT VC verification
]
```

## New Files Summary

| Phase | New File | Purpose |
|-------|----------|---------|
| 0 | `core/eidas/qc_statements_parser.py` | Real ASN.1 QcStatements parsing |
| 0 | `tests/unit/test_qc_statements_parser.py` | Parser tests |
| 1 | `core/eidas/eutl_adapter.py` | pyHanko EUTL wrapper |
| 2 | `core/validator/eidas_validator.py` | CIR 2025/1945 validation |
| 2 | `core/validator/validation_report.py` | TS 119 102-2 reports |
| 2 | `core/validator/validation_policy.py` | TS 119 172-4 policy |
| 2 | `tests/unit/test_eidas_validation.py` | Validation tests |
| 3 | `core/remote/csc_client.py` | CSC API v2 client |
| 3 | `core/remote/oauth_handler.py` | OAuth 2.0 flows |
| 3 | `core/remote/credential_manager.py` | Remote credential management |
| 3 | `gui/settings_pages/remote_signing_page.py` | Remote signing GUI |
| 3 | `gui/settings_pages/qtsp_presets.py` | QTSP presets |
| 3 | `tests/unit/test_csc_client.py` | CSC client tests |
| 3 | `tests/unit/test_remote_signing.py` | Remote signing tests |
| 4 | `tests/unit/test_seal_production.py` | Production seal tests |
| 5 | `core/wallet/oid4vp_verifier.py` | OpenID4VP Relying Party |
| 5 | `core/wallet/sdjwt_verifier.py` | SD-JWT VC verification |
| 5 | `core/wallet/qeaa_handler.py` | QEAA attribute handling |
| 5 | `api/routes/wallet.py` | Wallet API endpoints |

## References

### EU Regulations
- [Regulation (EU) 2024/1183](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) — eIDAS 2
- [CIR (EU) 2025/1945](https://eur-lex.europa.eu/eli/reg_impl/2025/1945/oj) — Validation of QES
- [CIR (EU) 2025/1946](https://eur-lex.europa.eu/eli/reg_impl/2025/1946/oj) — Preservation of QES
- [CIR (EU) 2025/1929](https://eur-lex.europa.eu/eli/reg_impl/2025/1929/oj) — Qualified timestamps
- [CIR (EU) 2025/1567](https://eur-lex.europa.eu/eli/reg_impl/2025/1567/oj) — Remote QSCDs
- [CIR (EU) 2024/2982](https://eur-lex.europa.eu/eli/reg_impl/2024/2982/oj) — Wallet protocols

### ETSI Standards
- [EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf) — AdES validation
- [EN 319 412-5 V2.5.1](https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.05.01_60/en_31941205v020501p.pdf) — QcStatements
- [TS 119 612 V2.4.1](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf) — Trusted Lists TLv6
- [TS 119 102-2 V1.4.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/) — Validation reports
- [TS 119 172-4 V1.1.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/) — Validation policy

### Technical Resources
- [CSC API V2.2](https://cloudsignatureconsortium.org/resources/download-api-specifications/) — Cloud Signature Consortium
- [pyHanko Docs](https://docs.pyhanko.eu/en/latest/) — PAdES library
- [EUDI Wallet ARF](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework) — Architecture Reference Framework
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — Verifiable Presentations
- [SD-JWT (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/) — Selective Disclosure JWT
- [certomancer-csc-dummy](https://github.com/MatthiasValvekens/certomancer-csc-dummy) — CSC test server
- [EU LOTL](https://ec.europa.eu/tools/lotl/eu-lotl.xml) — List of Trusted Lists

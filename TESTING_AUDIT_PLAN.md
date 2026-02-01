# PDFSigner - Testing Audit Plan

> Generated: 2026-02-01
> Current coverage: 87% core | ~1,750 tests
> Target coverage: 95% core | ~2,350 tests

---

## Executive Summary

This audit identified **45+ functions without adequate tests** across compliance-critical modules. The plan is organized in 4 phases over 8 weeks, prioritizing security and regulatory compliance.

### Risk Matrix

| Module | Current Tests | Gap | Priority |
|--------|--------------|-----|----------|
| `credential_store.py` | 0 | 168 lines | 🔴 P0 |
| `notification_service.py` | 0 | ~200 lines | 🔴 P0 |
| `soc2_report.py` | 0 | ~300 lines | 🔴 P0 |
| `authorization.py` | partial | 6 functions | 🔴 P0 |
| `data_export.py` | 0 | 4 functions | 🔴 P0 |
| API Security tests | 39 | 51 endpoints | 🔴 P0 |
| `pdf_signer.py` rollback | partial | 3 paths | 🟠 P1 |
| `key_manager.py` concurrency | partial | 5 race conditions | 🟠 P1 |
| `session_manager.py` concurrency | partial | 5 race conditions | 🟠 P1 |

---

## Phase 1: Critical Security (Week 1-2)

### Objective
Eliminate critical security gaps that could lead to data breaches or compliance failures.

### Tasks

#### 1.1 Credential Store Tests (NEW FILE)
**File:** `tests/unit/test_credential_store.py`
**Priority:** 🔴 CRITICAL
**Estimated tests:** 15

```python
# Functions to test:
- store_password_for_file()
- get_password_for_file()
- delete_password_for_file()
- get_any_password_for_file()
- _generate_key_for_file()  # Hash collision test
```

**Test scenarios:**
- [ ] Happy path: store → retrieve → delete cycle
- [ ] Error: keyring.set_password() failure
- [ ] Error: keyring.get_password() returns None
- [ ] Security: hash collision with two different PDFs
- [ ] Security: password not stored in plaintext
- [ ] Edge: file path with special characters
- [ ] Edge: extremely long file paths
- [ ] Concurrency: simultaneous store operations

#### 1.2 API Security Tests (NEW FILE)
**File:** `tests/integration/test_api_security.py`
**Priority:** 🔴 CRITICAL
**Estimated tests:** 50

```python
# Test categories:
class TestJWTSecurity:
    - test_jwt_token_tampering_returns_401()
    - test_jwt_signature_verification()
    - test_jwt_algorithm_confusion_attack()
    - test_jwt_token_reuse_after_logout()
    - test_jwt_expiration_edge_cases()

class TestAPIKeySecurity:
    - test_api_key_not_accepted_in_query_string()
    - test_api_key_brute_force_rate_limiting()
    - test_api_key_enumeration_prevention()

class TestInputValidation:
    - test_sql_injection_in_user_search()
    - test_sql_injection_in_breach_filters()
    - test_path_traversal_in_backup_id()
    - test_path_traversal_in_report_download()
    - test_mass_assignment_in_user_update()

class TestRateLimiting:
    - test_login_rate_limit_5_per_minute()
    - test_mfa_verification_rate_limit()
```

#### 1.3 MFA Tests (EXPAND EXISTING)
**File:** `tests/unit/test_mfa.py` + `tests/integration/test_api_mfa.py`
**Priority:** 🔴 CRITICAL
**Estimated tests:** 20

```python
# New scenarios:
- test_mfa_enroll_generates_valid_qr_code()
- test_mfa_verify_with_time_drift_30_seconds()
- test_mfa_backup_code_single_use_only()
- test_mfa_bypass_attempt_without_valid_code()
- test_mfa_disable_requires_current_password()
- test_mfa_enrollment_secret_not_exposed_in_response()
```

#### 1.4 RBAC Authorization Tests (EXPAND EXISTING)
**File:** `tests/unit/test_authorization.py`
**Priority:** 🔴 CRITICAL
**Estimated tests:** 15

```python
# New scenarios:
- test_idor_user_cannot_access_other_user_data()
- test_privilege_escalation_user_to_admin_blocked()
- test_rbac_healthcare_mode_enforcement()
- test_rbac_permission_decorator_async()
- test_emergency_role_permission_set()
```

### Phase 1 Deliverables
- [ ] `tests/unit/test_credential_store.py` (15 tests)
- [ ] `tests/integration/test_api_security.py` (50 tests)
- [ ] `tests/integration/test_api_mfa.py` (20 tests)
- [ ] Expanded `tests/unit/test_authorization.py` (15 tests)
- **Total: 100 new tests**

---

## Phase 2: Compliance (Week 3-4)

### Objective
Ensure all GDPR, HIPAA, and SOC 2 requirements have automated test coverage.

### Tasks

#### 2.1 Breach Notification Tests (NEW FILE)
**File:** `tests/unit/test_notification_service.py`
**Priority:** 🔴 CRITICAL (GDPR Art. 33)
**Estimated tests:** 18

```python
# Functions to test:
- generate_gdpr_notification()
- generate_hipaa_notification()
- calculate_notification_deadline()
- send_notification()  # multi-channel
- _get_notification_recipients()
```

**Test scenarios:**
- [ ] GDPR notification includes all required fields (Art. 33)
- [ ] GDPR 72-hour deadline calculation
- [ ] HIPAA 60-day deadline calculation
- [ ] Multi-channel delivery (email, webhook, SMS)
- [ ] Notification retry on failure
- [ ] Template rendering with breach details
- [ ] Recipient list based on severity
- [ ] Audit trail for sent notifications

#### 2.2 SOC 2 Report Tests (NEW FILE)
**File:** `tests/unit/test_soc2_report.py`
**Priority:** 🔴 CRITICAL
**Estimated tests:** 15

```python
# Functions to test:
- generate_report()
- _map_evidence_to_controls()
- _calculate_coverage_score()
- _generate_executive_summary()
- export_markdown()
```

**Test scenarios:**
- [ ] Report maps all CC1-CC9 controls
- [ ] Weighted scoring algorithm accuracy
- [ ] Partial vs implemented control weighting
- [ ] Evidence-to-control mapping completeness
- [ ] Markdown export formatting
- [ ] Report with zero evidence (edge case)
- [ ] Report date range filtering

#### 2.3 GDPR Data Export Tests (NEW FILE)
**File:** `tests/unit/test_data_export.py`
**Priority:** 🔴 CRITICAL (GDPR Art. 20)
**Estimated tests:** 12

```python
# Functions to test:
- export_user_data()
- _collect_profile_data()
- _collect_audit_history()
- _collect_certificates()
- _collect_sessions()
```

**Test scenarios:**
- [ ] Export includes all user data categories
- [ ] Export includes audit history
- [ ] JSON format is machine-readable
- [ ] Export with non-existent user
- [ ] IDOR: user cannot export another user's data
- [ ] Large data export performance

#### 2.4 Emergency Access Tests (NEW FILE)
**File:** `tests/integration/test_api_emergency.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 15

```python
# Endpoints to test:
- POST /api/v1/emergency/request
- GET /api/v1/emergency/pending
- POST /api/v1/emergency/{id}/approve
- POST /api/v1/emergency/{id}/deny
- POST /api/v1/emergency/{id}/revoke
```

**Test scenarios:**
- [ ] Request requires justification (reason not empty)
- [ ] Dual approval when require_approval=true
- [ ] Auto-approval when disabled
- [ ] Access expiration (duration_hours)
- [ ] Non-admin cannot approve/deny
- [ ] Audit trail for all operations

### Phase 2 Deliverables
- [ ] `tests/unit/test_notification_service.py` (18 tests)
- [ ] `tests/unit/test_soc2_report.py` (15 tests)
- [ ] `tests/unit/test_data_export.py` (12 tests)
- [ ] `tests/integration/test_api_emergency.py` (15 tests)
- **Total: 60 new tests**

---

## Phase 3: Core Robustness (Week 5-6)

### Objective
Eliminate race conditions and improve error handling in core signing/crypto modules.

### Tasks

#### 3.1 PDF Signer Rollback Tests (EXPAND EXISTING)
**File:** `tests/unit/test_pdf_signer.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 12

```python
# New scenarios:
- test_sign_pdf_rollback_on_phase4_failure()
- test_sign_pdf_temp_file_cleanup_on_error()
- test_sign_pdf_with_corrupted_xref()
- test_sign_pdf_output_permission_denied()
- test_template_rendering_qr_failure_fallback()
- test_coordinate_conversion_rotated_page()
```

#### 3.2 Key Manager Concurrency Tests (EXPAND EXISTING)
**File:** `tests/unit/test_key_manager.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 10

```python
# New scenarios using ThreadPoolExecutor:
- test_concurrent_key_generation()
- test_concurrent_cleanup_expired()
- test_get_key_during_rotation()
- test_database_deadlock_prevention()
- test_pbkdf2_performance_with_high_iterations()
```

#### 3.3 Session Manager Concurrency Tests (EXPAND EXISTING)
**File:** `tests/unit/test_session_manager.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 10

```python
# New scenarios:
- test_concurrent_session_creation_same_user()
- test_touch_session_during_cleanup()
- test_terminate_during_validation()
- test_max_sessions_concurrent_logins()
- test_session_expiration_boundary()
```

#### 3.4 DSS Manager Error Handling (EXPAND EXISTING)
**File:** `tests/unit/test_dss_manager.py`
**Priority:** 🟡 MEDIUM
**Estimated tests:** 8

```python
# New scenarios:
- test_embed_dss_shutil_move_failure()
- test_embed_dss_temp_cleanup_on_error()
- test_ocsp_crl_conflicting_status()
- test_build_validation_context_invalid_kwargs()
```

### Phase 3 Deliverables
- [ ] Expanded `tests/unit/test_pdf_signer.py` (12 tests)
- [ ] Expanded `tests/unit/test_key_manager.py` (10 tests)
- [ ] Expanded `tests/unit/test_session_manager.py` (10 tests)
- [ ] Expanded `tests/unit/test_dss_manager.py` (8 tests)
- **Total: 40 new tests**

---

## Phase 4: API Coverage (Week 7-8)

### Objective
Achieve 95% API endpoint coverage with security-focused tests.

### Tasks

#### 4.1 User Management Tests (NEW FILE)
**File:** `tests/integration/test_api_users.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 20

```python
# Endpoints:
- GET /api/v1/users/me
- GET /api/v1/users/
- GET /api/v1/users/{id}
- PUT /api/v1/users/{id}
- DELETE /api/v1/users/{id}
```

#### 4.2 Session Management Tests (NEW FILE)
**File:** `tests/integration/test_api_sessions.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 15

```python
# Endpoints:
- GET /api/v1/sessions/
- GET /api/v1/sessions/{id}
- DELETE /api/v1/sessions/{id}
- DELETE /api/v1/sessions/
```

#### 4.3 Backup/Restore Tests (NEW FILE)
**File:** `tests/integration/test_api_backup.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 15

```python
# Endpoints:
- POST /api/v1/backup/create
- GET /api/v1/backup/list
- POST /api/v1/backup/restore
- DELETE /api/v1/backup/{id}
```

#### 4.4 Breach Notification API Tests (NEW FILE)
**File:** `tests/integration/test_api_breach.py`
**Priority:** 🟠 HIGH
**Estimated tests:** 18

```python
# Endpoints:
- POST /api/v1/breach/report
- GET /api/v1/breach/
- GET /api/v1/breach/{id}
- PATCH /api/v1/breach/{id}/status
- POST /api/v1/breach/{id}/notify
```

#### 4.5 PHI/PII Scanner Tests (NEW FILE)
**File:** `tests/integration/test_api_phi.py`
**Priority:** 🟡 MEDIUM
**Estimated tests:** 12

```python
# Endpoint:
- POST /api/v1/phi/scan
```

#### 4.6 Remaining Endpoints (NEW FILES)
**Files:** `test_api_consent.py`, `test_api_retention.py`, `test_api_evidence.py`, `test_api_compliance.py`, `test_api_gdpr.py`, `test_api_redact.py`, `test_api_seal.py`, `test_api_vulnerabilities.py`
**Priority:** 🟡 MEDIUM
**Estimated tests:** 60

### Phase 4 Deliverables
- [ ] `tests/integration/test_api_users.py` (20 tests)
- [ ] `tests/integration/test_api_sessions.py` (15 tests)
- [ ] `tests/integration/test_api_backup.py` (15 tests)
- [ ] `tests/integration/test_api_breach.py` (18 tests)
- [ ] `tests/integration/test_api_phi.py` (12 tests)
- [ ] Additional API test files (60 tests)
- **Total: 140 new tests**

---

## Summary

### Test Count by Phase

| Phase | Weeks | New Tests | Cumulative |
|-------|-------|-----------|------------|
| Current | - | 1,750 | 1,750 |
| Phase 1 | 1-2 | 100 | 1,850 |
| Phase 2 | 3-4 | 60 | 1,910 |
| Phase 3 | 5-6 | 40 | 1,950 |
| Phase 4 | 7-8 | 140 | 2,090 |
| **Buffer** | - | 60 | **2,150** |

### Coverage Targets

| Metric | Current | Target |
|--------|---------|--------|
| Core coverage | 87% | 95% |
| API coverage | 43% | 95% |
| Total tests | 1,750 | 2,150+ |
| Security tests | ~50 | 200+ |
| Compliance tests | ~100 | 200+ |

### New Test Files Summary

```
tests/
├── unit/
│   ├── test_credential_store.py      # NEW (Phase 1)
│   ├── test_authorization.py         # EXPAND (Phase 1)
│   ├── test_notification_service.py  # NEW (Phase 2)
│   ├── test_soc2_report.py          # NEW (Phase 2)
│   ├── test_data_export.py          # NEW (Phase 2)
│   ├── test_pdf_signer.py           # EXPAND (Phase 3)
│   ├── test_key_manager.py          # EXPAND (Phase 3)
│   ├── test_session_manager.py      # EXPAND (Phase 3)
│   └── test_dss_manager.py          # EXPAND (Phase 3)
└── integration/
    ├── test_api_security.py         # NEW (Phase 1)
    ├── test_api_mfa.py              # NEW (Phase 1)
    ├── test_api_emergency.py        # NEW (Phase 2)
    ├── test_api_users.py            # NEW (Phase 4)
    ├── test_api_sessions.py         # NEW (Phase 4)
    ├── test_api_backup.py           # NEW (Phase 4)
    ├── test_api_breach.py           # NEW (Phase 4)
    ├── test_api_phi.py              # NEW (Phase 4)
    ├── test_api_consent.py          # NEW (Phase 4)
    ├── test_api_retention.py        # NEW (Phase 4)
    ├── test_api_evidence.py         # NEW (Phase 4)
    ├── test_api_compliance.py       # NEW (Phase 4)
    ├── test_api_gdpr.py             # NEW (Phase 4)
    ├── test_api_redact.py           # NEW (Phase 4)
    ├── test_api_seal.py             # NEW (Phase 4)
    └── test_api_vulnerabilities.py  # NEW (Phase 4)
```

---

## Execution Commands

```bash
# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=src --cov-report=html

# Run specific phase tests
uv run pytest tests/unit/test_credential_store.py -v  # Phase 1
uv run pytest tests/integration/test_api_security.py -v  # Phase 1

# Run security tests only
uv run pytest -m security -v

# Run compliance tests only
uv run pytest -m compliance -v

# Parallel execution (faster)
uv run pytest -n auto -v
```

---

## Risk Mitigation

### If Phase 1 is delayed:
- **Impact:** Security vulnerabilities remain in production
- **Mitigation:** Prioritize MFA and JWT tests first (highest attack surface)

### If Phase 2 is delayed:
- **Impact:** GDPR/HIPAA audit failures possible
- **Mitigation:** Prioritize notification_service tests (72h deadline is non-negotiable)

### If Phase 3-4 are delayed:
- **Impact:** Technical debt accumulates
- **Mitigation:** These phases can be split into smaller increments

---

## Success Criteria

- [ ] All Phase 1 tests pass (security baseline)
- [ ] All Phase 2 tests pass (compliance baseline)
- [ ] Coverage > 90% on core modules
- [ ] Coverage > 90% on API endpoints
- [ ] No critical/high vulnerabilities in security tests
- [ ] All GDPR/HIPAA/SOC2 controls have test coverage

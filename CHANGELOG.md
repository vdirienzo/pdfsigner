# Changelog

All notable changes to PDFSigner are documented here.

Format: [SemVer](https://semver.org/) with `Added | Changed | Fixed | Security` sections.

---

## [2.2.0] - 2026-02-01

### Security

- **JWT Token Blacklist for Real Logout**
  - `core/auth/jwt_blacklist.py` - SQLite-backed token revocation system
  - JWT tokens now include unique `jti` (JWT ID) claim for tracking
  - Logout endpoint (`/auth/logout`) adds tokens to blacklist
  - Middleware validates tokens against blacklist before authorization
  - Automatic cleanup of expired tokens to prevent unbounded growth
  - 19 integration tests in `test_jwt_revocation.py`

### Added - 100% Compliance Milestone

- **SOC 2 CC1-CC4 Controls** (Trust Service Criteria)
  - `core/compliance/governance.py` - CC1 Control Environment (5 sub-controls)
  - `core/compliance/communication.py` - CC2 Communication (3 sub-controls)
  - `core/compliance/risk_assessment.py` - CC3 Risk Assessment (4 sub-controls)
  - `core/compliance/monitoring.py` - CC4 Monitoring (2 sub-controls)
  - 21 SOC 2 controls fully automated
  - 52 unit tests in `test_soc2_controls.py`

- **NIST 800-53 Automated Checks** (26 controls)
  - `core/compliance/controls.py` - 17 new control definitions
    - AC family: AC-3, AC-5, AC-6, AC-8, AC-12, AC-17, AC-20
    - AU family: AU-3, AU-4, AU-6, AU-8, AU-11, AU-12
    - SC family: SC-12, SC-17, SC-23, SC-28
  - `core/compliance/checker.py` - 17 new `_check_nist_*` methods
  - 50 unit tests in `test_nist_checks.py`

- **eIDAS Production Integration** (EU TSL Real Data)
  - `core/eidas/lotl_fetcher.py` - EU LOTL XML fetcher with 24h cache
  - `core/eidas/tsl_parser.py` - Country TSL parser (ETSI TS 119 612)
  - `core/eidas/pdf_signature_extractor.py` - pyHanko signature extraction
  - `core/eidas/tsp_registry.py` - Enhanced with real EU TSL integration
  - `core/eidas/qualified_validator.py` - Production QES validation
  - 57 unit tests in `test_eidas_production.py`

### Changed

- **Compliance Status:**
  - SOC 2: 90% → 100% ✅
  - NIST 800-53: 90% → 100% ✅
  - eIDAS: 95% → 100% ✅
- **Test count:** 2,473 → 2,675 (+202 tests)
- **STANDARDS_COMPLIANCE.md:** All P1-P3 standards at 100%

---

## [2.1.0] - 2026-02-01

### Added - Compliance Phase 3 (GDPR & SOC 2)

- **GDPR Consent Management** (Article 7)
  - `core/gdpr/consent_manager.py` - Consent tracking with audit trail
  - `core/gdpr/consent_repository.py` - SQLite persistence
  - `core/gdpr/consent_types.py` - 5 consent types (PROCESSING, ANALYTICS, MARKETING, THIRD_PARTY, RESEARCH)
  - `api/routes/consent.py` - REST endpoints for consent CRUD
  - 30 unit tests

- **Data Breach Notification** (GDPR Art. 33-34, HIPAA)
  - `core/breach/breach_detector.py` - Anomaly detection with configurable thresholds
  - `core/breach/breach_manager.py` - Incident workflow management
  - `core/breach/notification_service.py` - HIPAA/GDPR notification formatting
  - `core/breach/breach_report.py` - Incident report generation
  - `api/routes/breach.py` - REST endpoints for breach management
  - 32 unit tests

- **SOC 2 Evidence Collection** (CC series)
  - `core/compliance/evidence_collector.py` - Automated evidence gathering
  - `core/compliance/soc2_report.py` - SOC 2 Type II report generation
  - `core/compliance/evidence_types.py` - 9 CC categories, 8 evidence types
  - `api/routes/evidence.py` - REST endpoints for evidence export
  - 27 unit tests

- **Vulnerability Management** (NIST RA-5)
  - `core/security/vuln_scanner.py` - Semgrep & pip-audit integration
  - `core/security/vuln_tracker.py` - Vulnerability tracking with SLA
  - `core/security/vuln_report.py` - Monthly vulnerability reports
  - `api/routes/vulnerabilities.py` - REST endpoints for vuln management
  - 34 unit tests

### Changed
- **Test count:** 2,350 → 2,473 (+123 tests)
- **STANDARDS_COMPLIANCE.md:** Phase 3 marked complete

---

## [2.0.0] - 2026-02-01

### Added - Government Compliance Phase 6 (Documentation & Certification)

- **System Security Plan (SSP)** - FedRAMP/NIST 800-53 compliant
  - `docs/security/SSP.md` - 39 KB comprehensive security plan
  - System identification and authorization boundary
  - FIPS 199 security categorization (Moderate)
  - Control implementation statements
  - Roles and responsibilities matrix
  - System interconnections documentation

- **Security Policies** - Auditor-ready documentation
  - `docs/security/access-control-policy.md` - 20 KB (RBAC, sessions, emergency access)
  - `docs/security/audit-policy.md` - 45 KB (events, retention, SIEM)
  - `docs/security/encryption-policy.md` - 47 KB (FIPS 140-2, key management)
  - `docs/security/incident-response-plan.md` - 34 KB (IR procedures, escalation)
  - `docs/security/change-management.md` - 42 KB (change control, CAB)
  - `docs/security/README.md` - 9.5 KB (documentation index)

### Changed
- **Version:** 2.0.0 - Government Compliance Complete
- **Documentation:** ~236 KB of security documentation added

---

## [1.9.0] - 2026-02-01

### Added - Government Compliance Phase 5 (eIDAS Qualified Signatures)

- **EU TSP Registry** (eIDAS Article 22)
  - `core/eidas/tsp_registry.py` - EU Trusted List management
  - `EUTSPRegistry` class with cache and offline mode
  - 9 European TSPs in mock data (DigiCert, Bundesdruckerei, Actalis, ACCV, etc.)
  - Search by URL, country (ISO 3166-1), service type
  - Cache with 7-day expiration (configurable)
  - Singleton: `get_tsp_registry()`

- **Qualified Signature Validator** (eIDAS Articles 25-29)
  - `core/eidas/qualified_validator.py` - QES validation engine
  - `QualifiedSignatureValidator` class
  - QcStatements parsing (RFC 3739, ETSI EN 319 412-5)
  - QSCD detection (OID 0.4.0.1862.1.4)
  - Signature level detection: Basic, AdES, QES
  - Certificate qualification checking
  - 43 unit tests in `test_eidas.py`

- **Electronic Seals** (eIDAS Articles 35-40)
  - `core/eidas/seal_manager.py` - Organization seals
  - `SealManager` class with create/validate/extract
  - Seal types: Basic, Advanced (AdESeal), Qualified (QESeal)
  - Seal appearances: Invisible, Stamp, Banner, Logo
  - Circular seal SVG generation
  - `api/routes/seal.py` - REST API endpoints
  - `api/schemas/seal.py` - Pydantic schemas
  - Settings: `seal_enabled`, `seal_default_type`, `seal_appearance`
  - Singleton: `get_seal_manager()`
  - 35 unit tests in `test_seal.py`

### Changed
- **Tests:** ~2,184 total (was ~2,106, +78 Phase 5 tests)

---

## [1.8.0] - 2026-02-01

### Added - Government Compliance Phase 4 (Compliance Dashboard)

- **Compliance Checker Engine** (NIST 800-53, FedRAMP, SOC 2)
  - `core/compliance/checker.py` - Main ComplianceChecker with 6 standards
  - `core/compliance/controls.py` - Control definitions (100+ controls)
  - `core/compliance/status_checker.py` - Real-time status verification
  - Standards: HIPAA, NIST 800-53, FedRAMP, eIDAS, GDPR, SOC 2
  - `check_hipaa()` → 8 controls (§164.312 Access, Audit, Integrity, Auth)
  - `check_nist_800_53()` → 15 controls (AC, AU, IA, SC families)
  - `check_eidas()` → 6 controls (PAdES-LTA, TSA, certificates)
  - `check_gdpr()` → 7 controls (retention, erasure, portability)
  - `check_soc2()` → 10 controls (Trust Service Criteria)
  - Overall score calculation (weighted average 0-100)
  - Evidence collection for audit trails
  - Actionable recommendations engine
  - Singleton: `get_compliance_checker()`
  - 78 unit tests in `test_compliance_checker.py`

- **Compliance Report Generator** (FedRAMP, SOC 2)
  - `core/compliance/report_generator.py` - Multi-format report generation
  - `core/compliance/formatters.py` - PDF, JSON, CSV, CEF formatters
  - PDF reports with executive summary and control matrix
  - JSON export with full details for programmatic access
  - CSV export for spreadsheet analysis
  - CEF (Common Event Format) for SIEM integration
  - SHA-256 checksums for report integrity
  - API endpoints: `POST /api/v1/compliance/{check,report,status}`
  - Settings: `compliance_report_dir`, `compliance_auto_check_enabled`
  - Singleton: `get_report_generator()`
  - 30 unit tests in `test_compliance_reports.py`

- **SIEM Integration** (SOC 2 AU-6, NIST AU-6)
  - `core/audit/siem_exporter.py` - SIEM export functionality
  - CEF formatter (ArcSight, Splunk compatible)
  - LEEF formatter (IBM QRadar compatible)
  - JSON Lines formatter for ELK stack
  - Syslog UDP/TCP/TLS transport
  - File export with automatic rotation (configurable MB)
  - Retention policy (configurable days)
  - Severity mapping (DEBUG→0, INFO→3, WARNING→5, ERROR→7, CRITICAL→10)
  - Signature IDs for 12 event types
  - Batch export with error handling
  - Connection testing (`test_connection()`)
  - Settings: `siem_enabled`, `siem_format`, `siem_syslog_host/port/protocol`
  - Singleton: `get_siem_exporter()`
  - 38 unit tests in `test_siem_exporter.py`

### Changed
- **Tests:** ~2,106 total (was ~1,921, +185 Phase 4 tests)

---

## [1.7.0] - 2026-02-01

### Added - Government Compliance Phase 3 (Data Protection)

- **PHI/PII Detection Engine** (HIPAA §164.514, GDPR)
  - `core/detection/pii_types.py` - PIIType enum (9 types) + PIIMatch dataclass
  - `core/detection/patterns.py` - Regex patterns for SSN, CC, email, phone, DOB, MRN, ICD-10
  - `core/detection/pii_detector.py` - PIIDetector with confidence scoring (0.0-1.0)
  - `core/detection/pdf_scanner.py` - PDF text extraction with coordinates (PyMuPDF)
  - Luhn algorithm validation for credit cards
  - Contextual detection (context words boost confidence)
  - Risk score calculation (0.0-1.0) based on PII sensitivity
  - API endpoint: `POST /api/v1/phi/scan`
  - CLI command: `pdfsigner scan-pii doc.pdf`
  - Singleton: `get_pii_detector()`
  - 40 unit tests in `test_pii_detector.py`

- **Automatic PDF Redaction** (HIPAA Safe Harbor)
  - `core/detection/redactor.py` - PDFRedactor with true redaction (not overlay)
  - Uses PyMuPDF `add_redact_annot()` + `apply_redactions()` for permanent removal
  - `redact_regions()` - Manual coordinate-based redaction
  - `redact_by_pattern()` - Auto-detect and redact by PII type
  - `preview_redactions()` - PNG preview before applying
  - Configurable replacement text (e.g., "[SSN REDACTED]")
  - API endpoints: `POST /api/v1/redact/{regions,auto,preview}`
  - CLI command: `pdfsigner redact doc.pdf --types ssn,credit_card`
  - Audit logging for all redaction events
  - Singleton: `get_pdf_redactor()`
  - 27 unit tests in `test_redactor.py`

- **GDPR Data Retention & Erasure** (GDPR Articles 17 & 20)
  - `core/gdpr/data_retention.py` - DataRetentionService
  - `core/gdpr/data_export.py` - UserDataExporter (JSON/CSV)
  - User anonymization (pseudonymization): name → `anonymous_[hash]`
  - Scheduled deletion with grace period (default: 30 days)
  - Data export for portability (all user data in machine-readable format)
  - Automatic purge of expired data
  - API endpoints: `POST /api/v1/gdpr/{export,anonymize,delete,purge}`
  - Settings: `gdpr_enabled`, `gdpr_retention_days`, `gdpr_deletion_grace_days`
  - Singleton: `get_data_retention_service()`
  - 30 unit tests in `test_data_retention.py`

### Changed
- **Tests:** ~1,921 total (was ~1,824, +97 Phase 3 tests)

---

## [1.6.0] - 2026-02-01

### Added - Government Compliance Phase 2 (Enhanced Access Controls)

- **Password Policy Engine** (NIST 800-53 IA-5)
  - `core/auth/password_policy.py` with `PasswordPolicy` dataclass
  - `core/auth/password_validator.py` with `PasswordValidator` class
  - Argon2 password hashing (NIST recommended)
  - Password history tracking (SQLite-backed, prevents reuse of last N passwords)
  - Common password detection (100+ blocked passwords)
  - Strength scoring 0-100 with suggestions
  - Settings: `password_min_length`, `password_max_age_days`, `password_history_count`, `password_lockout_threshold`
  - 43 unit tests in `test_password_policy.py`

- **Multi-Factor Authentication (MFA)** (NIST 800-53 IA-2)
  - `core/auth/mfa/totp_provider.py` - TOTP RFC 6238 (Google Authenticator compatible)
  - `core/auth/mfa/backup_codes.py` - One-time backup codes (XXXX-XXXX format)
  - `core/auth/mfa/mfa_manager.py` - MFA enrollment, verification, disable
  - `api/routes/mfa.py` - REST API endpoints for MFA management
  - QR code generation for easy enrollment
  - 10 backup codes per user (SHA-256 hashed)
  - Audit events: MFA_ENROLLED, MFA_VERIFIED, MFA_DISABLED, MFA_BACKUP_USED
  - Settings: `mfa_enabled`, `mfa_required_for_roles`, `mfa_backup_codes_count`
  - 30 unit tests in `test_mfa.py`

### Changed
- **Tests:** ~1824 total (was ~1751, +73 Phase 2 tests)

---

## [1.5.0] - 2026-02-01

### Added - Government Compliance Phase 1 (Cryptographic Hardening)

- **FIPS 140-2 Crypto Mode** (NIST 800-53 SC-13)
  - `core/crypto/fips_provider.py` with `FIPSCryptoProvider` class
  - Restricts algorithms to FIPS-approved only: SHA-256/384/512, AES-128/256, RSA-2048+, ECDSA P-256/384
  - Strict mode raises `FIPSModeError` for non-compliant algorithms
  - Settings: `fips_mode_enabled`, `fips_strict_mode`
  - Singleton: `get_fips_provider()`
  - 25 unit tests in `test_fips_provider.py`

- **TLS/HTTPS Enforcement** (NIST 800-53 SC-8)
  - `api/middleware/tls.py` with redirect and requirement middlewares
  - `TLSRedirectMiddleware`: HTTP → HTTPS redirect (301)
  - `TLSRequirementMiddleware`: Reject HTTP entirely (426 Upgrade Required)
  - `get_ssl_context()`: Configure SSL with min TLS version, mTLS support
  - `validate_tls_config()`: Startup validation of TLS configuration
  - X-Forwarded-Proto support for proxies/load balancers
  - Settings: `tls_enabled`, `tls_cert_path`, `tls_key_path`, `tls_min_version`, `tls_require_client_cert`, `tls_ca_cert_path`, `tls_redirect_http`, `tls_strict_mode`
  - 28 unit tests in `test_tls_middleware.py`

- **Secure Key Storage** (NIST 800-53 SC-12)
  - `core/crypto/key_manager.py` with `KeyManager` class
  - SQLite-backed encrypted key storage with PBKDF2 (480000+ iterations)
  - Key types: SYMMETRIC, ASYMMETRIC_PRIVATE, ASYMMETRIC_PUBLIC, HMAC
  - Key rotation with `rotate_key()` - old key marked as rotated
  - Key revocation with `revoke_key()` - prevents retrieval
  - Export/import with password-based encryption
  - Automatic cleanup of expired keys
  - Settings: `key_storage_path`, `key_default_expiry_days`, `key_auto_rotate_days`
  - Singleton: `get_key_manager()`, `init_key_manager()`
  - 30 unit tests in `test_key_manager.py`

### Changed
- **Tests:** 1751 total (was 1638, +113 Phase 1 tests)

---

## [1.4.0] - 2026-02-01

### Added - Healthcare Compliance (HIPAA)

- **PDF Encryption Module** (HIPAA §164.312(a)(2)(iv) - Encryption)
  - `core/encryption/` module with AES-256 encryption via PyMuPDF
  - `PasswordHandler` for encrypt/decrypt operations
  - `EncryptionValidator` enforces HIPAA-compliant settings
  - `CredentialStore` for secure password storage via keyring
  - `PDFEncryptor` as main orchestrator with batch support
  - CLI commands: `pdfsigner encrypt`, `pdfsigner decrypt`
  - Settings: `encryption_enabled`, `encryption_strength`, `encryption_hipaa_mode`
  - 17 unit tests in `test_encryption_config.py`

- **Enhanced Audit Trail** (HIPAA §164.312(b) - Audit Controls)
  - `AuditIntegrityManager` with HMAC-SHA256 signing
  - Chain hashing (blockchain-style) for tamper detection
  - 14 new event types: ENCRYPT_SUCCESS/FAILURE, DECRYPT_SUCCESS/FAILURE, ACCESS_GRANTED/DENIED, EMERGENCY_ACCESS, SESSION_START/END/TIMEOUT
  - 8 new HIPAA fields: `user_id`, `session_id`, `ip_address`, `user_agent`, `phi_accessed`, `record_hash`, `previous_hash`, `hmac_signature`
  - `verify_chain()` validates entire audit log sequence
  - `verify_audit_file()` generates detailed integrity report
  - 14 unit tests in `test_audit_integrity.py`

- **User Registry** (HIPAA §164.312(d) - Person/Entity Authentication)
  - `core/users/` module with SQLite-backed user management
  - `User` dataclass with roles (VIEWER, SIGNER, ADMIN, AUDITOR, EMERGENCY)
  - `UserRepository` for CRUD operations with certificate binding
  - `CertificateBindingService` auto-creates users from PKCS#11 certificates
  - `Department` dataclass for organizational structure
  - 45 unit tests: `test_user_model.py` (19), `test_user_repository.py` (16), `test_cert_binding.py` (10)

### Fixed
- **Audit integrity verification** - `verify_audit_file()` now correctly returns `False` for non-existent files (was returning `True` due to missing critical issues check)

### Changed
- **Tests:** 1316 total (was 1240, +76 healthcare tests)

---

## [1.3.0] - 2026-02-01

### Added
- **REST API** - FastAPI-based API server (`pdfsigner-api` command)
  - JWT + API key authentication in `api/middleware/auth.py`
  - Sign endpoints: POST /api/v1/sign/, GET status, GET download
  - Validate endpoints: POST /api/v1/validate/, batch
  - Certificates endpoints: list, details, chain
  - 39 integration tests in `tests/integration/test_api.py`

- **Archive Timestamps (PAdES B-LTA)** - Complete long-term validation
  - CLI command `pdfsigner archive-ts` in `cli/archive_ts.py`
  - Phase 6 integration in `pdf_signer.py`
  - `ArchiveTSScheduler` for monitoring in `archive_ts_scheduler.py` (40 tests)
  - Settings: `archive_ts_enabled`, `archive_ts_auto`, `archive_ts_tsa_urls`

### Changed
- GUI validation now shows PAdES level (B-B/T/LT/LTA) in `validation_handler.py`
- Updated `ROADMAP_STATE_OF_ART.md` - EPIC 1 and EPIC 2 completed

---

## [1.1.0] - 2026-02-01

### Added (Tests - 183 new, 1091 total)
- **Unit tests for v1.1 features** - Complete test coverage for all new modules
  - `test_a11y.py` - 34 tests for accessibility helpers
  - `test_shortcuts_window.py` - 39 tests for keyboard shortcuts dialog
  - `test_settings_pages.py` - 34 tests for validation/behavior pages
  - `test_keyboard_shortcuts.py` - 36 tests for action registration
  - `test_pdf_validator_revocation_integration.py` - 14 tests for OCSP/CRL integration
- **E2E tests for v1.1 workflows** - `test_features_v11_e2e.py` with 26 tests
  - Recent files flow, notification flow, settings persistence, accessibility flows

### Added
- **Settings UI for New Features** - Complete preferences integration
  - `gui/settings_pages/validation_page.py` - Revocation checking config (enable, timeout, cache TTL, prefer OCSP)
  - `gui/settings_pages/behavior_page.py` - Recent files + notifications config
  - Auto-save with debounce pattern for all new widgets

- **ShortcutsWindow** - GTK4 native keyboard shortcuts help
  - New file: `gui/dialogs/shortcuts_window.py`
  - Access via `Ctrl+?` (action: `app.shortcuts`)
  - Grouped by Files and Application sections

- **RevocationChecker Integration** - OCSP/CRL validation during signature verification
  - New settings: `revocation_check_enabled`, `revocation_check_timeout`, `revocation_cache_ttl`, `revocation_prefer_ocsp`
  - Integrated in `pdf_validator.py` with `_check_revocation_status()` method
  - UI display in `validation_dialog.py` with status icons (✓/⚠/?)
  - Opt-in by default for backward compatibility

- **Recent Files History** - GTK RecentManager integration
  - New module: `core/recent/` with `RecentFilesManager` singleton
  - New widget: `gui/widgets/recent_files_popover.py` with relative timestamps
  - Settings: `recent_files_enabled`, `recent_files_limit`
  - Auto-registers signed files in history

- **Keyboard Shortcuts** - Productivity enhancements
  - `Ctrl+S` → Sign files
  - `Ctrl+Shift+V` → Validate signatures
  - `Ctrl+L` / `Delete` → Clear file list
  - `Ctrl+?` → Shortcuts window
  - `F1` → About dialog

- **Accessibility (a11y)** - WCAG 2.1 Level A compliance
  - 54 widgets with `set_accessible_name()` and `set_accessible_description()`
  - Screen reader support (Orca, NVDA compatible)
  - All strings internationalized with `_()`

- **System Notifications** - Desktop notifications for background events
  - New module: `core/notifications/` with `NotificationManager` singleton
  - Setting: `system_notifications_enabled`
  - Only notifies when window is not focused (anti-intrusive)
  - Anti-spam for certificate health (once per serial)

### Changed
- **SignatureInfo dataclass** - Added `revocation_status` and `revocation_message` fields
- **MainWindow** - Added recent files button, keyboard actions, validation handler
- **Tests:** 1091 total (was 908)

### Fixed
- **RecentFilesManager SIGABRT** - Use `add_item()` instead of `add_full()` with `Gtk.RecentData`
  - `Gtk.RecentData.groups = [...]` causes SIGABRT (signal, not Python exception) in tests
  - Added graceful fallback when `_manager is None` (CLI/tests without display)

---

## [1.0.2] - 2026-02-01

### Changed
- **Certificate Health UI Redesign** - Banner replaced with header popover
  - New file: `gui/widgets/cert_health_popover.py`
  - Header icon button reflects health status (🔐/⚠️/🔶/🚨/❌)
  - Click opens popover with certificate details
  - Cleaner main window - no banner taking space
- **Revocation Checker:** Use duck typing with `# type: ignore[attr-defined]` for mock compatibility
- **Report Generator:** Use `Flowable` base type and explicit `list[dict]` annotations

### Security
- **urllib3:** Updated to 2.6.3 (fixes CVE-2025-66418, CVE-2025-66471 - DoS vulnerabilities)

### Fixed
- **4 assert statements** replaced with explicit `RuntimeError` in:
  - `gui/dialogs/certificate_details_dialog.py`
  - `gui/signing_handler.py`
  - `i18n/__init__.py` (2 locations)
- **Silent except blocks** - Added logging in `gui/file_list_widget.py`

---

## [1.0.1] - 2026-01-31

### Fixed
- **Audit Logger:** Date iteration bug when querying events across month boundaries (e.g., Jan 31 → Feb). Now uses `day=1` when incrementing months to avoid "day is out of range" errors.

### Changed
- **NSSHandler:** Replace `assert` statements with explicit `RuntimeError` for better error messages in production/optimized mode.
- **Exception Handling:** Add debug logging to 7 silent `except` blocks across `chain_validator.py`, `credential_manager.py`, `content_analyzer.py`, `pdf_validator.py` for improved observability.
- **Stamp Composer:** Extract duplicated font loading logic into `_load_fonts()` helper function (DRY principle).
- **Report Generator:** Fix type annotations to use `list[Paragraph | Spacer | Table]` for proper mypy validation.

### Security
- Add `# nosec` comments with explanations for Bandit false positives in `audit_event.py` and `nss_setup.py`.

---

## [1.0.0] - 2026-01-27

### Added - Major Security & Compliance Features

- **OCSP/CRL Certificate Revocation Checking** (Feature 1.1)
  - `core/certificate/revocation_checker.py` - OCSPChecker + CRLChecker classes
  - OCSP-first strategy with automatic CRL fallback
  - Intelligent caching: TTL for OCSP, nextUpdate for CRL
  - RevocationStatus enum: GOOD, REVOKED, UNKNOWN, ERROR
  - Extraction of revocation reason and time when available
  - 32 new unit tests with mocked HTTP responses

- **Certificate Chain Validation** (Feature 1.2)
  - `core/certificate/chain_validator.py` - Full X.509 chain validation
  - `core/certificate/trust_store.py` - System CA loading (Debian, RedHat, Alpine, etc.)
  - ChainStatus enum: VALID, PARTIAL_CHAIN, UNTRUSTED_ROOT, INVALID_SIGNATURE, EXPIRED
  - RSA signature verification at each chain level
  - AKI/SKI handling, cycle prevention, max depth limit (10)
  - Custom CA support for enterprise PKI
  - 13 new unit tests with generated certificates

- **Validation Reports Export** (Feature 2.1)
  - `core/reports/report_generator.py` - PDF/CSV/JSON report generation
  - `gui/dialogs/export_report_dialog.py` - GTK4 export dialog
  - PDF reports with colored status tables and certificate details
  - CSV reports compatible with Excel
  - JSON reports for API integration
  - ReportOptions for customizable output
  - 17 new unit tests

- **Certificate Details Viewer** (Feature 2.2)
  - `core/certificate/x509_parser.py` - Complete X.509 field extraction
  - `gui/dialogs/certificate_details_dialog.py` - 4-tab GTK4/libadwaita dialog
  - Tabs: General, Details, Extensions, Thumbprints
  - Copy buttons for serial number and fingerprints
  - All X.509 fields: DN, validity, key usage, SANs, CRL/OCSP URLs, policies
  - 13 new unit tests

- **Signature Metadata Fields** (Feature 2.3)
  - Settings: `default_signature_reason`, `default_signature_location`, `default_signature_contact`
  - OptionsDialog: "Signature Information" section with 3 entry fields
  - CLI flags: `--reason`, `--location`, `--contact`
  - Values passed to pyHanko PdfSignatureMetadata
  - 9 new unit tests

- **Audit Trail System** (Feature 2.4)
  - `core/audit/` module with JSON Lines format (monthly rotation)
  - 8 event types: sign_success/failure, validate_success/failure, token_login/logout, etc.
  - Thread-safe singleton logger with configurable retention (1-3650 days)
  - Query interface with date/type filters and CSV export
  - Helper functions: `log_signing_event()`, `log_validation_event()`, etc.
  - Settings: `audit_enabled` (default: true), `audit_retention_days` (default: 90)
  - ISO 27001/GDPR/eIDAS compatible logging
  - 20 new unit tests

- **Unit tests expansion** - 246 new tests (622 → 868 total, 89% coverage)

### Changed
- Refactored sign_pdf() into 4 phases for testability
- Specific PKCS#11 exceptions replace generic catches
- README updated with new features and test count

---

## [0.9.4] - 2026-01-26

### Added
- **Template override in signing dialog** - Dropdown to select template before signing
  - Override default template without going to Settings
  - Shows all available templates: built-in + custom
  - "Invisible (metadata only)" option for hidden signatures
  - Dynamic visibility: Page/Position options hide when invisible selected
- **Settings auto-save with debounce** - Changes save automatically after 500ms
  - Removed manual "Save" button from Advanced page
  - Uses `GLib.timeout_add()` for debounced saves

### Changed
- **Options dialog redesign** - Cleaner layout with compact header
  - Template selector as primary option
  - Grid-based Page/Position selectors
  - Template name passed through entire signing pipeline

---

## [0.9.3] - 2026-01-26

### Added
- **Persistent progress dialog** - No longer auto-closes after signing
  - Shows output filename per file (`→ doc_signed.pdf`)
  - Folder button (📁) opens containing directory in file manager
  - "Close" button with suggested-action style when complete
- **PIN cache integration** - `SigningHandler` now uses `pin_cache` when enabled
  - Checks for cached PIN before showing PIN dialog
  - Default changed to **disabled** (more secure)
- **GUI logging configuration** - Log level from settings applied at startup and on save

### Fixed
- **PIN cache not working** - Handler cached settings at init, never updated; now gets fresh settings
- **File list not clearing** - `_on_remove_clicked` failed to find `_file_paths`; fixed widget traversal
- **Log level changes ignored** - GUI never configured loguru; now applies immediately

---

## [0.9.2] - 2026-01-15

### Changed
- **Certificate health UI** - Uses banner widget for certificate status display
  - Color-coded status (🔐/⚠️/🔶/🚨/❌) based on expiry
  - Shows certificate details (subject, issuer, expiry date)
  - Banner widget: `gui/widgets/cert_health_banner.py`

---

## [0.9.1] - 2026-01-13

### Changed
- **Test coverage boost** - 520 total tests (was 393)
  - 5 modules at 100% coverage: `settings.py`, `position_finder.py`, `multi_signer.py`, `lta_handler.py`, `health_status.py`
  - `content_analyzer.py`: 78% → 97%, `pdf_validator.py`: 73% → 96%
- **Coverage configuration** - Excludes GUI/UI code, core coverage: 87%

---

## [0.9.0] - 2026-01-10

### Added
- **Certificate Health Dashboard Complete** - GitHub Issue #6 fully implemented
  - Collapsible banner: compact by default, expandable for details
  - CSS animations: fade-in, pulse for critical/expired states
  - Toast notifications for expiry warnings (WARNING/ALERT/CRITICAL/EXPIRED)
  - Color-coded backgrounds, text, and progress bars
  - New files: `gui/styles.css`, `gui/widgets/cert_health_banner.py`
  - Health levels: OK (>60 days), WARNING (31-60), ALERT (8-30), CRITICAL (1-7), EXPIRED (≤0)
- **Custom CSS system** - `styles.css` loaded at app startup via `Gtk.CssProvider`

---

## [0.8.9] - 2026-01-08

### Added
- **Certificate Health Dashboard** - Initial implementation (Issue #6)
  - Core modules: `core/certificate/health_status.py`
  - 41 new tests for health status logic
- **Total tests: 393** (was 360)

---

## [0.8.8] - 2026-01-06

### Fixed
- **First-run settings validation** - NSS path existence no longer validated at settings load
  - Allows app to start cleanly on first run (before NSS wizard creates the database)
  - Existence check moved to runtime (NSSChecker)

---

## [0.8.7] - 2026-01-04

### Changed
- **NSS wizard window height** - Increased from 400px to 480px for better button visibility

---

## [0.8.6] - 2026-01-02

### Fixed
- **Hybrid PDF validation** - PDFs with hybrid-reference format now validate correctly
  - Uses `PdfFileReader(strict=False)` to allow mixed xref tables/streams
  - Fallback handler extracts signer info even when full validation fails
- **Word wrap in validation dialog** - Long text (issuer, signer) now wraps properly

### Changed
- **Simplified signature display** - Main window shows only signature count + icon
  - No signer name text (prevents window expansion)
  - Click ⓘ button for full details in dialog

### Added
- **TSA integration tests** - Added tests for DigiCert and Sectigo TSA servers
  - All 15 TSA tests pass (FreeTSA, DigiCert, Sectigo)

---

## [0.8.5] - 2025-12-28

### Added
- **Signature viewer in GUI** - When adding files with existing signatures:
  - Shows signature count: "2 signature(s)"
  - Info button (ⓘ) opens ValidationResultDialog with full details
  - Async validation in background (doesn't slow down adding files)
  - Cached results for instant dialog display
- **Multiple signatures support** - PDF signatures are incremental (PAdES)

### Fixed
- **GTK4 dialog** - ValidationResultDialog now uses `present()` instead of deprecated `run()`

### Added
- **New tests** - 13 tests for file_list_widget logic, 4 tests for hybrid PDF handling

---

## [0.8.3] - 2025-12-20

### Added
- **GUI unit tests** - 26 tests for SigningHandler and ValidationHandler
  - Uses GTK mocks (no display required)
  - `conftest_gui.py` provides mock GTK4/Adwaita objects

### Changed
- **Removed release workflow** - Manual releases during development
- **Synced Debian changelog** - All versions 0.8.0-0.8.3

---

## [0.8.2] - 2025-12-18

### Fixed
- **AppStream metainfo** - Updated with all release history, fixed screenshot URLs
- **Release workflow** - Added missing pip dependencies (pillow, build, hatchling)

---

## [0.8.1] - 2025-12-15

### Changed
- **Refactored nss_handler.py** - Extracted PKCS#11 paths to `pkcs11_libs.py`
- **Removed CI workflow** - No automated checks on push
- **Updated packaging** - Added `qrcode pillow` to Flatpak/AppImage build scripts

---

## [0.8.0] - 2025-12-10

### Added
- **QR verification code** - Optional QR in visible signatures
  - Contains: document hash (SHA-256), signer name, timestamp
  - CLI flag: `--qr-code` (enables `--visible` automatically)
  - GUI checkbox in signature options dialog
  - New modules: `core/stamp/qr_generator.py`, `core/stamp/stamp_composer.py`
  - New dependencies: `qrcode[pil]`, `pillow`
- **Dry-run QR support** - Real QR generation with demo data (150 DPI quality)

---

## [0.7.0] - 2025-12-01

### Added
- **Complete packaging system** - AppImage, .deb, Flatpak
- **GitHub Actions release workflow** - Automated builds on tag push
- **AppStream metadata** - For software centers
- **Multi-resolution icons** - 16x16 to 512x512

### Changed
- **Debian 13+ / Python 3.12+** - Updated minimum requirements
- **GNOME Platform 49** - Updated Flatpak runtime

---

## [0.6.0] - 2025-11-20

### Changed
- **289 tests** - 79 new tests for signer module
- **92% coverage** on core/signer/ module (was 84%)
- **100% coverage** on lta_handler.py
- **97% coverage** on signature_field.py (was 14%)
- **90% coverage** on multi_signer.py (was 25%)

---

## [0.5.0] - 2025-11-10

### Added
- **NSS Setup Wizard** - First-run wizard auto-configures NSS database
- **Izenpe TSA** - Basque Country timestamp server

### Changed
- **210 tests** (31 new for NSS setup)
- Default TSA: local time (no external TSA required)
- Removed help button from UI

---

## [0.4.0] - 2025-11-01

### Added
- **Multi-token PKCS#11 support** - Auto-detection of SafeNet, YubiKey, Nitrokey, OpenSC, Feitian, SoftHSM, nCipher
- Improved library search with multiple paths per vendor
- Better error messages listing all supported tokens

---

## [0.3.1] - 2025-10-20

### Fixed
- TSA HTTPTimeStamper API (correct parameter: `timeout`)

### Added
- TSA integration tests verifying FreeTSA works
- CI/CD pipeline with GitHub Actions
- Pre-commit hooks (ruff, mypy, bandit)
- MIT LICENSE and CONTRIBUTING.md
- Expanded test suite to 179 tests (33% coverage)

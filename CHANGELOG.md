# Changelog

All notable changes to PDFSigner are documented here.

Format: [SemVer](https://semver.org/) with `Added | Changed | Fixed | Security` sections.

---

## [1.1.0] - 2026-02-01

### Added
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
- **Tests:** 800 total (consolidated from previous count)

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

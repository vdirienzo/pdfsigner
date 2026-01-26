# Changelog

All notable changes to PDFSigner are documented here.

Format: [SemVer](https://semver.org/) with `Added | Changed | Fixed | Security` sections.

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
- **Certificate health UI redesign** - Moved from banner to header popover
  - New header icon button (🔐/⚠️/🔶/🚨/❌) reflects health status
  - Click opens popover with certificate details (subject, issuer, expiry, progress)
  - Cleaner main window - no banner taking up space
  - New file: `gui/widgets/cert_health_popover.py`
  - Banner widget (`cert_health_banner.py`) kept as legacy reference
- **First popover widget** in the project - establishes pattern for future UI

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

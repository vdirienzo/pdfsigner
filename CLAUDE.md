# PDFSigner - Project Memory

> **Purpose:** This file helps Claude (or any AI assistant) understand the project context quickly.
> **Last Updated:** 2026-01-14
> **Version:** 0.8.4
> **Author:** Homero Thompson del Lago del Terror

---

## Project Overview

**PDFSigner** is a digital PDF signing application for Linux/GNOME that supports multiple USB cryptographic tokens via PKCS#11/NSS.

### Key Features
- PAdES-LTV signatures with TSA timestamp
- GTK4/libadwaita standalone GUI
- CLI with subcommands (sign, validate, list-certs)
- Dry-run mode for testing without real token
- Visible signature with smart positioning
- **QR verification code** - Optional QR in visible signatures (hash, signer, timestamp)
- **Signature viewer** - Display existing signatures when adding files (signer, timestamp, validity)
- Batch signing with PIN cache
- **Multi-token PKCS#11 support**

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Python | 3.12+ |
| Package Manager | uv |
| GUI Framework | GTK4 + libadwaita |
| PDF Signing | pyHanko (PAdES-LTV) |
| PDF Analysis | PyMuPDF (fitz) |
| Token/Crypto | NSS + python-pkcs11 |
| Config | pydantic-settings |
| Logging | loguru |
| Linting | Ruff |
| Type Check | mypy |
| Security | Bandit, Safety |
| Testing | pytest (360 tests) |

---

## Supported Tokens (PKCS#11)

Auto-detected in priority order by `nss_handler.py`:

| Priority | Token | Library File | Notes |
|----------|-------|--------------|-------|
| 1 | SafeNet/Thales | `libeToken.so` | eToken 5110, 5300 |
| 1 | Luna HSM | `libCryptoki2_64.so` | Enterprise HSM |
| 2 | YubiKey | `libykcs11.so` | PIV mode only |
| 3 | Nitrokey | `libnethsm.so` | Pro/HSM models |
| 4 | OpenSC | `opensc-pkcs11.so` | Generic smart cards |
| 5 | Feitian | `libcastle.so` | ePass tokens |
| 6 | SoftHSM | `libsofthsm2.so` | Testing only |
| 7 | nCipher | `libcknfast.so` | Enterprise HSM |
| 8 | NSS | `libsoftokn3.so` | Fallback |

**Adding new tokens:** Edit `PKCS11_LIB_PATHS` constants in `src/pdfsigner/core/token/nss_handler.py`

---

## Project Structure

```
pdfsigner/
├── src/pdfsigner/
│   ├── cli/                    # CLI commands (sign.py, validate.py, etc.)
│   ├── config/                 # Settings from ~/.config/pdfsigner/config.toml
│   ├── core/
│   │   ├── mock/               # Dry-run simulation (MockBatchManager, stamp_simulator)
│   │   ├── pdf_analyzer/       # Content analysis, position finding
│   │   ├── signer/             # PAdES signing (pdf_signer, batch_manager, lta_handler)
│   │   ├── stamp/              # QR code generation (qr_generator, stamp_composer)
│   │   ├── token/              # NSS/PKCS#11 (nss_handler, cert_selector, pin_cache)
│   │   ├── setup/              # NSS wizard (nss_checker, nss_setup)
│   │   └── validator/          # Signature validation
│   ├── gui/                    # GTK4 standalone app (app.py, main_window.py)
│   └── ui/dialogs/             # Reusable dialogs (options, pin, progress, nss_wizard)
├── data/
│   ├── com.pdfsigner.app.desktop    # Desktop entry
│   ├── com.pdfsigner.app.metainfo.xml  # AppStream metadata
│   └── icons/                  # Multi-resolution icons (16-512px)
├── debian/                     # Debian packaging (control, rules, changelog)
├── flatpak/
│   └── com.pdfsigner.app.yaml  # Flatpak manifest
├── scripts/
│   ├── build-packages.sh       # Main packaging script
│   ├── appimage/               # AppImage build scripts
│   ├── debian/                 # Debian build script
│   ├── flatpak/                # Flatpak build script
│   ├── install.sh              # Multi-distro installer
│   └── uninstall.sh            # Uninstaller
├── tests/
│   ├── unit/                   # Unit tests (343 tests including GUI)
│   │   ├── conftest_gui.py    # GTK mocks for GUI testing
│   │   ├── test_signing_handler.py  # 16 GUI tests
│   │   └── test_validation_handler.py  # 10 GUI tests
│   └── integration/            # Integration tests (TSA, etc.)
├── config/                     # Example config files
├── .pre-commit-config.yaml     # Pre-commit hooks
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # MIT License
└── README.md
```

---

## How to Run

### GUI (Standalone)
```bash
cd /home/user/projects/pdfsigner
uv run pdfsigner-gui
```

### CLI
```bash
uv run pdfsigner sign file.pdf
uv run pdfsigner validate file_signed.pdf
uv run pdfsigner list-certs
```

### Dry-Run Mode (No Token Required)
```bash
uv run pdfsigner --dry-run sign file.pdf
# Or set in ~/.config/pdfsigner/config.toml: dry_run = true
```

---

## Key Implementation Details

### Coordinate Systems
- **PyMuPDF (fitz):** Origin (0,0) at TOP-LEFT, Y increases downward
- **PDF Standard:** Origin (0,0) at BOTTOM-LEFT, Y increases upward
- **Conversion needed** in `position_finder.py` when calculating stamp positions for pyHanko

### Stamp Customization (Real Signatures)
Uses pyHanko's `TextStampStyle` with placeholders:
- `%(signer)s` - Certificate CN (signer name)
- `%(ts)s` - Timestamp

### TSA (Timestamp Authority)
- **Default TSA:** `https://freetsa.org/tsr` (free, no auth required)
- **Protocol:** RFC 3161 (handled by pyHanko's HTTPTimeStamper)
- **Algorithm:** SHA-256
- **Important:** Use `timeout` parameter (not `https_timeout`) in HTTPTimeStamper

### Output Files
- Suffix: `_signed` (changed from `_firmado`)
- Example: `document.pdf` → `document_signed.pdf`

### Language
- All UI/messages in **English**
- Code comments in English
- User documentation in English

---

## Configuration

**Location:** `~/.config/pdfsigner/config.toml`

Key settings:
```toml
nss_db_path = "/home/user/.nss"
tsa_url = "https://freetsa.org/tsr"
dry_run = false
output_suffix = "_signed"
log_level = "INFO"
```

---

## Testing

```bash
# Run all tests
uv run pytest -v

# With coverage
uv run pytest --cov=src --cov-report=term-missing

# Unit tests only
uv run pytest tests/unit/ -v

# Integration tests (requires internet for TSA)
uv run pytest tests/integration/ -v

# Specific test
uv run pytest tests/unit/test_position_finder.py -v
```

### Current Coverage
- **360 tests passing** (including 39 GUI tests)
- **~45% overall coverage**
- Key modules:
  - signer/ module: **92%** (lta_handler 100%, signature_field 97%, batch_manager 97%)
  - exceptions (100%), stamp_simulator (100%), pin_cache (98%)
- GUI tests use mocks (no display required)

---

## Development Workflow

### Code Quality
```bash
# Lint and format
uv run ruff check --fix .
uv run ruff format .

# Type checking
uv run mypy src/

# Security scan
uv run bandit -r src/
uv run safety check
```

### Pre-commit Hooks
```bash
# Install hooks (one time)
uv run pre-commit install

# Run manually
uv run pre-commit run --all-files
```

---

## Important Files

| File | Purpose |
|------|---------|
| `lta_handler.py` | TSA timestamp integration (HTTPTimeStamper) |
| `pdf_signer.py` | Main PDF signing logic with pyHanko |
| `batch_manager.py` | Batch signing orchestration |
| `nss_handler.py` | **NSS/PKCS#11 token communication** (multi-token support) |
| `position_finder.py` | Smart signature position calculation |
| `stamp_simulator.py` | Dry-run stamp simulation |
| `qr_generator.py` | QR code generation (hash, signer, timestamp) |
| `stamp_composer.py` | Image composition (text + QR) using Pillow |

### nss_handler.py Key Details
- Uses `pkcs11_libs.py` for token vendor library paths
- `_find_pkcs11_lib()` searches libraries in priority order
- First found library is used
- Logs which token type was detected

---

## Pending Features / Ideas

1. **Drag & Drop** - Drop PDFs directly into GUI window
2. **Signature Profiles** - Save preset configurations
3. **Verification in GUI** - Button to verify existing signatures
4. **Preview Position** - Show thumbnail with stamp position before signing
5. **Certificate Expiry Notification** - Warn when cert is expiring
6. **Batch from Folder** - Sign all PDFs in a directory

---

## Repository

- **GitHub:** https://github.com/vdirienzo/pdfsigner
- **Branch:** dev (main development)
- **License:** MIT

---

## Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Token not detected | Check NSS DB path, run `certutil -L -d ~/.nss` |
| No PKCS#11 library | Install token driver, check `nss_handler.py` for supported paths |
| Dry-run not working | Set `dry_run = true` in config or use `--dry-run` flag |
| Config not loading | Check TOML syntax in `~/.config/pdfsigner/config.toml` |
| GUI won't start | Verify GTK4 and libadwaita are installed |
| TSA timeout | Check internet connection, try alternate TSA URL |
| HTTPTimeStamper error | Use `timeout` param, not `https_timeout` |
| AppImage libfuse error | Debian 13+: use `--appimage-extract` then `./squashfs-root/AppRun` |

---

## Packaging & Distribution

### Build Packages

```bash
# Build all formats
./scripts/build-packages.sh --all

# Individual formats
./scripts/build-packages.sh --flatpak   # Recommended
./scripts/build-packages.sh --deb
./scripts/build-packages.sh --appimage

# Clean build directories
./scripts/build-packages.sh --clean
```

### Output

```
dist/
├── appimage/PDFSigner-{VERSION}-x86_64.AppImage
├── deb/pdfsigner_{VERSION}-1_all.deb
└── flatpak/PDFSigner-{VERSION}.flatpak
```

### Installation Commands

**Flatpak (Recommended):**
```bash
flatpak install --user dist/flatpak/PDFSigner-*.flatpak
flatpak run com.pdfsigner.app
```

**Debian:**
```bash
sudo dpkg -i dist/deb/pdfsigner_*.deb
sudo apt install -f  # if dependencies missing
pdfsigner-gui
```

**AppImage:**
```bash
# With libfuse2:
chmod +x PDFSigner-*.AppImage && ./PDFSigner-*.AppImage

# Debian 13+ (no libfuse2):
./PDFSigner-*.AppImage --appimage-extract
./squashfs-root/AppRun
# Or install: sudo mv squashfs-root /opt/pdfsigner
```

### Manual Releases

During development, releases are built locally:
```bash
# Build all formats
./scripts/build-packages.sh --all

# Create release tag (if needed)
git tag v0.8.3
git push origin v0.8.3
```

### Key Packaging Files

| File | Purpose |
|------|---------|
| `scripts/build-packages.sh` | Main build script (shows install instructions) |
| `flatpak/com.pdfsigner.app.yaml` | Flatpak manifest (GNOME Platform 49) |
| `debian/control` | Debian dependencies |
| `debian/rules` | Debian build rules (skips tests) |
| `data/com.pdfsigner.app.metainfo.xml` | AppStream metadata |
| `data/icons/` | Multi-resolution icons (16-512px) |
| `screenshots/` | App screenshots for software centers |

### Build Dependencies

| Format | Packages |
|--------|----------|
| **Flatpak** | `flatpak`, `flatpak-builder`, `org.gnome.Platform//49`, `org.gnome.Sdk//49` |
| **Debian** | `debhelper`, `dh-python`, `pybuild-plugin-pyproject`, `python3-hatchling` |
| **AppImage** | `python3`, `pip`, `wget` (downloads appimagetool) |

---

## Recent Changes (v0.8.8)

- **Fixed first-run settings validation** - NSS path existence no longer validated at settings load
  - Allows app to start cleanly on first run (before NSS wizard creates the database)
  - Existence check moved to runtime (NSSChecker)

### Previous (v0.8.7)

- **NSS wizard window height** - Increased from 400px to 480px for better button visibility

### Previous (v0.8.6)

- **Hybrid PDF validation fixed** - PDFs with hybrid-reference format now validate correctly
  - Uses `PdfFileReader(strict=False)` to allow mixed xref tables/streams
  - Fallback handler extracts signer info even when full validation fails
- **Simplified signature display** - Main window shows only signature count + icon
  - No signer name text (prevents window expansion)
  - Click ⓘ button for full details in dialog
- **Word wrap in validation dialog** - Long text (issuer, signer) now wraps properly
- **TSA integration tests** - Added tests for DigiCert and Sectigo TSA servers
  - All 15 TSA tests pass (FreeTSA, DigiCert, Sectigo)

### Previous (v0.8.4-v0.8.5)

- **Signature viewer in GUI** - When adding files with existing signatures:
  - Shows signature count: "2 signature(s)"
  - Info button (ⓘ) opens ValidationResultDialog with full details
  - Async validation in background (doesn't slow down adding files)
  - Cached results for instant dialog display
- **Multiple signatures support** - PDF signatures are incremental (PAdES), adding new signatures doesn't break existing ones
- **Fixed GTK4 dialog** - ValidationResultDialog now uses `present()` instead of deprecated `run()`
- **New tests** - 13 tests for file_list_widget logic, 4 tests for hybrid PDF handling

### Previous (v0.8.3)

- **GUI unit tests** - 26 tests for SigningHandler and ValidationHandler
  - Uses GTK mocks (no display required)
  - `conftest_gui.py` provides mock GTK4/Adwaita objects
- **Removed release workflow** - Manual releases during development
- **Synced Debian changelog** - All versions 0.8.0-0.8.3

### Previous (v0.8.2)

- **Fixed AppStream metainfo** - Updated with all release history, fixed screenshot URLs
- **Fixed release workflow** - Added missing pip dependencies (pillow, build, hatchling)

### Previous (v0.8.1)

- **Refactored nss_handler.py** - Extracted PKCS#11 paths to `pkcs11_libs.py`
- **Removed CI workflow** - No automated checks on push
- **Updated packaging** - Added `qrcode pillow` to Flatpak/AppImage build scripts

### Previous (v0.8.0)

- **QR verification code** - Optional QR in visible signatures
  - Contains: document hash (SHA-256), signer name, timestamp
  - CLI flag: `--qr-code` (enables `--visible` automatically)
  - GUI checkbox in signature options dialog
  - New modules: `core/stamp/qr_generator.py`, `core/stamp/stamp_composer.py`
  - New dependencies: `qrcode[pil]`, `pillow`
- **Dry-run QR support** - Real QR generation with demo data (150 DPI quality)

### Previous (v0.7.0)

- **Complete packaging system** - AppImage, .deb, Flatpak
- **GitHub Actions release workflow** - Automated builds on tag push
- **AppStream metadata** - For software centers
- **Multi-resolution icons** - 16x16 to 512x512
- **Debian 13+ / Python 3.12+** - Updated minimum requirements
- **GNOME Platform 49** - Updated Flatpak runtime

### Previous (v0.6.0)

- **289 tests** - 79 new tests for signer module
- **92% coverage** on core/signer/ module (was 84%)
- **100% coverage** on lta_handler.py
- **97% coverage** on signature_field.py (was 14%)
- **90% coverage** on multi_signer.py (was 25%)

### Previous (v0.5.0)

- **NSS Setup Wizard** - First-run wizard auto-configures NSS database
- **Izenpe TSA added** - Basque Country timestamp server
- **210 tests** (31 new for NSS setup)
- Default TSA: local time (no external TSA required)
- Removed help button from UI

### Previous (v0.4.0)
- **Multi-token PKCS#11 support** - Auto-detection of SafeNet, YubiKey, Nitrokey, OpenSC, Feitian, SoftHSM, nCipher
- Improved library search with multiple paths per vendor
- Better error messages listing all supported tokens

### Previous (v0.3.1)
- Fixed TSA HTTPTimeStamper API (correct parameter: `timeout`)
- Added TSA integration tests verifying FreeTSA works
- Added CI/CD pipeline with GitHub Actions
- Added pre-commit hooks (ruff, mypy, bandit)
- Added MIT LICENSE and CONTRIBUTING.md
- Expanded test suite to 179 tests (33% coverage)

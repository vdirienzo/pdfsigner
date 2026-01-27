<p align="center">
  <img src="src/pdfsigner/ui/icon/icon512.png" alt="PDFSigner Logo" width="128" height="128">
</p>

<h1 align="center">PDFSigner</h1>

<p align="center">
  <strong>Digital PDF Signing with Hardware Cryptographic Tokens</strong>
  <br>
  <em>PAdES-LTV compliant signatures for legally valid documents</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT"></a>
  <a href="https://gtk.org/"><img src="https://img.shields.io/badge/GTK-4.0-4A86CF?style=flat-square&logo=gnome&logoColor=white" alt="GTK4"></a>
  <a href="https://github.com/pyhanko/pyhanko"><img src="https://img.shields.io/badge/pyHanko-PAdES--LTV-orange?style=flat-square" alt="pyHanko"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-868%20passing-success?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-89%25%20core-blue?style=flat-square" alt="Coverage">
</p>

---

## Features

| Security | User Experience |
|----------|-----------------|
| PAdES-LTV signatures with long-term validation | GTK4/libadwaita native GNOME interface |
| TSA timestamps for legal compliance | Drag & drop file handling |
| Multi-token support (SafeNet, YubiKey, Nitrokey) | Batch signing with progress tracking |
| OCSP/CRL certificate revocation checking | Signature metadata (reason, location, contact) |
| Chain validation with system trust store | QR verification codes in stamps |

---

## Quick Start

### Dry-Run Mode (No Token Required)

```bash
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# GUI
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui

# CLI
uv run pdfsigner --dry-run sign document.pdf
```

### With Hardware Token

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libnss3-tools

# Clone and install
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync

# Configure PyGObject access
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# Set up NSS database
mkdir -p ~/.nss && certutil -N -d sql:$HOME/.nss

# Run
uv run pdfsigner-gui
```

---

## Screenshots

| Main Window | Signature Options |
|-------------|-------------------|
| ![Main Window](screenshots/01.png) | ![Options](screenshots/02.png) |

| Settings | Advanced |
|----------|----------|
| ![Settings](screenshots/03.png) | ![Advanced](screenshots/04.png) |

---

## Supported Tokens

| Token | Library | Status |
|-------|---------|--------|
| SafeNet/Thales eToken | `libeToken.so` | Tested |
| Luna HSM | `libCryptoki2_64.so` | Supported |
| YubiKey | `libykcs11.so` | Supported |
| Nitrokey | `libnethsm.so` | Supported |
| OpenSC | `opensc-pkcs11.so` | Supported |
| SoftHSM | `libsofthsm2.so` | Tested |

> Add new tokens: Edit `PKCS11_LIB_PATHS` in `src/pdfsigner/core/token/pkcs11_libs.py`

---

## Installation

### System Dependencies

**Debian/Ubuntu:**
```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 libnss3-tools opensc
```

**Fedora:**
```bash
sudo dnf install python3-gobject gtk4 libadwaita nss-tools opensc
```

**Arch Linux:**
```bash
sudo pacman -S python-gobject gtk4 libadwaita nss opensc
```

### Pre-built Packages

| Format | Command |
|--------|---------|
| Snap | `sudo snap install pdfsigner && sudo snap connect pdfsigner:raw-usb` |
| Flatpak | `./scripts/build-packages.sh --flatpak` |
| AppImage | `./scripts/build-packages.sh --appimage` |
| Debian | `./scripts/build-packages.sh --deb` |

---

## Configuration

Config file: `~/.config/pdfsigner/config.toml`

```toml
# NSS Database
nss_db_path = "/home/YOUR_USERNAME/.nss"

# TSA (Timestamp Authority)
tsa_url = "https://freetsa.org/tsr"

# Signature Defaults
default_visible = true
default_page = "last"
signature_template = "with_qr"
output_suffix = "_signed"

# PIN Cache
pin_cache_enabled = true
pin_cache_timeout_seconds = 300

# Audit Trail
audit_enabled = true
audit_retention_days = 90

# Appearance
theme = "system"
log_level = "INFO"
```

### TSA Servers

| Provider | URL |
|----------|-----|
| FreeTSA | `https://freetsa.org/tsr` |
| DigiCert | `http://timestamp.digicert.com` |
| Sectigo | `http://timestamp.sectigo.com` |

---

## Usage

### GUI

```bash
uv run pdfsigner-gui
```

**Shortcuts:** `Ctrl+O` Open | `Ctrl+,` Settings | `Ctrl+Q` Quit

### CLI

```bash
# Sign
uv run pdfsigner sign document.pdf
uv run pdfsigner sign document.pdf --visible --page last
uv run pdfsigner sign *.pdf

# Validate
uv run pdfsigner validate document_signed.pdf

# List certificates
uv run pdfsigner list-certs
```

---

## Signature Templates

| Template | Description |
|----------|-------------|
| `default` | Signer name + date |
| `minimal` | Single line compact |
| `corporate` | Name + organization + date |
| `with_qr` | QR code + name + date + "Verifiable" |

Templates location: `src/pdfsigner/config/builtin_templates/`

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                       PDFSigner                             │
├────────────────────────────────────────────────────────────┤
│  GUI (GTK4)  │  CLI (argparse)  │  Config (TOML)          │
├────────────────────────────────────────────────────────────┤
│                      CORE LAYER                             │
│  BatchManager → PDFSigner → LTAHandler (TSA)               │
│       ↓             ↓                                       │
│  NSSHandler    PositionFinder    PDFValidator              │
│  (PKCS#11)      (PyMuPDF)        (verify)                  │
├────────────────────────────────────────────────────────────┤
│  USB Token  │  NSS Database  │  TSA Server                 │
└────────────────────────────────────────────────────────────┘
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `core/signer/pdf_signer.py` | PAdES-LTV signing with pyHanko |
| `core/signer/batch_manager.py` | Multi-file orchestration |
| `core/signer/lta_handler.py` | TSA timestamp integration |
| `core/token/nss_handler.py` | PKCS#11 token communication |
| `core/audit/audit_logger.py` | Structured audit logging |
| `core/validator/pdf_validator.py` | Signature verification |

---

## Development

```bash
# Setup
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync --all-extras
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# Tests
uv run pytest -v                                    # All tests (868)
uv run pytest --cov=src --cov-report=term-missing  # With coverage

# Code quality
uv run ruff check --fix . && uv run ruff format .  # Lint + format
uv run mypy src/                                   # Type check
uv run pre-commit run --all-files                  # Pre-commit hooks
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named 'gi'` | `echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth` |
| Token not detected | Check: `lsusb`, `modutil -list -dbdir sql:$HOME/.nss` |
| TSA timeout | Try: `tsa_url = "http://timestamp.digicert.com"` |
| AppImage libfuse error | `./PDFSigner-*.AppImage --appimage-extract && ./squashfs-root/AppRun` |

---

## Changelog

### [1.0.0] - 2026-01-27

#### Added
- **Audit Trail System** - Structured JSON logging for compliance
  - Event types: signing, validation, token operations
  - Configurable retention (1-3650 days)
  - Export to CSV/JSON
- **Certificate Validation** - Enhanced X.509 validation
- **Signature Metadata** - Reason, location, contact info fields

#### Changed
- Improved UI with metadata input fields
- 868 tests with 89% core coverage

### [0.9.5] - 2026-01-26

#### Added
- **Snap Package Support** - Native Snap packaging
- **E2E Test Suite** - 37 comprehensive tests

#### Fixed
- Multi-page signing with visual stamps
- Position preference now always respected

### [0.9.4] - 2026-01-26

#### Added
- **Template Editor Dialog** - Create custom signature templates
- **Per-signing template override**

<details>
<summary>Earlier releases</summary>

### [0.9.0 - 0.9.3]
- Certificate Health Dashboard
- PIN cache improvements
- 520+ tests

### [0.8.x]
- QR verification codes
- NSS Setup Wizard
- Multi-token PKCS#11 support
- Flatpak, AppImage, Debian packaging

### [0.1.0 - 0.7.0]
- Initial release with PAdES-LTV signatures
- GTK4 GUI and CLI
- Dry-run mode

</details>

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with Python, GTK4, and pyHanko</sub>
</p>

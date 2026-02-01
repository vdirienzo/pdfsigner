<p align="center">
  <img src="src/pdfsigner/ui/icon/icon512.png" alt="PDFSigner Logo" width="128" height="128">
</p>

<h1 align="center">PDFSigner</h1>

<p align="center">
  <strong>Enterprise-Grade Digital PDF Signing</strong>
  <br>
  <em>PAdES B-LTA compliant signatures with REST API</em>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT"></a>
  <a href="https://gtk.org/"><img src="https://img.shields.io/badge/GTK-4.0-4A86CF?style=flat-square&logo=gnome&logoColor=white" alt="GTK4"></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-REST_API-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PAdES-B--LTA-orange?style=flat-square" alt="PAdES B-LTA">
  <img src="https://img.shields.io/badge/tests-1240%2B%20passing-success?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-87%25%20core-blue?style=flat-square" alt="Coverage">
</p>

---

## ✨ Highlights

| Category | Features |
|----------|----------|
| **Compliance** | PAdES B-LTA (highest level), eIDAS compliant, DSS embedding, archive timestamps |
| **Interfaces** | GTK4 GUI, CLI, REST API (FastAPI) |
| **Security** | PKCS#11 hardware tokens, OCSP/CRL revocation, chain validation, audit trail |
| **Integration** | JWT + API key auth, async signing jobs, webhook-ready |
| **UX** | Drag & drop, batch signing, keyboard shortcuts, recent files, accessibility |

---

## 🚀 Quick Start

### Option 1: Dry-Run Mode (No Hardware Required)

```bash
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# GUI
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui

# CLI
uv run pdfsigner --dry-run sign document.pdf --visible

# REST API
uv run pdfsigner-api  # → http://localhost:8000/docs
```

### Option 2: With Hardware Token

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libnss3-tools

# Clone and setup
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync

# Configure PyGObject
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# Setup NSS database
mkdir -p ~/.nss && certutil -N -d sql:$HOME/.nss

# Run
uv run pdfsigner-gui
```

---

## 📸 Screenshots

| Main Window | Signature Options |
|-------------|-------------------|
| ![Main Window](screenshots/01.png) | ![Options](screenshots/02.png) |

| Settings | Advanced |
|----------|----------|
| ![Settings](screenshots/03.png) | ![Advanced](screenshots/04.png) |

---

## 🔌 REST API

Start the server:
```bash
uv run pdfsigner-api
# Swagger UI: http://localhost:8000/docs
# ReDoc: http://localhost:8000/redoc
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/token` | Get JWT access token |
| `POST` | `/auth/refresh` | Refresh token |
| `POST` | `/api/v1/sign/` | Sign PDF (async job) |
| `GET` | `/api/v1/sign/{id}/status` | Check job status |
| `GET` | `/api/v1/sign/{id}/download` | Download signed PDF |
| `POST` | `/api/v1/validate/` | Validate signatures |
| `POST` | `/api/v1/validate/batch` | Batch validation |
| `GET` | `/api/v1/certificates/` | List certificates |
| `GET` | `/api/v1/certificates/{id}/chain` | Get certificate chain |

### Authentication

```bash
# Get token
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# Use token
curl -X POST http://localhost:8000/api/v1/validate/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@document.pdf"

# Or use API key
curl -X POST http://localhost:8000/api/v1/validate/ \
  -H "X-API-Key: your-api-key" \
  -F "file=@document.pdf"
```

---

## 💻 CLI Usage

```bash
# Sign with visible stamp
uv run pdfsigner sign document.pdf --visible --page last --qr-code

# Sign with metadata
uv run pdfsigner sign document.pdf --visible \
    --reason "Approved" \
    --location "Buenos Aires" \
    --contact "signer@company.com"

# Batch signing
uv run pdfsigner sign *.pdf
uv run pdfsigner sign ./documents/ -r  # recursive

# Validate signatures (shows PAdES level)
uv run pdfsigner validate document_signed.pdf
# Output: ✓ Valid signature (PAdES B-LTA) - Signer: John Doe

# Add archive timestamp to existing signed PDF
uv run pdfsigner archive-ts signed.pdf
uv run pdfsigner archive-ts signed.pdf -t https://freetsa.org/tsr

# List certificates from token
uv run pdfsigner list-certs

# Dry-run mode
uv run pdfsigner --dry-run sign document.pdf --visible
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--visible` | Add visible signature stamp |
| `--page last/first/N` | Page for stamp placement |
| `--qr-code` | Include QR verification code |
| `--reason "text"` | Signature reason |
| `--location "text"` | Signing location |
| `--contact "text"` | Contact information |
| `--cert N` | Certificate number to use |
| `-r, --recursive` | Process subfolders |
| `--dry-run` | Simulation mode (no token) |
| `-t, --tsa-url` | Custom TSA URL |

---

## 📋 PAdES Compliance Levels

PDFSigner supports all PAdES baseline profiles:

| Level | Description | Support |
|-------|-------------|---------|
| **B-B** | Basic signature | ✅ |
| **B-T** | Signature with timestamp | ✅ |
| **B-LT** | Long-term validation (DSS) | ✅ |
| **B-LTA** | Long-term archival (archive TS) | ✅ |

Enable automatic B-LTA in config:
```toml
ltv_enabled = true        # Embed DSS (B-LT)
archive_ts_enabled = true # Enable archive timestamps
archive_ts_auto = true    # Auto-add after signing (B-LTA)
```

---

## ⚙️ Configuration

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

# Long-Term Validation (PAdES B-LT)
ltv_enabled = true
ltv_fail_open = true
ltv_ocsp_timeout = 10
ltv_crl_timeout = 30
ltv_prefer_ocsp = true

# Archive Timestamps (PAdES B-LTA)
archive_ts_enabled = false
archive_ts_auto = false
archive_ts_tsa_urls = []  # Fallback TSAs

# PIN Cache
pin_cache_enabled = true
pin_cache_timeout_seconds = 300

# Audit Trail
audit_enabled = true
audit_retention_days = 90

# Revocation Checking
revocation_check_enabled = false
revocation_check_timeout = 10
revocation_prefer_ocsp = true

# Appearance
theme = "system"  # system, light, dark
```

### TSA Servers

| Provider | URL | Notes |
|----------|-----|-------|
| FreeTSA | `https://freetsa.org/tsr` | Free, reliable |
| DigiCert | `http://timestamp.digicert.com` | Fast |
| Sectigo | `http://timestamp.sectigo.com` | Enterprise |

---

## 🔐 Supported Tokens

| Token | Library | Status |
|-------|---------|--------|
| SafeNet/Thales eToken | `libeToken.so` | ✅ Tested |
| Luna HSM | `libCryptoki2_64.so` | ✅ Supported |
| YubiKey | `libykcs11.so` | ✅ Supported |
| Nitrokey | `libnethsm.so` | ✅ Supported |
| OpenSC | `opensc-pkcs11.so` | ✅ Supported |
| SoftHSM | `libsofthsm2.so` | ✅ Tested |

> **Add new tokens:** Edit `PKCS11_LIB_PATHS` in `src/pdfsigner/core/token/pkcs11_libs.py`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         PDFSigner v1.3                          │
├─────────────────────────────────────────────────────────────────┤
│   GUI (GTK4)   │   CLI (argparse)   │   REST API (FastAPI)     │
├─────────────────────────────────────────────────────────────────┤
│                         CORE LAYER                               │
│  BatchManager → PDFSigner (6 phases) → DSSManager → ArchiveTS   │
│       ↓              ↓                      ↓                    │
│  NSSHandler    PositionFinder         PDFValidator              │
│  (PKCS#11)      (PyMuPDF)          (PAdES level detection)      │
├─────────────────────────────────────────────────────────────────┤
│  USB Token  │  NSS Database  │  TSA Server  │  Archive TS DB    │
└─────────────────────────────────────────────────────────────────┘
```

### Signing Phases

1. **Prepare** - Signing context and certificate chain
2. **Fields** - Create signature fields
3. **Stamps** - Visual signature stamps (multi-page)
4. **Sign** - Cryptographic signature with pyHanko
5. **DSS** - Embed OCSP/CRL for LTV (B-LT)
6. **Archive TS** - Add archive timestamp (B-LTA)

### Key Modules

| Module | Purpose |
|--------|---------|
| `core/signer/pdf_signer.py` | Main signing engine (6 phases) |
| `core/signer/dss_manager.py` | DSS embedding for PAdES B-LT |
| `core/signer/archive_ts_manager.py` | Archive timestamps (B-LTA) |
| `core/signer/archive_ts_scheduler.py` | Long-term PDF monitoring |
| `core/validator/pdf_validator.py` | Signature verification + PAdES detection |
| `core/token/nss_handler.py` | PKCS#11 token communication |
| `api/` | REST API (FastAPI + JWT) |

---

## 🧪 Development

```bash
# Setup
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync --all-extras
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# Run tests (1240+ tests)
uv run pytest -v
uv run pytest --cov=src --cov-report=term-missing

# Run specific test suites
uv run pytest tests/unit/                    # Unit tests
uv run pytest tests/integration/test_api.py  # API tests (39)
uv run pytest tests/e2e/                     # E2E tests

# Code quality
uv run ruff check --fix . && uv run ruff format .
uv run mypy src/
uv run pre-commit run --all-files
```

### Test Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| Core (signer, validator) | ~600 | 87% |
| Archive TS | 71 | 96% |
| DSS Manager | 35 | 95% |
| API | 39 | 65% |
| GUI | ~200 | mocked |

---

## 📦 Installation Options

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

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open files |
| `Ctrl+S` | Sign files |
| `Ctrl+Shift+V` | Validate signatures |
| `Ctrl+L` / `Delete` | Clear file list |
| `Ctrl+?` | Shortcuts help |
| `Ctrl+,` | Settings |
| `F1` | About |
| `Ctrl+Q` | Quit |

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named 'gi'` | `echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth` |
| Token not detected | Check: `lsusb`, `modutil -list -dbdir sql:$HOME/.nss` |
| TSA timeout | Try alternative: `tsa_url = "http://timestamp.digicert.com"` |
| API auth error | Set `PDFSIGNER_API_JWT_SECRET_KEY` env var |
| AppImage libfuse | `./PDFSigner-*.AppImage --appimage-extract && ./squashfs-root/AppRun` |

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with Python, GTK4, FastAPI, and pyHanko</strong>
  <br>
  <sub>PAdES B-LTA compliant • eIDAS ready • Enterprise-grade</sub>
</p>

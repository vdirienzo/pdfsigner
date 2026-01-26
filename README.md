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
  <br>
  <img src="https://img.shields.io/badge/tests-622%20passing-success?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-87%25%20core-blue?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-configuration">Configuration</a> •
  <a href="#-architecture">Architecture</a>
</p>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 Enterprise Security
- **PAdES-LTV** signatures with long-term validation
- **TSA timestamps** for legal compliance
- **Multi-token** support (SafeNet, YubiKey, Nitrokey...)
- **PIN caching** for batch operations

</td>
<td width="50%">

### 🖥️ Modern Experience
- **GTK4/libadwaita** native GNOME interface
- **Drag & drop** file handling
- **Batch signing** with progress tracking
- **Dark mode** support

</td>
</tr>
<tr>
<td width="50%">

### 📋 Flexibility
- **CLI & GUI** for all workflows
- **Visible/invisible** signatures
- **QR verification codes** in stamps
- **Smart positioning** avoids content

</td>
<td width="50%">

### 🧪 Developer Friendly
- **Dry-run mode** for testing without hardware
- **622 tests** with 87% coverage
- **Modular architecture** for extensibility
- **Comprehensive logging**

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Option 1: Run with Dry-Run Mode (No Token Required)

Perfect for testing before you have your hardware token set up:

```bash
# Clone and install
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Run GUI in simulation mode
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui

# Or CLI
uv run pdfsigner --dry-run sign document.pdf
```

### Option 2: Full Installation with Token

```bash
# 1. Install system dependencies (Debian/Ubuntu)
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libnss3-tools

# 2. Clone and install
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync

# 3. Configure PyGObject access
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# 4. Set up NSS database (one-time)
mkdir -p ~/.nss
certutil -N -d sql:$HOME/.nss

# 5. Run
uv run pdfsigner-gui
```

---

## 📸 Screenshots

<table>
  <tr>
    <td align="center">
      <img src="screenshots/01.png" width="400" alt="Main Window"/>
      <br/><b>Main Window</b><br/>
      <sub>Drag & drop PDF files to sign</sub>
    </td>
    <td align="center">
      <img src="screenshots/02.png" width="400" alt="Settings - General"/>
      <br/><b>Settings</b><br/>
      <sub>NSS database and TSA configuration</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="screenshots/03.png" width="400" alt="Visible Signature Settings"/>
      <br/><b>Signature Appearance</b><br/>
      <sub>Customize visible signature style</sub>
    </td>
    <td align="center">
      <img src="screenshots/04.png" width="400" alt="Advanced Settings"/>
      <br/><b>Advanced Options</b><br/>
      <sub>PIN cache and logging configuration</sub>
    </td>
  </tr>
</table>

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Screenshots](#-screenshots)
- [Supported Tokens](#-supported-tokens)
- [Installation](#-installation)
  - [System Dependencies](#system-dependencies)
  - [Manual Installation](#manual-installation)
  - [Pre-built Packages](#pre-built-packages)
- [Token Setup](#-token-setup)
  - [SafeNet eToken](#safenet-5110-driver)
  - [NSS Database](#nss-database-setup)
- [Configuration](#%EF%B8%8F-configuration)
- [Usage](#%EF%B8%8F-usage)
  - [GUI Application](#gui-graphical-application)
  - [CLI Commands](#cli-command-line)
- [Dry-Run Mode](#-dry-run-mode)
- [Architecture](#-architecture)
- [Building & Distribution](#-building--distribution)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Changelog](#-changelog)
- [License](#-license)

---

## 🔑 Supported Tokens

PDFSigner auto-detects PKCS#11 libraries in priority order:

| Token | Library | Status | Use Case |
|-------|---------|--------|----------|
| **SafeNet/Thales eToken** | `libeToken.so` | ✅ Tested | Enterprise signing (5110, 5300) |
| **Luna HSM** | `libCryptoki2_64.so` | ✅ Supported | High-security HSM |
| **YubiKey** | `libykcs11.so` | ✅ Supported | PIV mode signing |
| **Nitrokey** | `libnethsm.so` | ✅ Supported | Open-source security |
| **OpenSC** | `opensc-pkcs11.so` | ✅ Supported | Generic smart cards |
| **Feitian ePass** | `libcastle.so` | ✅ Supported | ePass tokens |
| **SoftHSM** | `libsofthsm2.so` | ✅ Tested | Testing/development |
| **nCipher/Entrust** | `libcknfast.so` | ✅ Supported | Enterprise HSM |

> **Adding new tokens:** Edit `PKCS11_LIB_PATHS` in `src/pdfsigner/core/token/pkcs11_libs.py`

---

## 📦 Installation

### System Dependencies

<details>
<summary><b>Debian / Ubuntu / Linux Mint</b></summary>

```bash
sudo apt update
sudo apt install -y \
    python3-gi \
    python3-gi-cairo \
    gir1.2-gtk-4.0 \
    gir1.2-adw-1 \
    libnss3-tools \
    opensc
```
</details>

<details>
<summary><b>Fedora / RHEL 9+</b></summary>

```bash
sudo dnf install -y \
    python3-gobject \
    gtk4 \
    libadwaita \
    nss-tools \
    opensc
```
</details>

<details>
<summary><b>Arch Linux</b></summary>

```bash
sudo pacman -S --noconfirm \
    python-gobject \
    gtk4 \
    libadwaita \
    nss \
    opensc
```
</details>

<details>
<summary><b>openSUSE Tumbleweed</b></summary>

```bash
sudo zypper install -y \
    python3-gobject \
    gtk4 \
    libadwaita \
    mozilla-nss-tools \
    opensc
```
</details>

### Manual Installation

```bash
# 1. Install uv (modern Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# 2. Clone repository
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner

# 3. Install dependencies
uv sync

# 4. Configure system PyGObject access (varies by distro)
# Debian/Ubuntu:
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
# Fedora:
echo "/usr/lib64/python3.*/site-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# 5. Copy configuration template
mkdir -p ~/.config/pdfsigner
cp config/pdfsigner.toml.example ~/.config/pdfsigner/config.toml

# 6. Verify installation
uv run pdfsigner --help
```

### Pre-built Packages

| Format | Download | Best For |
|--------|----------|----------|
| **Flatpak** | `PDFSigner-{VERSION}.flatpak` | Sandboxed, recommended |
| **AppImage** | `PDFSigner-{VERSION}-x86_64.AppImage` | Portable, no install |
| **Debian** | `pdfsigner_{VERSION}-1_all.deb` | Native Debian/Ubuntu |

```bash
# Build packages locally
./scripts/build-packages.sh --all
```

---

## 🔐 Token Setup

### SafeNet 5110 Driver

<details>
<summary><b>Step-by-step installation</b></summary>

#### 1. Obtain the driver

- **Official:** Contact your certificate provider
- **Thales Portal:** https://supportportal.thalesgroup.com
- **IT Department:** Usually provides the installer

#### 2. Install

```bash
# Debian/Ubuntu
sudo dpkg -i SafenetAuthenticationClient-*.deb
sudo apt-get install -f

# Fedora/RHEL
sudo dnf install ./SafenetAuthenticationClient-*.rpm

# Verify
ls -la /usr/lib/libeToken.so
```

#### 3. Configure USB permissions

```bash
sudo tee /etc/udev/rules.d/90-safenet.rules << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0529", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="08e6", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

#### 4. Verify

```bash
pkcs11-tool --module /usr/lib/libeToken.so -L
```
</details>

### NSS Database Setup

The NSS (Network Security Services) database is required to communicate with your token.

```bash
# 1. Create directory
mkdir -p ~/.nss

# 2. Initialize database
certutil -N -d sql:$HOME/.nss
# Press Enter twice for empty password (development) or set a password

# 3. Register your token module (SafeNet example)
modutil -add "SafeNet" -libfile /usr/lib/libeToken.so -dbdir sql:$HOME/.nss

# 4. Verify
modutil -list -dbdir sql:$HOME/.nss
```

> **First-run wizard:** PDFSigner includes an automatic NSS setup wizard that guides you through this process on first launch.

---

## ⚙️ Configuration

Configuration file: `~/.config/pdfsigner/config.toml`

```toml
# ═══════════════════════════════════════════════════════════════
# NSS Database (Token Communication)
# ═══════════════════════════════════════════════════════════════
nss_db_path = "/home/YOUR_USERNAME/.nss"

# ═══════════════════════════════════════════════════════════════
# TSA (Timestamp Authority) - Required for legal validity
# ═══════════════════════════════════════════════════════════════
tsa_url = "https://freetsa.org/tsr"
# tsa_username = ""  # If authentication required
# tsa_password = ""

# ═══════════════════════════════════════════════════════════════
# Visible Signature Defaults
# ═══════════════════════════════════════════════════════════════
default_visible = false
signature_width_mm = 50
signature_height_mm = 20
default_page = "last"        # "last", "first", or page number

# ═══════════════════════════════════════════════════════════════
# QR Verification Code
# ═══════════════════════════════════════════════════════════════
qr_enabled = false
qr_position = "left"         # "left" or "right"

# ═══════════════════════════════════════════════════════════════
# Output & Behavior
# ═══════════════════════════════════════════════════════════════
output_suffix = "_signed"    # document.pdf → document_signed.pdf
pin_cache_enabled = true
pin_cache_timeout_seconds = 300
dry_run = false

# ═══════════════════════════════════════════════════════════════
# Appearance & Logging
# ═══════════════════════════════════════════════════════════════
theme = "system"             # "system", "light", "dark"
log_level = "INFO"           # "DEBUG", "INFO", "WARNING", "ERROR"
```

### Public TSA Servers

| Provider | URL | Recommendation |
|----------|-----|----------------|
| FreeTSA | `https://freetsa.org/tsr` | Testing, personal |
| DigiCert | `http://timestamp.digicert.com` | Production |
| Sectigo | `http://timestamp.sectigo.com` | Production |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Production |

---

## 🖥️ Usage

### GUI (Graphical Application)

```bash
# Start application
uv run pdfsigner-gui

# With dry-run mode
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui
```

**Keyboard Shortcuts:**
| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open files |
| `Ctrl+,` | Settings |
| `Ctrl+Q` | Quit |

### CLI (Command Line)

#### Sign Documents

```bash
# Sign a single file
uv run pdfsigner sign document.pdf

# Sign with visible signature on last page
uv run pdfsigner sign document.pdf --visible --page last

# Sign with QR verification code
uv run pdfsigner sign document.pdf --qr-code

# Sign multiple files
uv run pdfsigner sign file1.pdf file2.pdf file3.pdf

# Sign all PDFs in directory
uv run pdfsigner sign ./documents/

# Sign recursively
uv run pdfsigner sign ./documents/ -r

# Select specific certificate
uv run pdfsigner sign document.pdf --cert 2
```

#### Validate Signatures

```bash
# Validate a signed document
uv run pdfsigner validate document_signed.pdf

# Validate with details
uv run pdfsigner -v validate document_signed.pdf

# Validate multiple files
uv run pdfsigner validate *.pdf
```

#### List Certificates

```bash
# List available certificates on token
uv run pdfsigner list-certs
```

---

## 🧪 Dry-Run Mode

Test PDFSigner without hardware token:

```bash
# CLI flag
uv run pdfsigner --dry-run sign document.pdf

# Environment variable
PDFSIGNER_DRY_RUN=true uv run pdfsigner sign document.pdf

# GUI
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui
```

**What happens in dry-run:**
- ✅ Simulates token connection
- ✅ Accepts any 4+ digit PIN
- ✅ Creates `_signed` output files
- ✅ Generates visual stamps (including QR codes)
- ⚠️ **Does NOT create cryptographically valid signatures**

<details>
<summary><b>Example output</b></summary>

```
============================================================
⚠️  DRY-RUN MODE - SIMULATION WITHOUT REAL TOKEN
============================================================
Files will be copied with _signed suffix
but will NOT contain a real digital signature.

[DRY-RUN] Simulating token connection...
[DRY-RUN] Simulated token: SafeNet 5110 (SIMULATED)
[DRY-RUN] Enter any PIN with 4+ digits to simulate:
Enter token PIN: ****
[DRY-RUN] Simulated authentication successful

[DRY-RUN] [100.0%] document.pdf                     [success]

------------------------------------------------------------
✓ [DRY-RUN] 1 file(s) copied with _signed suffix

⚠️  Note: Files are NOT actually signed.
   Copies were created to simulate the process.
```
</details>

---

## 🏗️ Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        PDFSigner                                 │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────┐    ┌───────────┐    ┌───────────┐               │
│  │    GUI    │    │    CLI    │    │  Config   │               │
│  │  (GTK4)   │    │ (argparse)│    │  (TOML)   │               │
│  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘               │
│        │                │                │                      │
│        └────────────────┼────────────────┘                      │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    CORE LAYER                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │   │
│  │  │ BatchManager │  │  PDFSigner   │  │  LTAHandler  │    │   │
│  │  │  (orchestr.) │─▶│  (pyHanko)   │─▶│    (TSA)     │    │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │   │
│  │          │                │                               │   │
│  │          ▼                ▼                               │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │   │
│  │  │ NSSHandler   │  │PositionFinder│  │ PDFValidator │    │   │
│  │  │  (PKCS#11)   │  │  (PyMuPDF)   │  │  (verify)    │    │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  EXTERNAL SERVICES                        │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │   │
│  │  │  USB Token   │  │  NSS Database │  │  TSA Server  │    │   │
│  │  │  (hardware)  │  │  (~/.nss)    │  │  (HTTP)      │    │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Signing Flow

```
User Request
     │
     ▼
┌────────────────┐
│ SigningHandler │  GUI/CLI entry point
└───────┬────────┘
        │
        ▼
┌────────────────┐     ┌────────────────┐
│  OptionsDialog │────▶│   PINDialog    │  User interaction
└───────┬────────┘     └───────┬────────┘
        │                      │
        └──────────┬───────────┘
                   ▼
         ┌────────────────┐
         │  BatchManager  │  Orchestrates batch
         └───────┬────────┘
                 │
                 ▼
         ┌────────────────┐
         │   PDFSigner    │  Core signing logic
         └───────┬────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
┌──────────────┐  ┌──────────────┐
│  NSSHandler  │  │  LTAHandler  │
│  (PKCS#11)   │  │    (TSA)     │
└──────┬───────┘  └──────┬───────┘
       │                 │
       ▼                 ▼
   USB Token        TSA Server
```

### Module Reference

| Module | Location | Purpose |
|--------|----------|---------|
| **PDFSigner** | `core/signer/pdf_signer.py` | PAdES-LTV signing with pyHanko |
| **BatchManager** | `core/signer/batch_manager.py` | Multi-file orchestration |
| **LTAHandler** | `core/signer/lta_handler.py` | TSA timestamp integration |
| **NSSHandler** | `core/token/nss_handler.py` | PKCS#11 token communication |
| **PositionFinder** | `core/pdf_analyzer/position_finder.py` | Smart signature placement |
| **PDFValidator** | `core/validator/pdf_validator.py` | Signature verification |
| **MockBatchManager** | `core/mock/mock_batch.py` | Dry-run simulation |

---

## 📦 Building & Distribution

### Build All Packages

```bash
./scripts/build-packages.sh --all
```

### Individual Builds

| Format | Command | Output |
|--------|---------|--------|
| Flatpak | `./scripts/build-packages.sh --flatpak` | `dist/flatpak/*.flatpak` |
| AppImage | `./scripts/build-packages.sh --appimage` | `dist/appimage/*.AppImage` |
| Debian | `./scripts/build-packages.sh --deb` | `dist/deb/*.deb` |

### Flatpak Installation

```bash
# Install GNOME 49 runtime (if needed)
flatpak install flathub org.gnome.Platform//49 org.gnome.Sdk//49

# Build and install
./scripts/build-packages.sh --flatpak
flatpak install --user dist/flatpak/PDFSigner-*.flatpak

# Run
flatpak run com.pdfsigner.app
```

---

## 🔧 Development

### Setup

```bash
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner
uv sync --all-extras
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```

### Commands

```bash
# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=src/pdfsigner --cov-report=term-missing

# Linting & formatting
uv run ruff check --fix . && uv run ruff format .

# Type checking
uv run mypy src/pdfsigner --ignore-missing-imports

# Security scan
uv run bandit -r src/ && uv run safety check

# Pre-commit hooks
uv run pre-commit run --all-files
```

### Test Coverage

**622 tests** with **87% core coverage**

| Module | Coverage | Status |
|--------|----------|--------|
| `lta_handler.py` | 100% | ✅ |
| `health_status.py` | 100% | ✅ |
| `settings.py` | 100% | ✅ |
| `position_finder.py` | 100% | ✅ |
| `multi_signer.py` | 100% | ✅ |
| `batch_manager.py` | 97% | ✅ |
| `pdf_validator.py` | 96% | ✅ |
| `pdf_signer.py` | 74% | ⚠️ (E2E covered) |

### Project Structure

```
pdfsigner/
├── src/pdfsigner/
│   ├── cli/                 # CLI commands (sign, validate, list-certs)
│   ├── config/              # Settings (pydantic-settings + TOML)
│   ├── core/
│   │   ├── certificate/     # Health status & expiry tracking
│   │   ├── mock/            # Dry-run simulation
│   │   ├── pdf_analyzer/    # PDF analysis & positioning
│   │   ├── setup/           # NSS wizard
│   │   ├── signer/          # PAdES signing (pyHanko)
│   │   ├── stamp/           # QR code generation
│   │   ├── token/           # NSS/PKCS#11 handlers
│   │   └── validator/       # Signature verification
│   ├── gui/                 # GTK4 application
│   │   ├── handlers/        # SigningHandler, ValidationHandler
│   │   ├── settings_pages/  # Settings dialog pages
│   │   └── widgets/         # Custom widgets
│   └── ui/                  # Dialogs (PIN, options, progress)
├── tests/
│   ├── unit/                # Unit tests (585)
│   ├── integration/         # Integration tests (16)
│   └── e2e/                 # E2E dry-run tests (37)
├── scripts/                 # Build & install scripts
└── config/                  # Example configuration
```

---

## 🐛 Troubleshooting

<details>
<summary><b>"No module named 'gi'"</b></summary>

```bash
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```
</details>

<details>
<summary><b>AppImage: "dlopen(): error loading libfuse.so.2"</b></summary>

Debian 13+ removed libfuse2. Extract and run:

```bash
./PDFSigner-*.AppImage --appimage-extract
./squashfs-root/AppRun
```
</details>

<details>
<summary><b>"USB token not detected"</b></summary>

```bash
# 1. Check physical connection
lsusb | grep -i "safenet\|gemalto\|thales\|yubico"

# 2. Verify driver
ls -la /usr/lib/libeToken.so

# 3. Check NSS module
modutil -list -dbdir sql:$HOME/.nss

# 4. Test PKCS#11
pkcs11-tool --module /usr/lib/libeToken.so -L
```
</details>

<details>
<summary><b>"SEC_ERROR_PKCS11_DEVICE_ERROR"</b></summary>

```bash
# Reload USB permissions
sudo udevadm control --reload-rules
sudo udevadm trigger

# Reconnect token
```
</details>

<details>
<summary><b>"TSA error / Timeout"</b></summary>

```bash
# Test TSA connectivity
curl -v https://freetsa.org/tsr

# Try alternative TSA in config.toml
tsa_url = "http://timestamp.digicert.com"
```
</details>

<details>
<summary><b>GUI doesn't start</b></summary>

```bash
# Verify GTK4
python3 -c "import gi; gi.require_version('Gtk', '4.0'); print('GTK4 OK')"

# Verify libadwaita
python3 -c "import gi; gi.require_version('Adw', '1'); print('Adwaita OK')"
```
</details>

---

## 📝 Changelog

### [0.9.5] - 2026-01-26

#### Added
- **E2E Test Suite** - 37 comprehensive tests covering full signing workflow
  - Single/multi-page signing scenarios
  - All position preferences (bottom-right, top-left, etc.)
  - All built-in templates
  - QR code generation
  - Batch signing operations
  - Edge cases and output verification

#### Fixed
- **Multi-page signing** - Visual stamps now appear on all selected pages
  - pyHanko limitation: only ONE signature field per operation
  - Solution: Signature field on first page + visual PNG stamps on remaining pages
- **Position preference ignored** - User's explicit position choice now always respected
  - Previously fell back to AUTO search when content detected at preferred location
  - Now: if user selects BOTTOM_RIGHT, signature goes there regardless of content

### [0.9.4] - 2026-01-26

#### Added
- **Template Editor Dialog** - Create custom signature templates from GUI
  - Dynamic text fields with color/size customization
  - Reorder fields with up/down buttons
  - Live preview while editing
  - Support for custom text lines beyond defaults
- **Per-signing template override** - Select different template for each signing operation

#### Fixed
- **pyHanko layout imports** - Fixed `SimpleBoxLayoutRule` and `Margins` imports
- **Ruff linting** - Fixed 43 naming convention issues in tests

### [0.9.3] - 2026-01-25

#### Fixed
- **PIN cache** not working correctly in batch operations
- **File list** not clearing properly after signing

### [0.9.2] - 2026-01-15

#### Changed
- **Certificate Health UI** - Banner widget for certificate status
  - Color-coded status icons (🔐/⚠️/🔶/🚨/❌) based on expiry
  - Shows certificate details (subject, issuer, expiry date)

### [0.9.1] - 2026-01-14

#### Added
- **Test coverage boost** - 520 total tests
  - 16 E2E tests for complete sign → validate flow
  - 32 tests for certificate health status
  - Multiple modules now at 100% coverage

### [0.9.0] - 2026-01-14

#### Added
- **Certificate Health Dashboard** - Collapsible banner with expiry warnings
- **CSS animations** - Fade-in, pulse for critical states
- **Toast notifications** for expiry warnings

<details>
<summary><b>Earlier releases (v0.1.0 - v0.8.9)</b></summary>

### [0.8.x] - January 2026
- QR verification codes in signatures
- NSS Setup Wizard for first-run
- Multi-token PKCS#11 support
- Complete packaging system (Flatpak, AppImage, Debian)
- 79 new tests for signer module

### [0.7.0] - January 2026
- Flatpak, AppImage, and Debian packaging
- AppStream metadata for software centers
- Desktop entry with MIME types

### [0.6.0] - January 2026
- Major test coverage improvements
- TSA integration tests

### [0.5.0] - January 2026
- NSS Setup Wizard
- Izenpe TSA support

### [0.1.0 - 0.4.0] - January 2026
- Initial release with PAdES-LTV signatures
- GTK4 GUI and CLI
- Dry-run mode for testing
- Multi-token support

</details>

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Homero Thompson del Lago del Terror**

---

<p align="center">
  <sub>Built with ❤️ using Python, GTK4, and pyHanko</sub>
</p>

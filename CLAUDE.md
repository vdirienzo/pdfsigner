# PDFSigner - Project Memory

> **Purpose:** This file helps Claude (or any AI assistant) understand the project context quickly.
> **Last Updated:** 2026-01-14
> **Author:** Homero Thompson del Lago del Terror

---

## Project Overview

**PDFSigner** is a digital PDF signing application for Linux/GNOME that uses a SafeNet 5110 USB token via NSS (Network Security Services).

### Key Features
- PAdES-LTV signatures with TSA timestamp
- GTK4/libadwaita standalone GUI
- CLI with subcommands (sign, validate, list-certs)
- Dry-run mode for testing without real token
- Visible signature with smart positioning
- Batch signing with PIN cache

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
| CI/CD | GitHub Actions |

---

## Project Structure

```
pdfsigner/
├── .github/
│   └── workflows/
│       └── ci.yml              # CI/CD pipeline (lint, security, test, build)
├── src/pdfsigner/
│   ├── cli/                    # CLI commands (sign.py, validate.py, etc.)
│   ├── config/                 # Settings from ~/.config/pdfsigner/config.toml
│   ├── core/
│   │   ├── mock/               # Dry-run simulation (MockBatchManager, stamp_simulator)
│   │   ├── pdf_analyzer/       # Content analysis, position finding
│   │   ├── signer/             # PAdES signing (pdf_signer, batch_manager, lta_handler)
│   │   ├── token/              # NSS/PKCS#11 (nss_handler, cert_selector, pin_cache)
│   │   └── validator/          # Signature validation
│   ├── gui/                    # GTK4 standalone app (app.py, main_window.py)
│   └── ui/dialogs/             # Reusable dialogs (options, pin, progress, help)
├── tests/
│   ├── unit/                   # Unit tests (170+ tests)
│   └── integration/            # Integration tests (TSA, etc.)
├── scripts/
│   ├── install.sh              # Multi-distro installer
│   └── uninstall.sh            # Uninstaller
├── config/                     # Example config files
├── .pre-commit-config.yaml     # Pre-commit hooks (ruff, mypy, bandit)
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
- **179 tests passing**
- **33% overall coverage**
- Key modules: exceptions (100%), stamp_simulator (100%), pin_cache (98%), batch_manager (97%)

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

### CI/CD Pipeline
GitHub Actions runs on push/PR to `main` and `dev`:
1. **Lint** - Ruff check and format
2. **Security** - Bandit and Safety
3. **Test** - pytest with coverage
4. **Build** - Package build

---

## Important Files

| File | Purpose |
|------|---------|
| `lta_handler.py` | TSA timestamp integration (HTTPTimeStamper) |
| `pdf_signer.py` | Main PDF signing logic with pyHanko |
| `batch_manager.py` | Batch signing orchestration |
| `nss_handler.py` | NSS/PKCS#11 token communication |
| `position_finder.py` | Smart signature position calculation |
| `stamp_simulator.py` | Dry-run stamp simulation |

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
| Dry-run not working | Set `dry_run = true` in config or use `--dry-run` flag |
| Config not loading | Check TOML syntax in `~/.config/pdfsigner/config.toml` |
| GUI won't start | Verify GTK4 and libadwaita are installed |
| TSA timeout | Check internet connection, try alternate TSA URL |
| HTTPTimeStamper error | Use `timeout` param, not `https_timeout` |

---

## Recent Changes (v0.3.1)

- Fixed TSA HTTPTimeStamper API (correct parameter: `timeout`)
- Added TSA integration tests verifying FreeTSA works
- Added CI/CD pipeline with GitHub Actions
- Added pre-commit hooks (ruff, mypy, bandit)
- Added MIT LICENSE and CONTRIBUTING.md
- Expanded test suite to 179 tests (33% coverage)

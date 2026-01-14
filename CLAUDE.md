# PDFSigner - Project Memory

> **Purpose:** This file helps Claude (or any AI assistant) understand the project context quickly.
> **Last Updated:** 2026-01-13
> **Author:** Homero Thompson del Lago del Terror

---

## Project Overview

**PDFSigner** is a digital PDF signing application for Linux/GNOME that uses a SafeNet 5110 USB token via NSS (Network Security Services).

### Key Features
- PAdES-LTV signatures with TSA timestamp
- GTK4/libadwaita standalone GUI
- Nautilus file manager integration (right-click → "Sign digitally")
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

---

## Project Structure

```
pdfsigner/
├── src/pdfsigner/
│   ├── cli/                 # CLI commands (sign.py, validate.py, etc.)
│   ├── config/              # Settings from ~/.config/pdfsigner/config.toml
│   ├── core/
│   │   ├── mock/            # Dry-run simulation (MockBatchManager, stamp_simulator)
│   │   ├── pdf_analyzer/    # Content analysis, position finding
│   │   ├── signer/          # PAdES signing (pdf_signer, batch_manager, lta_handler)
│   │   ├── token/           # NSS/PKCS#11 (nss_handler, cert_selector, pin_cache)
│   │   └── validator/       # Signature validation
│   ├── gui/                 # GTK4 standalone app (app.py, main_window.py, signing_handler.py)
│   ├── nautilus_extension/  # Nautilus integration (sign_extension.py)
│   └── ui/dialogs/          # Reusable dialogs (options, pin, progress, help)
├── scripts/
│   ├── install.sh           # Multi-distro installer
│   └── uninstall.sh         # Uninstaller
├── tests/
└── config/                  # Example config files
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

### Nautilus Integration
After running `./scripts/install.sh`:
- Right-click on PDF in Nautilus → "Sign digitally"
- Opens the GUI with the file loaded

---

## Key Bugs Fixed (2026-01-13 Session)

### 1. Simulated Stamp Position
**Problem:** Stamps always appeared bottom-right regardless of user selection.
**Cause:** `signing_handler.py` wasn't passing the `appearance` object to MockBatchManager.
**Fix:** Store full appearance object and pass it through the chain.
**Files:** `signing_handler.py`, `mock_batch.py`, `stamp_simulator.py`

### 2. Nautilus Extension Not Appearing
**Problem:** "Sign digitally" option didn't show in context menu.
**Cause:** GIR version mismatch - code used `Nautilus 4.0` but system has `4.1`.
**Fix:** `gi.require_version("Nautilus", "4.1")`
**File:** `sign_extension.py:15`

### 3. Nautilus Import Collision
**Problem:** Extension loaded but import failed silently.
**Cause:** Wrapper file named `pdfsigner.py` collided with `pdfsigner` package.
**Fix:** Renamed to `pdfsigner_nautilus.py`
**Location:** `~/.local/share/nautilus-python/extensions/pdfsigner_nautilus.py`

### 4. GTK4 Dialog Incompatibility
**Problem:** Clicking "Sign digitally" did nothing.
**Cause:** Code used GTK3-style `dialog.run()` which doesn't exist in GTK4.
**Fix:** Refactored extension to launch standalone GUI via subprocess instead of managing dialogs directly.
**File:** `sign_extension.py` (reduced from 295 to ~125 lines)

### 5. PROJECT_PATH Calculation
**Problem:** GUI didn't launch when clicking from Nautilus.
**Cause:** Used 5 `.parent` calls instead of 4.
**Fix:** `PROJECT_PATH = Path(__file__).parent.parent.parent.parent`

---

## Important Implementation Details

### Coordinate Systems
- **PyMuPDF (fitz):** Origin (0,0) at TOP-LEFT, Y increases downward
- **PDF Standard:** Origin (0,0) at BOTTOM-LEFT, Y increases upward
- **Conversion needed** in `position_finder.py` when calculating stamp positions for pyHanko

### Stamp Customization (Real Signatures)
Uses pyHanko's `TextStampStyle` with placeholders:
- `%(signer)s` - Certificate CN (signer name)
- `%(ts)s` - Timestamp

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
tsa_url = "http://timestamp.server.com"
dry_run = false
output_suffix = "_signed"
log_level = "INFO"
```

---

## Nautilus Extension Architecture

The extension is a **thin launcher** that:
1. Detects PDF files in selection
2. Shows "Sign digitally" menu item
3. Launches GUI app via `subprocess.Popen`
4. Passes file paths as arguments

This avoids GTK4 dialog complexity and reuses the working GUI.

**Wrapper location:** `~/.local/share/nautilus-python/extensions/pdfsigner_nautilus.py`

---

## Testing

```bash
# Run all tests
uv run pytest -v

# With coverage
uv run pytest --cov=src

# Specific test
uv run pytest tests/unit/test_position_finder.py -v
```

---

## Commits History (Recent Session)

```
17ebcd1 fix(nautilus): correct PROJECT_PATH calculation
e32788c refactor(nautilus): simplify extension to launch GUI app
4fa6361 fix(nautilus): rename extension file to avoid import collision
85fcb9f fix(nautilus): update GIR version from 4.0 to 4.1
faeb172 fix(i18n): translate Nautilus extension and scripts
c515ec7 docs(changelog): add version 0.2.0
20e2578 fix: change output suffix from _firmado to _signed
7aed18b fix(about): correct GitHub repository URL
64a55d2 fix(help): translate help dialog to English
89c06a3 feat(gui): add help dialog with documentation
```

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
| Nautilus option missing | Check GIR version, restart Nautilus (`nautilus -q`) |
| Import errors | Check wrapper filename isn't `pdfsigner.py` |
| GUI won't open from Nautilus | Verify PROJECT_PATH in sign_extension.py |
| Token not detected | Check NSS DB path, run `certutil -L -d ~/.nss` |
| Dry-run not working | Set `dry_run = true` in config or use `--dry-run` flag |

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**PDFSigner** - Digital PDF signing application for Linux/GNOME with PKCS#11/NSS token support.

**Tech Stack:** Python 3.12+, uv, GTK4/libadwaita, pyHanko (PAdES-LTV), PyMuPDF (fitz), NSS/python-pkcs11

## Development Commands

```bash
# Run application
uv run pdfsigner-gui                    # GUI
uv run pdfsigner sign file.pdf          # CLI
uv run pdfsigner --dry-run sign file.pdf  # Without real token

# Tests
uv run pytest -v                        # All tests (520)
uv run pytest tests/unit/ -v            # Unit only
uv run pytest -k "test_health" -v       # Pattern match
uv run pytest tests/unit/test_position_finder.py::test_find_position_avoids_content -v  # Single test
uv run pytest --cov=src --cov-report=term-missing  # With coverage

# Code quality
uv run ruff check --fix . && uv run ruff format .  # Lint + format
uv run mypy src/                        # Type check
uv run bandit -r src/ && uv run safety check       # Security

# Pre-commit (run before committing)
uv run pre-commit run --all-files
```

## Architecture

### Signing Flow
```
MainWindow → SigningHandler → OptionsDialog → PINDialog
                           → BatchManager.sign_files()
                              → PDFSigner.sign() → LTAHandler (TSA) → pyHanko
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `core/signer/pdf_signer.py` | Main signing logic with pyHanko |
| `core/signer/batch_manager.py` | Batch orchestration, progress callbacks |
| `core/signer/lta_handler.py` | TSA timestamp (HTTPTimeStamper) |
| `core/token/nss_handler.py` | PKCS#11 multi-token communication |
| `core/pdf_analyzer/position_finder.py` | Smart signature positioning |
| `core/mock/` | Dry-run simulation (MockBatchManager, stamp_simulator) |
| `gui/handlers/` | Bridge GUI ↔ Core (SigningHandler, ValidationHandler) |

### Dry-Run Mode
When `dry_run=true`: `MockBatchManager` replaces `BatchManager`, no token/PIN/TSA needed, outputs real PDFs with simulated stamps.

### GUI Threading
- Use `GLib.idle_add()` for thread-safe UI updates from background threads
- Progress via `ProgressDialog`, results via `Adw.Toast`

### PIN Cache Flow
```
SigningHandler._request_pin_or_use_cache()
  ├─ if pin_cache_enabled AND cached PIN valid → use cached PIN
  └─ else → show PinDialog → store PIN in cache if enabled
```
- **Important:** Always call `get_settings()` fresh when checking `pin_cache_enabled` (settings may change mid-session)
- Cache singleton: `get_pin_cache(timeout_seconds)` in `core/token/pin_cache.py`

### Progress Dialog Behavior
- Does NOT auto-close after signing completes
- Shows output filename per file (e.g., `→ doc_signed.pdf`)
- Folder button opens containing directory via `Gio.AppInfo.launch_default_for_uri()`
- User closes manually with "Close" button

## Critical Implementation Details

### Coordinate Systems (IMPORTANT)
- **PyMuPDF (fitz):** Origin (0,0) at **TOP-LEFT**, Y increases downward
- **PDF Standard/pyHanko:** Origin (0,0) at **BOTTOM-LEFT**, Y increases upward
- Conversion happens in `position_finder.py` - always verify coordinate transforms

### TSA Configuration
```python
# CORRECT - use 'timeout' parameter
HTTPTimeStamper(url=tsa_url, timeout=30)

# WRONG - 'https_timeout' doesn't exist
HTTPTimeStamper(url=tsa_url, https_timeout=30)  # Will fail!
```

### Stamp Placeholders (pyHanko TextStampStyle)
- `%(signer)s` - Certificate CN
- `%(ts)s` - Timestamp

### Output Convention
- Suffix: `_signed` (e.g., `document.pdf` → `document_signed.pdf`)

## Testing Notes

- **Coverage:** 87% core (excludes `gui/`, `ui/`, `cli/` - see `pyproject.toml`)
- **GUI tests:** Use mocks in `conftest_gui.py`, no display required
- **Integration tests:** Require internet (TSA servers)
- **Test naming:** `test_<function>_<scenario>_<expected>`

## Configuration

Location: `~/.config/pdfsigner/config.toml`

| Setting | Default | Description |
|---------|---------|-------------|
| `nss_db_path` | `~/.nss` | NSS database with token |
| `tsa_url` | `""` | Timestamp server URL |
| `dry_run` | `false` | Simulation mode |
| `output_suffix` | `"_signed"` | Output filename suffix |
| `log_level` | `"INFO"` | DEBUG/INFO/WARNING/ERROR |
| `pin_cache_enabled` | `false` | Cache PIN for batch signing |
| `pin_cache_timeout_seconds` | `300` | Cache expiry (60-3600s) |

## Adding New Token Support

Edit `PKCS11_LIB_PATHS` in `src/pdfsigner/core/token/pkcs11_libs.py` - tokens auto-detected in priority order.

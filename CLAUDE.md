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
uv run pytest -v                        # All tests (764)
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
| `core/signer/pdf_signer.py` | Main signing logic with pyHanko (refactored into phases) |
| `core/signer/batch_manager.py` | Batch orchestration, progress callbacks |
| `core/signer/lta_handler.py` | TSA timestamp (HTTPTimeStamper) |
| `core/token/nss_handler.py` | PKCS#11 multi-token communication (specific exceptions) |
| `core/token/cert_selector.py` | Certificate filtering by expiry and key usage |
| `core/pdf_analyzer/position_finder.py` | Smart signature positioning |
| `core/signature/` | Template system (template.py, template_renderer.py, template_loader.py) |
| `core/audit/` | Audit trail system (audit_logger.py, audit_event.py) - JSON Lines format |
| `core/mock/` | Dry-run simulation (MockBatchManager, stamp_simulator) |
| `gui/handlers/` | Bridge GUI ↔ Core (SigningHandler, ValidationHandler) |

### Template System
Templates control signature visibility: no template = invisible, with template = visible stamp.

```
config/builtin_templates/
├── default.json      # Simple text (signer + date)
├── corporate.json    # Logo + signer + org + date
├── minimal.json      # Single line compact
└── with_qr.json      # QR verification code
```

Template JSON structure:
```json
{
  "name": "template_name",
  "width_mm": 60, "height_mm": 25,
  "layers": [
    {"type": "background", "color": "#ffffff"},
    {"type": "text", "x": 5, "y": 30, "text": "{signer_name}", "font_size": 10}
  ]
}
```
- Layer types: `background`, `border`, `text`, `image`, `qr`
- Variables: `{signer_name}`, `{date}`, `{org}`
- Coordinates: relative (0-100% of dimensions)

### PDFSigner Sign Flow (Refactored)
The `sign_pdf()` method is divided into 4 phases for testability:
```
PDFSigner.sign_pdf()
  ├─ Phase 1: _prepare_signing_context()     # Validate, create signer, get timestamper
  ├─ Phase 2: create_signature_field_with_stamps()  # Field spec + stamp positions
  ├─ Phase 3: _preprocess_pdf_with_stamps()  # Add visual stamps to multi-page
  └─ Phase 4: _execute_signing()             # pyHanko PdfSigner.sign_pdf()
```

### Template Override Flow
Users can override default template per-signing in OptionsDialog:
```
SignatureOptionsDialog.get_selected_template()
  → SigningHandler._current_options["template"]
  → BatchManager.sign_batch(template_override=...)
  → PDFSigner.sign_pdf(template_override=...)
  → _build_stamp_style(template_override=...)
```

### Audit Trail System
Structured logging for security and compliance:
```
core/audit/
├── audit_event.py       # Event types and data structures
├── audit_logger.py      # Thread-safe singleton logger
└── __init__.py          # Helper functions (log_signing_event, log_validation_event, etc.)
```

**Event Types:**
- `SIGN_SUCCESS` / `SIGN_FAILURE` - PDF signing operations
- `VALIDATE_SUCCESS` / `VALIDATE_FAILURE` - Signature validation
- `TOKEN_LOGIN` / `TOKEN_LOGOUT` - PKCS#11 token operations
- `CERTIFICATE_SELECTED` - Certificate selection for signing
- `CONFIG_CHANGE` - Settings modifications

**Storage:**
- Location: `~/.local/share/pdfsigner/audit/`
- Format: JSON Lines (one JSON object per line)
- Rotation: Monthly (`audit_YYYY-MM.jsonl`)
- Retention: Configurable (1-3650 days, default: 90)

**Usage:**
```python
from pdfsigner.core.audit import log_signing_event

log_signing_event(
    document_path="/path/to/doc.pdf",
    certificate_serial="abc123",
    certificate_issuer="CN=Test CA",
    user_cn="John Doe",
    success=True,
    details={"template": "default"}
)
```

**Query and Export:**
```python
from pdfsigner.core.audit import get_audit_logger

logger = get_audit_logger()
events = logger.get_events(start_date=..., event_types=[...])
csv_data = logger.export_csv(events)
```

### Settings Auto-Save
Settings dialog uses debounced auto-save (no manual save button):
```python
# Debounce pattern in SettingsDialog
GLib.timeout_add(500, self._auto_save)  # 500ms debounce
```
- All widgets connected via `notify::selected`, `notify::active`, `changed` signals
- Writes to `~/.config/pdfsigner/config.toml` after 500ms of no changes

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
- **E2E tests:** Dry-run mode (`tests/e2e/`), covers full signing workflow with all variants
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
| `audit_enabled` | `true` | Enable audit logging |
| `audit_retention_days` | `90` | Days to retain audit logs (1-3650) |
| `signature_template` | `""` | Template name (empty = invisible) |

## Adding New Token Support

Edit `PKCS11_LIB_PATHS` in `src/pdfsigner/core/token/pkcs11_libs.py` - tokens auto-detected in priority order.

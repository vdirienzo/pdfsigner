# CLAUDE.md

## Project Overview

**PDFSigner** - Digital PDF signing for Linux/GNOME with PKCS#11/NSS token support.

**Stack:** Python 3.12+, uv, GTK4/libadwaita, pyHanko (PAdES-LTA), PyMuPDF, NSS/python-pkcs11, FastAPI

## Commands

```bash
# Run
uv run pdfsigner-gui                    # GUI
uv run pdfsigner --dry-run sign f.pdf   # CLI dry-run
uv run pdfsigner archive-ts signed.pdf  # Add archive timestamp
uv run pdfsigner-api                    # REST API server

# Test
uv run pytest -v                        # ~1240 tests
uv run pytest --cov=src                 # Coverage (87% core)

# Quality
uv run ruff check --fix . && uv run ruff format .
uv run mypy src/
uv run pre-commit run --all-files
```

## Architecture

```
MainWindow → SigningHandler → BatchManager → PDFSigner → pyHanko
                            → OptionsDialog → PINDialog
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `core/signer/pdf_signer.py` | Main signing (6 phases: prep → fields → stamps → sign → DSS → archive TS) |
| `core/signer/batch_manager.py` | Batch orchestration |
| `core/signer/dss_manager.py` | DSS embedding for PAdES B-LT |
| `core/signer/archive_ts_manager.py` | Archive timestamps for PAdES B-LTA |
| `core/signer/archive_ts_scheduler.py` | Long-term PDF monitoring (SQLite) |
| `core/token/nss_handler.py` | PKCS#11 communication |
| `core/validator/pdf_validator.py` | Signature validation + PAdES level detection |
| `api/` | REST API (FastAPI) |
| `gui/handlers/` | GUI ↔ Core bridge |

### Patterns

**Settings pages:** `create_X_page(settings, dialog) -> Adw.PreferencesPage`
- Store widget refs in `dialog.widget_name` for auto-save

**GUI threading:** `GLib.idle_add()` for UI updates from background threads

**Dry-run:** `dry_run=true` → MockBatchManager, no token needed

## Critical Gotchas

### Coordinate Systems
- **PyMuPDF:** Origin TOP-LEFT, Y↓
- **pyHanko/PDF:** Origin BOTTOM-LEFT, Y↑
- Conversion in `position_finder.py`

### TSA Configuration
```python
HTTPTimeStamper(url=tsa_url, timeout=30)  # ✓ 'timeout'
HTTPTimeStamper(url=tsa_url, https_timeout=30)  # ✗ doesn't exist
```

### Avoid assert in Production
```python
if self._lib is None:
    raise RuntimeError("...")  # ✓ works with python -O
assert self._lib is not None   # ✗ stripped in -O mode
```

### GTK RecentManager
```python
manager.add_item(uri)  # ✓ safe
# add_full() with RecentData.groups causes SIGABRT in tests
```

### Date Iteration (audit_logger)
```python
current = current.replace(month=m+1, day=1)  # ✓ always day=1
current = current.replace(month=m+1)         # ✗ fails Jan 31→Feb
```

### Mock Compatibility
```python
for item in aia:  # type: ignore[attr-defined]  # ✓ duck typing
if not isinstance(aia, SomeType): return None  # ✗ fails with Mock
```

## REST API

Run: `uv run pdfsigner-api` → http://localhost:8000/docs

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/token` | Get JWT token |
| POST | `/api/v1/sign/` | Sign PDF (async job) |
| GET | `/api/v1/sign/{id}/status` | Job status |
| GET | `/api/v1/sign/{id}/download` | Download signed PDF |
| POST | `/api/v1/validate/` | Validate signatures |
| POST | `/api/v1/validate/batch` | Batch validation |
| GET | `/api/v1/certificates/` | List certificates |

**Auth:** JWT Bearer token OR `X-API-Key` header

## Testing

- **~1240 tests** (unit + integration + E2E + API)
- **87% coverage** on core (excludes gui/)
- **GUI tests:** mocks in `conftest_gui.py`, no display
- **API tests:** `tests/integration/test_api.py` (39 tests)
- **Naming:** `test_<func>_<scenario>_<expected>`

### GTK Mock Testing Patterns

```python
# ✗ Don't verify MagicMock object identity (IDs differ each access)
mock_widget.update_property.assert_called_with([Gtk.AccessibleProperty.LABEL], ["Test"])

# ✓ Verify VALUES passed instead
call_args = mock_widget.update_property.call_args
properties, values = call_args[0]
assert values == ["Test"]

# ✗ Don't use issubclass() with mocked GTK classes
assert issubclass(ShortcutsWindow, Gtk.ShortcutsWindow)  # False with mocks

# ✓ Use inspect.getsource() for inheritance/method checks
import inspect
source = inspect.getsource(ShortcutsWindow)
assert "class ShortcutsWindow(Gtk.ShortcutsWindow)" in source

# ✓ For action/shortcut creation, verify source code directly
source = inspect.getsource(PDFSignerApp.create_actions)
assert 'Gio.SimpleAction.new("open", None)' in source
```

## Configuration

Location: `~/.config/pdfsigner/config.toml`

| Setting | Default | Description |
|---------|---------|-------------|
| `nss_db_path` | `~/.nss` | NSS database |
| `tsa_url` | `""` | Timestamp server |
| `dry_run` | `false` | Simulation mode |
| `output_suffix` | `"_signed"` | Output suffix |
| `ltv_enabled` | `true` | Embed DSS (PAdES B-LT) |
| `ltv_fail_open` | `true` | Continue if LTV fails |
| `archive_ts_enabled` | `false` | Enable archive timestamps |
| `archive_ts_auto` | `false` | Auto-add after DSS (B-LTA) |
| `revocation_check_enabled` | `false` | OCSP/CRL check |
| `recent_files_enabled` | `true` | Track recent PDFs |

## Adding Token Support

Edit `PKCS11_LIB_PATHS` in `core/token/pkcs11_libs.py`

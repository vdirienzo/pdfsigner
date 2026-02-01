# CLAUDE.md

## Project Overview

**PDFSigner** - Digital PDF signing for Linux/GNOME with PKCS#11/NSS token support.

**Stack:** Python 3.12+, uv, GTK4/libadwaita, pyHanko (PAdES-LTV), PyMuPDF, NSS/python-pkcs11

## Commands

```bash
# Run
uv run pdfsigner-gui                    # GUI
uv run pdfsigner --dry-run sign f.pdf   # CLI dry-run

# Test
uv run pytest -v                        # 1091 tests
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
| `core/signer/pdf_signer.py` | Main signing (4 phases) |
| `core/signer/batch_manager.py` | Batch orchestration |
| `core/token/nss_handler.py` | PKCS#11 communication |
| `core/signature/` | Template system |
| `core/audit/` | Audit trail (JSON Lines) |
| `gui/handlers/` | GUI ↔ Core bridge |
| `gui/settings_pages/` | Settings pages (factory pattern) |

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

## Testing

- **1091 tests** (unit + integration + E2E)
- **87% coverage** on core (excludes gui/)
- **GUI tests:** mocks in `conftest_gui.py`, no display
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
| `pin_cache_enabled` | `false` | Cache PIN |
| `audit_enabled` | `true` | Audit logging |
| `signature_template` | `""` | Template (empty=invisible) |
| `revocation_check_enabled` | `false` | OCSP/CRL check |
| `recent_files_enabled` | `true` | Track recent PDFs |
| `system_notifications_enabled` | `true` | Desktop notifications |

## Adding Token Support

Edit `PKCS11_LIB_PATHS` in `core/token/pkcs11_libs.py`

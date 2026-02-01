# PDFSigner v1.2 - Plan de Implementacion

## Resumen Ejecutivo

**Objetivo:** Completar la integracion UI de las features implementadas en v1.1 y agregar tests.

| # | Tarea | Esfuerzo | Impacto |
|---|-------|----------|---------|
| 1 | Settings UI para nuevas features | ~3h | UX completa |
| 2 | Shortcuts Window (GTK4) | ~1h | Discoverability |
| 3 | Tests para nuevos modulos | ~2h | Quality assurance |
| 4 | Bump version a 1.1.0 | ~30min | Release |
| | **TOTAL** | **~6.5h** | **Alto** |

---

## Estado Actual (v1.1.0)

### Features Implementadas (Core + GUI basica)

| Feature | Core | Settings | UI Config |
|---------|------|----------|-----------|
| RevocationChecker | OK | 4 campos | NO |
| Recent Files | OK | 2 campos | NO |
| Notifications | OK | 1 campo | NO |
| Keyboard Shortcuts | OK | - | NO (sin help) |
| Accessibility | OK | - | - |

### Archivos Nuevos en v1.1
```
src/pdfsigner/
├── core/
│   ├── recent/
│   │   ├── __init__.py
│   │   └── recent_manager.py         # 141 lineas
│   └── notifications/
│       ├── __init__.py
│       └── notification_manager.py   # 261 lineas
└── gui/widgets/
    └── recent_files_popover.py       # 225 lineas
```

---

## FASE 1: Settings UI para Nuevas Features (~3h)

### 1.1 Pagina de Validacion (Revocation Settings)

**Archivo:** `src/pdfsigner/gui/settings_pages/validation_page.py` (NUEVO)

**Campos a agregar:**
| Campo | Widget | Default |
|-------|--------|---------|
| `revocation_check_enabled` | Adw.SwitchRow | false |
| `revocation_check_timeout` | Adw.SpinRow (5-60) | 10 |
| `revocation_cache_ttl` | Adw.SpinRow (300-86400) | 3600 |
| `revocation_prefer_ocsp` | Adw.SwitchRow | true |

**Estructura UI:**
```
Validation
├── Certificate Revocation
│   ├── [Switch] Enable revocation checking
│   ├── [Spin] Timeout (seconds): 10
│   ├── [Spin] Cache TTL (seconds): 3600
│   └── [Switch] Prefer OCSP over CRL
```

### 1.2 Pagina de Comportamiento (Recent Files + Notifications)

**Archivo:** `src/pdfsigner/gui/settings_pages/behavior_page.py` (NUEVO o modificar existente)

**Campos a agregar:**
| Campo | Widget | Default |
|-------|--------|---------|
| `recent_files_enabled` | Adw.SwitchRow | true |
| `recent_files_limit` | Adw.SpinRow (5-50) | 10 |
| `system_notifications_enabled` | Adw.SwitchRow | true |

**Estructura UI:**
```
Behavior
├── Recent Files
│   ├── [Switch] Track recent files
│   └── [Spin] Maximum files to show: 10
├── Notifications
│   └── [Switch] Show system notifications
```

### 1.3 Integracion en SettingsDialog

**Archivo a modificar:** `src/pdfsigner/gui/settings_dialog.py`

```python
# Agregar paginas nuevas al navigation
self._add_page("validation", _("Validation"), ValidationPage())
self._add_page("behavior", _("Behavior"), BehaviorPage())
```

---

## FASE 2: Shortcuts Window (~1h)

### 2.1 Dialogo de Atajos de Teclado

**Archivo:** `src/pdfsigner/gui/dialogs/shortcuts_window.py` (NUEVO)

**Usar GTK4 ShortcutsWindow nativo:**

```python
from gi.repository import Gtk

class ShortcutsWindow(Gtk.ShortcutsWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Section: General
        section = Gtk.ShortcutsSection(title=_("General"))
        group = Gtk.ShortcutsGroup(title=_("Application"))

        shortcuts = [
            ("Ctrl+O", _("Open files")),
            ("Ctrl+S", _("Sign selected files")),
            ("Ctrl+Shift+V", _("Validate signatures")),
            ("Ctrl+L", _("Clear file list")),
            ("Delete", _("Clear file list")),
            ("Ctrl+,", _("Preferences")),
            ("F1", _("About")),
            ("Ctrl+Q", _("Quit")),
        ]

        for accel, title in shortcuts:
            shortcut = Gtk.ShortcutsShortcut(
                accelerator=accel,
                title=title,
            )
            group.append(shortcut)

        section.append(group)
        self.append(section)
```

### 2.2 Integracion

**Archivos a modificar:**

| Archivo | Cambio |
|---------|--------|
| `gui/app.py` | Agregar action `app.shortcuts` + atajo `<Control>question` |
| `gui/main_window.py` | Agregar boton ? en header (opcional) |

---

## FASE 3: Tests para Nuevos Modulos (~2h)

### 3.1 Tests NotificationManager

**Archivo:** `tests/unit/test_notification_manager.py` (NUEVO)

**Tests a implementar:**
```python
# Singleton
def test_get_notification_manager_returns_singleton():
def test_notification_manager_thread_safe():

# Should notify logic
def test_should_notify_when_window_unfocused():
def test_should_not_notify_when_window_focused():
def test_should_not_notify_when_disabled():

# Batch complete
def test_notify_batch_complete_all_success():
def test_notify_batch_complete_with_failures():
def test_notify_batch_complete_respects_disabled():

# Certificate health
def test_notify_certificate_health_warning():
def test_notify_certificate_health_critical():
def test_notify_certificate_health_anti_spam():
def test_notify_certificate_health_only_once_per_serial():

# Critical error
def test_notify_critical_error():
```

### 3.2 Tests RecentFilesManager

**Archivo:** `tests/unit/test_recent_manager.py` (NUEVO)

**Tests a implementar:**
```python
# Singleton
def test_get_recent_files_manager_returns_singleton():

# Add file
def test_add_file_registers_in_recent():
def test_add_file_with_operation():
def test_add_file_respects_disabled_setting():

# Get recent
def test_get_recent_pdfs_returns_pdf_only():
def test_get_recent_pdfs_respects_limit():
def test_get_recent_pdfs_sorted_by_date():

# Clear
def test_clear_pdf_history():

# Edge cases
def test_add_nonexistent_file_handles_gracefully():
def test_get_recent_with_deleted_files():
```

### 3.3 Tests RecentFilesPopover

**Archivo:** `tests/unit/gui/test_recent_files_popover.py` (NUEVO)

**Tests a implementar:**
```python
def test_popover_creation():
def test_format_relative_time_seconds():
def test_format_relative_time_minutes():
def test_format_relative_time_hours():
def test_format_relative_time_days():
def test_format_relative_time_weeks():
def test_populate_with_files():
def test_populate_empty_shows_placeholder():
```

---

## FASE 4: Bump Version + Release (~30min)

### 4.1 Archivos a Actualizar

| Archivo | Cambio |
|---------|--------|
| `pyproject.toml` | `version = "1.1.0"` |
| `gui/app.py` | `version="1.1.0"` en AboutWindow |
| `debian/changelog` | Nueva entrada 1.1.0 |

### 4.2 Comandos de Release

```bash
# Verificar todo pasa
uv run pytest -v
uv run ruff check . && uv run mypy src/

# Commit version bump
git add -A
git commit -m "chore: bump version to 1.1.0"

# Tag
git tag -a v1.1.0 -m "Release v1.1.0 - Revocation, Recent Files, Shortcuts, A11y, Notifications"
git push origin dev --tags
```

---

## Orden de Implementacion Recomendado

```
┌─────────────────────────────────────────────────────────────┐
│                    PARALELO GRUPO 1                          │
├─────────────────────────┬───────────────────────────────────┤
│ FASE 1.1: Validation    │ FASE 1.2: Behavior Page           │
│ Page (revocation)       │ (recent + notifications)          │
└─────────────────────────┴───────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    SECUENCIAL                                │
├─────────────────────────────────────────────────────────────┤
│ FASE 1.3: Integrar en SettingsDialog                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    PARALELO GRUPO 2                          │
├─────────────────────────┬───────────────────────────────────┤
│ FASE 2: Shortcuts       │ FASE 3: Tests                     │
│ Window                  │ (notification + recent)           │
└─────────────────────────┴───────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    FINAL                                     │
├─────────────────────────────────────────────────────────────┤
│ FASE 4: Version bump + release                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Criterios de Aceptacion

1. [ ] Settings UI permite configurar revocation checking
2. [ ] Settings UI permite configurar recent files y notifications
3. [ ] Shortcuts window muestra todos los atajos disponibles
4. [ ] Tests para NotificationManager con >80% coverage
5. [ ] Tests para RecentFilesManager con >80% coverage
6. [ ] Todos los tests pasan (800+)
7. [ ] Version bumped a 1.1.0

---

## Notas Tecnicas

### Patron para Settings Pages
```python
class ValidationPage(Adw.PreferencesPage):
    def __init__(self):
        super().__init__(title=_("Validation"))
        self._settings = get_settings()
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        group = Adw.PreferencesGroup(title=_("Certificate Revocation"))

        self.revocation_switch = Adw.SwitchRow(
            title=_("Enable revocation checking"),
            subtitle=_("Check OCSP/CRL during validation"),
        )
        self.revocation_switch.set_active(self._settings.revocation_check_enabled)
        group.add(self.revocation_switch)

        self.add(group)

    def _connect_signals(self):
        self.revocation_switch.connect("notify::active", self._on_setting_changed)

    def _on_setting_changed(self, *args):
        # Debounced auto-save pattern
        GLib.timeout_add(500, self._save_settings)
```

### Mocking GTK para Tests
```python
# En conftest.py
@pytest.fixture
def mock_gtk_recent_manager(mocker):
    """Mock GTK RecentManager for tests without display."""
    mock = mocker.MagicMock()
    mocker.patch("gi.repository.Gtk.RecentManager.get_default", return_value=mock)
    return mock

@pytest.fixture
def mock_gio_notification(mocker):
    """Mock Gio.Notification for tests."""
    mock = mocker.MagicMock()
    mocker.patch("gi.repository.Gio.Notification", return_value=mock)
    return mock
```

---

## Dependencias

No se requieren dependencias nuevas. Todo usa GTK4/libadwaita existente.

---

## Fuera de Alcance (v1.3+)

- Editor visual de templates de firma
- Soporte para multiples perfiles de configuracion
- Sincronizacion de configuracion en la nube
- Plugins/extensiones de terceros

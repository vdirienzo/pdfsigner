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
uv run pdfsigner encrypt doc.pdf        # Encrypt PDF (AES-256)
uv run pdfsigner decrypt doc_enc.pdf    # Decrypt PDF
uv run pdfsigner-api                    # REST API server

# Test
uv run pytest -v                        # ~2473 tests
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
| `core/encryption/` | PDF encryption (AES-256) for HIPAA §164.312(a)(2)(iv) |
| `core/audit/` | Enhanced audit trail with HMAC integrity (HIPAA §164.312(b)) |
| `core/users/` | User registry with certificate binding (HIPAA §164.312(d)) |
| `core/crypto/fips_provider.py` | FIPS 140-2 algorithm validation (NIST SC-13) |
| `core/crypto/key_manager.py` | Secure key storage with encryption/rotation (NIST SC-12) |
| `core/auth/password_policy.py` | Password policy config (NIST IA-5) |
| `core/auth/password_validator.py` | Password validation + Argon2 hashing |
| `core/auth/mfa/` | TOTP MFA + backup codes (NIST IA-8) |
| `core/eidas/tsp_registry.py` | EU Trusted List of TSPs (eIDAS Art. 22) |
| `core/eidas/qualified_validator.py` | QES validation (eIDAS Art. 25-28) |
| `core/gdpr/consent_manager.py` | GDPR consent tracking (Art. 7) |
| `core/breach/breach_manager.py` | Breach detection & notification (GDPR Art. 33-34) |
| `core/compliance/evidence_collector.py` | SOC 2 evidence collection (CC series) |
| `core/compliance/soc2_report.py` | SOC 2 Type II report generation |
| `core/security/vuln_scanner.py` | Vulnerability scanning (Semgrep/pip-audit) |
| `core/security/vuln_tracker.py` | Vulnerability tracking & remediation (NIST RA-5) |
| `api/` | REST API (FastAPI) |
| `api/middleware/tls.py` | TLS/HTTPS enforcement, mTLS, redirect middleware |
| `gui/handlers/` | GUI ↔ Core bridge |

### Patterns

**Settings pages:** `create_X_page(settings, dialog) -> Adw.PreferencesPage`
- Store widget refs in `dialog.widget_name` for auto-save

**GUI threading:** `GLib.idle_add()` for UI updates from background threads

**Dry-run:** `dry_run=true` → MockBatchManager, no token needed

**Encryption (HIPAA):** `PDFEncryptor` orchestrates password-based AES-256 encryption
- `PasswordHandler` uses PyMuPDF for actual encryption/decryption
- `EncryptionValidator` enforces HIPAA-compliant settings (AES-256, no print)
- `CredentialStore` uses keyring for secure password storage

**Audit Integrity:** Chain hashing + HMAC signing for tamper detection
- `AuditIntegrityManager.sign_event()` → adds `record_hash`, `hmac_signature`, `previous_hash`
- `verify_chain()` validates entire audit log sequence
- Singleton: `get_audit_integrity_manager()`

**User Registry:** SQLite-backed user management with certificate binding
- `UserRepository` for CRUD operations
- `CertificateBindingService.get_or_create_user_for_certificate()` auto-creates users from PKCS#11 certs

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

### Audit Integrity Verification
```python
# ✓ Check critical issues including file-level errors
has_critical = any(i.get("severity") == "critical" for i in report["issues"])
is_valid = invalid == 0 and chain_intact and not has_critical

# ✗ Missing file errors not counted - returns True for missing files!
is_valid = report["invalid_records"] == 0 and report["chain_intact"]
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
| GET | `/api/v1/users/me` | Current user info |
| GET | `/api/v1/users/` | List users (admin) |
| GET | `/api/v1/sessions/` | List user sessions |
| DELETE | `/api/v1/sessions/{id}` | Terminate session |
| POST | `/api/v1/emergency/request` | Request break-glass |
| GET | `/api/v1/emergency/pending` | Pending requests (admin) |
| POST | `/api/v1/emergency/{id}/approve` | Approve request (admin) |

**Auth:** JWT Bearer token OR `X-API-Key` header

### TLS/HTTPS Configuration

**Module:** `api/middleware/tls.py`

Enable TLS by setting environment variables or config:

```bash
# Environment variables
export PDFSIGNER_API_TLS_ENABLED=true
export PDFSIGNER_API_TLS_CERT_PATH=/path/to/cert.pem
export PDFSIGNER_API_TLS_KEY_PATH=/path/to/key.pem
export PDFSIGNER_API_TLS_MIN_VERSION=TLSv1.2  # or TLSv1.3

# Run with TLS
uv run pdfsigner-api
# or
uvicorn pdfsigner.api.main:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```

**TLS Settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `tls_enabled` | `false` | Enable TLS/HTTPS for API |
| `tls_cert_path` | `""` | Path to TLS certificate (PEM) |
| `tls_key_path` | `""` | Path to TLS private key (PEM) |
| `tls_min_version` | `"TLSv1.2"` | Minimum TLS version (TLSv1.2/TLSv1.3) |
| `tls_require_client_cert` | `false` | Enable mTLS (mutual TLS) |
| `tls_ca_cert_path` | `""` | CA cert for client verification (mTLS) |
| `tls_redirect_http` | `true` | Redirect HTTP → HTTPS |
| `tls_strict_mode` | `false` | Reject HTTP entirely (no redirect) |

**Features:**
- HTTP to HTTPS redirect (301)
- Strict mode rejects HTTP (426 Upgrade Required)
- X-Forwarded-Proto support for proxies/load balancers
- mTLS with client certificate verification
- Configurable TLS version (1.2 or 1.3)
- Startup validation of TLS configuration

**Example mTLS:**

```bash
export PDFSIGNER_API_TLS_REQUIRE_CLIENT_CERT=true
export PDFSIGNER_API_TLS_CA_CERT_PATH=/path/to/ca.pem
```

## Testing

- **~1750 tests** (unit + integration + E2E + API)
- **87% coverage** on core (excludes gui/)
- **GUI tests:** mocks in `conftest_gui.py`, no display
- **API tests:** `tests/integration/test_api.py` (39 tests)
- **TLS tests:** `tests/unit/test_tls_middleware.py` (28 tests)
- **Healthcare tests:** 76 tests for encryption, audit integrity, user registry
- **Gov Compliance tests:** FIPS (25), TLS (28), Key Manager (30)
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
| `encryption_enabled` | `false` | Auto-encrypt after signing |
| `encryption_strength` | `"aes256"` | AES-128 or AES-256 |
| `encryption_method` | `"password"` | password or certificate |
| `encryption_store_password` | `false` | Store in keyring |
| `encryption_hipaa_mode` | `false` | Enforce HIPAA restrictions |
| `encryption_allow_print` | `false` | Allow printing (HIPAA: must be false) |
| `healthcare_mode` | `false` | Enable HIPAA compliance mode |
| `healthcare_session_timeout_minutes` | `15` | Auto-logoff timeout (5-60) |
| `healthcare_max_sessions` | `3` | Max concurrent sessions per user |
| `healthcare_emergency_duration_hours` | `4` | Emergency access duration |
| `healthcare_emergency_require_approval` | `true` | Require admin approval for emergency |
| `fips_mode_enabled` | `false` | Enable FIPS 140-2 crypto mode |
| `fips_strict_mode` | `true` | Raise exception for non-FIPS algorithms |
| `key_storage_path` | `""` | Path to encrypted key database |
| `key_default_expiry_days` | `365` | Default key expiration |
| `key_auto_rotate_days` | `90` | Auto-rotate keys older than this |

## Adding Token Support

Edit `PKCS11_LIB_PATHS` in `core/token/pkcs11_libs.py`

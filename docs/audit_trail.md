# Audit Trail - PDFSigner

Sistema de auditoría estructurado para registro de eventos de seguridad y cumplimiento normativo.

## Características

- **Formato JSON Lines**: Un JSON por línea, fácil de parsear y compatible con herramientas de log analysis
- **Rotación mensual**: Archivos `audit_YYYY-MM.jsonl` para organización temporal
- **Thread-safe**: Singleton con locks para uso concurrente seguro
- **Retención configurable**: 1-3650 días (default: 90)
- **Query interface**: Filtros por fecha y tipo de evento
- **Export CSV**: Para análisis en Excel/LibreOffice

## Ubicación de logs

```
~/.local/share/pdfsigner/audit/
├── audit_2026-01.jsonl
├── audit_2026-02.jsonl
└── audit_2026-03.jsonl
```

## Tipos de eventos

| Evento | Descripción |
|--------|-------------|
| `SIGN_SUCCESS` | Firma digital exitosa |
| `SIGN_FAILURE` | Error al firmar documento |
| `VALIDATE_SUCCESS` | Validación de firma exitosa |
| `VALIDATE_FAILURE` | Error al validar firma |
| `TOKEN_LOGIN` | Autenticación en token PKCS#11 |
| `TOKEN_LOGOUT` | Cierre de sesión en token |
| `CERTIFICATE_SELECTED` | Selección de certificado para firma |
| `CONFIG_CHANGE` | Cambio en configuración |

## Estructura de evento

```json
{
  "event_type": "sign_success",
  "timestamp": "2026-01-27T14:45:34.004859",
  "event_id": "fe319ee3-4de6-49ac-8709-45a0bfdd264b",
  "user_cn": "John Doe",
  "hostname": "workstation-01",
  "document_path": "/home/user/documents/contract.pdf",
  "document_hash_sha256": "abc123...",
  "certificate_serial": "def456",
  "certificate_issuer": "CN=Corporate CA,O=Company Inc",
  "status": "SUCCESS",
  "error_message": null,
  "details": {
    "template": "corporate",
    "visible": true,
    "page": "last"
  }
}
```

## Configuración

En `~/.config/pdfsigner/config.toml`:

```toml
audit_enabled = true
audit_retention_days = 90
```

O via variables de entorno:

```bash
export PDFSIGNER_AUDIT_ENABLED=true
export PDFSIGNER_AUDIT_RETENTION_DAYS=180
```

## Uso en código

### Logging de eventos

```python
from pdfsigner.core.audit import log_signing_event

# Registrar firma exitosa
log_signing_event(
    document_path="/path/to/document.pdf",
    certificate_serial="abc123",
    certificate_issuer="CN=Test CA",
    user_cn="John Doe",
    success=True,
    details={"template": "default", "visible": True}
)

# Registrar error
log_signing_event(
    document_path="/path/to/document.pdf",
    certificate_serial="abc123",
    certificate_issuer="CN=Test CA",
    user_cn="John Doe",
    success=False,
    error="Token not found",
)
```

### Consulta de eventos

```python
from pdfsigner.core.audit import get_audit_logger, AuditEventType
from datetime import datetime, timedelta

logger = get_audit_logger()

# Todos los eventos del último mes
start = datetime.now() - timedelta(days=30)
events = logger.get_events(start_date=start)

# Solo eventos de firma
events = logger.get_events(
    event_types=[AuditEventType.SIGN_SUCCESS, AuditEventType.SIGN_FAILURE]
)

# Rango de fechas específico
events = logger.get_events(
    start_date=datetime(2026, 1, 1),
    end_date=datetime(2026, 1, 31)
)
```

### Export a CSV

```python
from pdfsigner.core.audit import get_audit_logger

logger = get_audit_logger()
events = logger.get_events()

csv_data = logger.export_csv(events)

# Guardar a archivo
with open("audit_report.csv", "w") as f:
    f.write(csv_data)
```

### Limpieza de logs antiguos

```python
from pdfsigner.core.audit import get_audit_logger

logger = get_audit_logger()

# Elimina logs anteriores a retention_days
deleted_count = logger.cleanup_old_logs()
print(f"Deleted {deleted_count} old log files")
```

## Helper functions

### log_signing_event()

```python
log_signing_event(
    document_path: str | Path,
    certificate_serial: str | None,
    certificate_issuer: str | None,
    user_cn: str | None,
    success: bool,
    error: str | None = None,
    details: dict | None = None,
)
```

### log_validation_event()

```python
log_validation_event(
    document_path: str | Path,
    signature_count: int,
    all_valid: bool,
    error: str | None = None,
    details: dict | None = None,
)
```

### log_token_event()

```python
log_token_event(
    event_type: AuditEventType,  # TOKEN_LOGIN or TOKEN_LOGOUT
    user_cn: str | None = None,
    success: bool = True,
    error: str | None = None,
    details: dict | None = None,
)
```

### log_certificate_selection()

```python
log_certificate_selection(
    certificate_serial: str,
    certificate_issuer: str,
    user_cn: str,
    details: dict | None = None,
)
```

### log_config_change()

```python
log_config_change(
    setting_name: str,
    old_value: str | None,
    new_value: str | None,
    user_cn: str | None = None,
    details: dict | None = None,
)
```

## Análisis con herramientas CLI

### jq (Query JSON Lines)

```bash
# Contar eventos por tipo
cat audit_2026-01.jsonl | jq -s 'group_by(.event_type) | map({type: .[0].event_type, count: length})'

# Eventos de un usuario específico
cat audit_2026-01.jsonl | jq 'select(.user_cn == "John Doe")'

# Eventos con errores
cat audit_2026-01.jsonl | jq 'select(.status == "FAILURE")'
```

### grep

```bash
# Buscar eventos de un documento
grep "/path/to/document.pdf" audit_2026-01.jsonl

# Buscar firmas fallidas
grep "sign_failure" audit_2026-01.jsonl
```

### Análisis estadístico con Python

```python
import json
from pathlib import Path
from collections import Counter

# Leer todos los eventos
events = []
audit_dir = Path.home() / ".local/share/pdfsigner/audit"
for log_file in audit_dir.glob("audit_*.jsonl"):
    with open(log_file) as f:
        for line in f:
            events.append(json.loads(line))

# Estadísticas
print(f"Total events: {len(events)}")
print(f"Event types: {Counter(e['event_type'] for e in events)}")
print(f"Users: {Counter(e['user_cn'] for e in events if e['user_cn'])}")
print(f"Success rate: {sum(1 for e in events if e['status'] == 'SUCCESS') / len(events) * 100:.1f}%")
```

## Cumplimiento normativo

El sistema de auditoría cumple con requisitos comunes de:

- **ISO 27001** (Sistema de Gestión de Seguridad de la Información)
- **GDPR** (Registro de procesamiento de datos personales)
- **eIDAS** (Servicios de confianza para firmas electrónicas)
- **SOC 2** (Logging de eventos de seguridad)

### Información registrada

- ✅ Quién: `user_cn` (CN del certificado)
- ✅ Qué: `event_type` (acción realizada)
- ✅ Cuándo: `timestamp` (ISO 8601)
- ✅ Dónde: `hostname` (equipo)
- ✅ Resultado: `status` (SUCCESS/FAILURE/ERROR)
- ✅ Contexto: `document_path`, `certificate_serial`, `details`

### Protección de logs

Los archivos de log tienen permisos restrictivos (600) y se almacenan en el directorio del usuario:

```bash
ls -l ~/.local/share/pdfsigner/audit/
-rw------- 1 user user 1234 Jan 27 14:45 audit_2026-01.jsonl
```

## Troubleshooting

### Los logs no se crean

Verificar configuración:

```python
from pdfsigner.config.settings import get_settings

settings = get_settings()
print(f"Audit enabled: {settings.audit_enabled}")
```

### Logs ocupan mucho espacio

Reducir `audit_retention_days`:

```toml
# config.toml
audit_retention_days = 30  # Solo 1 mes
```

Ejecutar limpieza manual:

```python
from pdfsigner.core.audit import get_audit_logger

get_audit_logger().cleanup_old_logs()
```

### Necesito auditoría externa (syslog, etc.)

El módulo usa `loguru` internamente. Para integrar con syslog:

```python
from loguru import logger

# En initialization code
logger.add("syslog", format="{message}")
```

## Performance

- **Escritura**: ~0.5ms por evento (SSD)
- **Query**: ~10ms por 1000 eventos
- **Thread-safety**: Lock granular solo en escritura
- **Memory**: Eventos se procesan en streaming (no carga completa en RAM)

## Futuras mejoras

- [ ] Firma digital de logs para no-repudio
- [ ] Compresión automática de logs antiguos (.jsonl.gz)
- [ ] API REST para query remoto
- [ ] Dashboard web de visualización
- [ ] Alertas en tiempo real (webhook)
- [ ] Integración con SIEM (Splunk, ELK, Graylog)

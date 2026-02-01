# Business Continuity Plan (BCP) - PDFSigner v2.0

> **Fecha:** 2026-02-01
> **Version:** 1.0
> **Cumplimiento:** HIPAA §164.308(a)(7), NIST 800-53 CP-9, SOC 2 CC9.1
> **Clasificacion:** INTERNAL

---

## Resumen Ejecutivo

Este documento define como responder y recuperar PDFSigner ante fallas criticas.

| Metrica | Objetivo |
|---------|----------|
| **RTO (Recovery Time)** | 4 horas (maximo) |
| **RPO (Recovery Point)** | 24 horas (ultimo backup) |
| **Disponibilidad Target** | 99.5% uptime |

---

## 1. SERVICIOS CRITICOS

### 1.1 Servicios Internos

| Servicio | Modulo | Criticidad | Funcion |
|----------|--------|------------|---------|
| **PDF Signing** | `core/signer/pdf_signer.py` | CRITICA | Firma PAdES-LTA (6 fases) |
| **PDF Validation** | `core/validator/pdf_validator.py` | CRITICA | Validacion de firmas |
| **PKCS#11 Token** | `core/token/nss_handler.py` | CRITICA | Comunicacion con tokens USB |
| **REST API** | `api/main.py` | ALTA | Servidor FastAPI |
| **User Management** | `core/users/user_repository.py` | ALTA | Gestion de usuarios/RBAC |
| **Audit Logging** | `core/audit/audit_logger.py` | ALTA | Logs con HMAC integrity |
| **DSS Manager** | `core/signer/dss_manager.py` | ALTA | OCSP/CRL para PAdES B-LT |
| **Archive Timestamps** | `core/signer/archive_ts_manager.py` | MEDIA | PAdES B-LTA |

### 1.2 Dependencias Externas

| Proveedor | Tipo | URL | Alternativa |
|-----------|------|-----|-------------|
| **DigiCert TSA** | Timestamp | `http://timestamp.digicert.com` | FreeTSA |
| **FreeTSA** | Timestamp | `https://freetsa.org/tsr` | Sectigo |
| **EU LOTL** | Trust List | `https://ec.europa.eu/tools/lotl/eu-lotl.xml` | Cache local (7 dias) |
| **OCSP Responders** | Revocacion | Extraido de certificados | CRL fallback |

### 1.3 Datos Criticos

| Dato | Ubicacion | Backup | Frecuencia |
|------|-----------|--------|------------|
| **NSS Database** | `~/.nss/` | CRITICO | Diario |
| **Users DB** | `~/.config/pdfsigner/users.db` | CRITICO | Cada cambio |
| **Keys DB** | `~/.local/share/pdfsigner/keys/keys.db` | CRITICO | Cada cambio |
| **Audit Logs** | `~/.local/share/pdfsigner/audit/` | CRITICO | Continuo |
| **Config** | `~/.config/pdfsigner/config.toml` | IMPORTANTE | Cada cambio |
| **Sessions DB** | `~/.config/pdfsigner/sessions.db` | NO (regenerable) | - |

---

## 2. ESCENARIOS DE FALLO Y RTO/RPO

### 2.1 Matriz de Escenarios

| # | Escenario | Probabilidad | Impacto | RTO | RPO |
|---|-----------|--------------|---------|-----|-----|
| 1 | **Servidor caido** | Media | Critico | 4h | 15min |
| 2 | **DB SQLite corrupta** | Baja | Alto | 2h | 24h |
| 3 | **TSA no disponible** | Alta | Medio | 30min | 0 |
| 4 | **Certificado expirado** | Media | Critico | 8-48h | 0 |
| 5 | **NSS DB corrupta** | Baja | Critico | 1h | N/A |
| 6 | **Disco lleno** | Media | Alto | 30min | 0 |
| 7 | **Config perdida** | Baja | Medio | 15min | Variable |
| 8 | **OCSP/CRL caido** | Alta | Bajo | 0 (auto) | 0 |
| 9 | **Audit log corrupto** | Baja | Alto | 4h | 0 |
| 10 | **Token USB perdido** | Baja | Critico | 8-48h | 0 |

### 2.2 Detalle de Escenarios Criticos

#### Escenario 1: Servidor Caido
```
Sintomas:
- API devuelve HTTP 503/timeout
- GUI no responde

Causa tipica:
- Crash del host/VM
- OOM killer
- Kernel panic

Datos en riesgo:
- Jobs de firma en curso
- Sesiones activas
- Ultimos 15min de audit logs (buffer)
```

#### Escenario 2: DB SQLite Corrupta
```
Sintomas:
- Error: "database disk image is malformed"
- Usuario no puede autenticarse

Causa tipica:
- Power loss durante commit
- Disco lleno durante transaccion
- Bad sectors

Archivos afectados:
- users.db, sessions.db, emergency.db
- retention.db, archive_ts.db
```

#### Escenario 5: NSS Database Corrupta
```
Sintomas:
- NSSConfigError: NSS database not found
- Token no detectado

Causa tipica:
- Borrado accidental de ~/.nss/
- Permisos incorrectos
- Archivos cert9.db/key4.db corruptos

Recuperacion:
- Recrear NSS: certutil -N -d sql:$HOME/.nss
- Token fisico debe estar presente
```

---

## 3. PROCEDIMIENTOS DE RECUPERACION

### 3.1 Restaurar desde Backup

**Tiempo estimado:** 5-15 minutos

```bash
# 1. Listar backups disponibles
ls -la ~/.local/share/pdfsigner/backups/

# 2. Restaurar via API (si disponible)
curl -X POST http://localhost:8000/api/v1/backup/restore \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"backup_id": "UUID", "password": "if_encrypted"}'

# 3. Restaurar manual
tar -xzf pdfsigner_backup_full_YYYYMMDD.tar.gz -C ~/

# 4. Verificar
sqlite3 ~/.config/pdfsigner/users.db "PRAGMA integrity_check;"
```

### 3.2 Reinstalar Aplicacion

**Tiempo estimado:** 10-20 minutos

```bash
# 1. Clonar repositorio
cd /opt && git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner

# 2. Instalar
./scripts/install.sh

# 3. O manual
sudo apt install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libnss3-tools
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# 4. Verificar
uv run pdfsigner --version
```

### 3.3 Recuperar Base de Datos

**Tiempo estimado:** 5-10 minutos

```bash
# 1. Detener aplicacion
pkill -f pdfsigner

# 2. Backup de DB corrupta
mv ~/.config/pdfsigner/users.db ~/.config/pdfsigner/users.db.corrupted

# 3. Restaurar desde backup
cp /backup/users.db ~/.config/pdfsigner/

# 4. Verificar integridad
sqlite3 ~/.config/pdfsigner/users.db "PRAGMA integrity_check;"

# 5. Si no hay backup, recrear
uv run python -c "
from pdfsigner.core.users import UserRepository
repo = UserRepository()  # Crea DB vacia
print('DB recreada')
"
```

### 3.4 Cambiar TSA Server (Failover)

**Tiempo estimado:** 2 minutos

```bash
# Opcion 1: Editar config
nano ~/.config/pdfsigner/config.toml
# Cambiar: tsa_url = "http://timestamp.digicert.com"

# Opcion 2: Variable de entorno (temporal)
export PDFSIGNER_TSA_URL="https://freetsa.org/tsr"

# Opcion 3: CLI override
uv run pdfsigner sign doc.pdf --tsa-url "https://freetsa.org/tsr"
```

**TSAs disponibles:**
| TSA | URL | Tipo |
|-----|-----|------|
| FreeTSA | `https://freetsa.org/tsr` | Gratuito |
| DigiCert | `http://timestamp.digicert.com` | Gratuito |
| Sectigo | `http://timestamp.sectigo.com` | Gratuito |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Gratuito |

### 3.5 Recuperar NSS Database

**Tiempo estimado:** 10-15 minutos

```bash
# 1. Backup NSS corrupto
mv ~/.nss ~/.nss.backup.$(date +%Y%m%d)

# 2. Crear nuevo NSS database
mkdir -p ~/.nss
certutil -N -d sql:$HOME/.nss
# Ingresa password para NSS (NO es el PIN del token)

# 3. Insertar token USB

# 4. Verificar que token se detecta
certutil -U -d sql:$HOME/.nss
certutil -L -d sql:$HOME/.nss -h all

# 5. Verificar con PDFSigner
uv run pdfsigner list-certs
```

### 3.6 Verificar Integridad de Audit Logs

**Tiempo estimado:** 5 minutos

```bash
# Verificar todos los logs
uv run python -c "
from pdfsigner.core.audit.audit_integrity import verify_audit_integrity
from pathlib import Path

audit_dir = Path.home() / '.local/share/pdfsigner/audit'
for log in sorted(audit_dir.glob('audit_*.jsonl')):
    ok, report = verify_audit_integrity(log)
    status = '✓' if ok else '✗ COMPROMETIDO'
    print(f'{status} {log.name}: {report[\"total_records\"]} registros')
"
```

**Si hay compromiso:**
1. Detener aplicacion inmediatamente
2. Preservar evidencia (snapshot de logs)
3. Notificar a Security Lead
4. Seguir Incident Response Plan

---

## 4. MATRIZ DE CONTACTOS

### 4.1 Roles Internos (COMPLETAR)

| Rol | Responsabilidad | Nombre | Telefono | Backup |
|-----|-----------------|--------|----------|--------|
| **Incident Commander** | Coordinacion general | [COMPLETAR] | [COMPLETAR] | [COMPLETAR] |
| **Security Lead** | Investigacion tecnica | [COMPLETAR] | [COMPLETAR] | [COMPLETAR] |
| **DevOps Lead** | Infraestructura, backups | [COMPLETAR] | [COMPLETAR] | [COMPLETAR] |
| **DBA** | Bases de datos SQLite | [COMPLETAR] | [COMPLETAR] | [COMPLETAR] |
| **Compliance Officer** | HIPAA, notificaciones | [COMPLETAR] | [COMPLETAR] | [COMPLETAR] |

### 4.2 Proveedores Externos

| Proveedor | Servicio | Contacto | SLA |
|-----------|----------|----------|-----|
| **DigiCert** | TSA | support@digicert.com / +1-801-701-9600 | 99.9% |
| **SafeNet/Thales** | Tokens USB | support@safenet-inc.com / +1-877-545-4774 | - |
| **Yubico** | YubiKey | support@yubico.com / +1-650-285-0088 | - |
| **EU Commission** | LOTL/TSL | digit-tsl@ec.europa.eu | - |

### 4.3 Autoridades (si breach PHI)

| Autoridad | Proposito | Contacto | Plazo |
|-----------|-----------|----------|-------|
| **HHS OCR** | HIPAA breach | ocrportal.hhs.gov | < 60 dias |
| **AEPD** | GDPR (Espana) | aepd.es | < 72h |
| **FBI Cyber** | Ransomware | IC3.gov | Inmediato |

---

## 5. NIVELES DE ESCALACION

| Nivel | Tiempo | Criterio | Contactar |
|-------|--------|----------|-----------|
| **L1 CRITICO** | < 15min | PHI breach, ransomware, sistema comprometido | Incident Commander + Security + Compliance + CISO |
| **L2 ALTO** | < 1h | Acceso no autorizado, malware, downtime > 4h | Security Lead + DevOps |
| **L3 MEDIO** | < 4h | Actividad sospechosa, TSA errors, degradacion | DevOps on-call |
| **L4 BAJO** | < 8h | Violacion menor, performance issues | On-call Engineer |

### Decision de Escalacion

```
¿PHI expuesto confirmado? → SI → L1 (Full IRT)
                          ↓ NO
¿Ransomware/compromiso?  → SI → L1 (Full IRT)
                          ↓ NO
¿Acceso no autorizado?   → SI → L2 (Security + Ops)
                          ↓ NO
¿Downtime > 4 horas?     → SI → L2 (DevOps + Security)
                          ↓ NO
                         L3-L4 (Seguir procedimiento)
```

---

## 6. BACKUP Y RESTAURACION

### 6.1 Estrategia de Backup

| Componente | Frecuencia | Retencion | Ubicacion |
|------------|------------|-----------|-----------|
| **Full backup** | Diario (02:00) | 90 dias | `~/.local/share/pdfsigner/backups/` |
| **Config** | Cada cambio | 30 dias | Incluido en full |
| **Audit logs** | Continuo | 7 anos (HIPAA) | Exportar a SIEM |
| **NSS database** | Diario | 30 dias | Manual |

### 6.2 Script de Backup Automatico

```bash
# Agregar a crontab
crontab -e

# Backup diario a las 02:00
0 2 * * * /opt/pdfsigner/.venv/bin/python -c "\
from pdfsigner.core.backup import get_backup_manager; \
get_backup_manager().create_backup(encrypt=True)"

# Verificacion semanal de integridad
0 3 * * 0 /opt/pdfsigner/.venv/bin/python -c "\
from pdfsigner.core.audit.audit_integrity import verify_audit_integrity; \
from pathlib import Path; \
[print(f.name, verify_audit_integrity(f)[0]) \
 for f in Path.home().glob('.local/share/pdfsigner/audit/audit_*.jsonl')]"
```

### 6.3 Backup Manual Critico

```bash
# NSS database (no incluido en backup automatico)
tar -czf ~/nss_backup_$(date +%Y%m%d).tar.gz ~/.nss/

# Config y datos
tar -czf ~/pdfsigner_manual_$(date +%Y%m%d).tar.gz \
  ~/.config/pdfsigner/ \
  ~/.local/share/pdfsigner/
```

---

## 7. CHECKLIST DE EMERGENCIA

### Primeros 60 Minutos (L1)

```
DETECCION (0-15 min):
☐ Verificar incidente real
☐ Clasificar severidad: __________
☐ Hora deteccion: __________
☐ Crear ticket: INC-__________

NOTIFICACION (15-30 min):
☐ Llamar Incident Commander
☐ Notificar Security Lead
☐ Activar bridge de emergencia

CONTENCION (30-60 min):
☐ Deshabilitar cuentas comprometidas
☐ Terminar sesiones sospechosas
☐ Aislar sistemas afectados
☐ Bloquear IPs atacantes

EVIDENCIA (paralelo):
☐ Snapshot audit logs
☐ Exportar datos de sesiones
☐ Calcular checksums
☐ Verificar integridad audit log
```

### Comandos de Emergencia

```bash
# Deshabilitar usuario
curl -X PATCH -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/users/$USER_ID" \
  -d '{"active": false}'

# Terminar sesiones de usuario
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/sessions/user/$USER_ID"

# Exportar audit (ultimos 7 dias)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/audit/events?days=7" \
  > /secure/forensics/audit-export.json

# Backup de emergencia
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/backup/create" \
  -d '{"encrypt": true}'
```

---

## 8. RECUPERACION TOTAL (Disaster Recovery)

**Tiempo estimado:** 30-60 minutos

### Fase 1: Sistema Base (15 min)
```bash
# Instalar OS (Debian 12 / Ubuntu 22.04+)
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-gi gir1.2-gtk-4.0 libnss3-tools opensc git
```

### Fase 2: Aplicacion (10 min)
```bash
cd /opt
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner && ./scripts/install.sh
```

### Fase 3: Datos (15 min)
```bash
# Transferir backup
scp backup_server:/backups/pdfsigner_full_*.tar.gz ~/

# Restaurar
tar -xzf pdfsigner_full_*.tar.gz -C ~/

# Verificar integridad
for db in ~/.config/pdfsigner/*.db; do
  sqlite3 "$db" "PRAGMA integrity_check;"
done
```

### Fase 4: Token y Verificacion (10 min)
```bash
# Verificar NSS
certutil -L -d sql:$HOME/.nss -h all

# Verificar certs
uv run pdfsigner list-certs

# Prueba de firma
uv run pdfsigner sign test.pdf
uv run pdfsigner validate test_signed.pdf

# Arrancar API
uv run pdfsigner-api &
curl http://localhost:8000/health
```

---

## 9. REVISION Y MANTENIMIENTO

| Actividad | Frecuencia | Responsable |
|-----------|------------|-------------|
| Actualizar contactos | Trimestral | Security Manager |
| Test de restauracion | Trimestral | DevOps |
| Tabletop exercise | Trimestral | CISO |
| Revision completa BCP | Anual | Security Team |

---

## Apendice: Estructura de Directorios

```
~/.config/pdfsigner/           # Configuracion
├── config.toml                # Config principal
├── users.db                   # Usuarios
├── sessions.db                # Sesiones (temporal)
└── *.db                       # Otras DBs

~/.local/share/pdfsigner/      # Datos
├── audit/                     # Logs JSONL
├── backups/                   # Backups automaticos
├── logs/                      # Logs aplicacion
└── keys/keys.db               # Claves (CRITICO)

~/.nss/                        # NSS para tokens
├── cert9.db
├── key4.db
└── pkcs11.txt
```

---

*Documento generado: 2026-02-01*
*Proxima revision: 2026-05-01*

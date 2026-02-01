# Guía de Configuración: SafeNet eToken con PDFSigner

## Resumen Ejecutivo

Esta guía explica cómo configurar tokens criptográficos SafeNet eToken (certificados por ONTI Argentina) para firmar documentos PDF con PDFSigner en sistemas Linux/GNOME.

**Tokens compatibles:**
- SafeNet eToken 5110 (USB-A, certificado ONTI)
- SafeNet eToken 5300 (USB-C)
- SafeNet eToken 5110+ FIPS (FIPS 140-2 Level 3)
- SafeNet eToken PRO (versiones anteriores)

**Requisitos:**
- Sistema Linux (Ubuntu 22.04+, Fedora 38+, Debian 12+)
- PDFSigner instalado (`uv run pdfsigner-gui`)
- Certificado digital de firma (AFIP, RENAPER, E-CERT, Andreani, etc.)
- Token SafeNet con certificado cargado

**Tiempo estimado:** 15-30 minutos

---

## 1. Verificación de Hardware

### 1.1 Identificar el Token

Conecta el token SafeNet al puerto USB y ejecuta:

```bash
# Verificar detección USB
lsusb | grep -i safenet
```

**Salida esperada:**
```
Bus 001 Device 012: ID 0529:0620 Aladdin Knowledge Systems Token JC
```

**Códigos de producto SafeNet:**
- `0529:0620` - SafeNet eToken 5110/PRO
- `0529:0600` - SafeNet eToken 5300
- `0529:0700` - SafeNet eToken 5110+ FIPS

Si no aparece:
- Verifica que el LED del token esté encendido
- Prueba otro puerto USB (preferir USB 2.0 sobre 3.0)
- Reinicia y vuelve a conectar

### 1.2 Verificar Modelo

En el token debe aparecer impreso:
- **Modelo:** eToken 5110, 5300, etc.
- **Número de serie:** SAFXXXX...
- **Certificación ONTI:** Solo modelos vendidos en Argentina

---

## 2. Instalación de Drivers

### 2.1 Ubuntu/Debian

```bash
# Opción 1: Repositorio oficial SafeNet (recomendado)
wget https://www3.safenet-inc.com/SupportDocuments/Linux-driver/SafenetAuthenticationClient-10.8-Linux-x64.deb
sudo dpkg -i SafenetAuthenticationClient-10.8-Linux-x64.deb

# Opción 2: Librería PKCS#11 directa (alternativa)
sudo apt-get update
sudo apt-get install -y libetoken
```

### 2.2 Fedora/RHEL/Rocky

```bash
# Opción 1: RPM oficial
wget https://www3.safenet-inc.com/SupportDocuments/Linux-driver/SafenetAuthenticationClient-10.8-Linux-x64.rpm
sudo rpm -ivh SafenetAuthenticationClient-10.8-Linux-x64.rpm

# Opción 2: Compilar desde fuente
sudo dnf install -y opensc pcsc-lite-libs
```

### 2.3 Arch Linux

```bash
# AUR package
yay -S safenet-authentication-client

# O usando OpenSC
sudo pacman -S opensc ccid
```

### 2.4 Verificar Instalación

```bash
# Buscar librería PKCS#11
find /usr -name "*eToken*.so" 2>/dev/null
```

**Rutas comunes:**
- `/usr/lib/libeToken.so` (Ubuntu/Debian)
- `/usr/lib64/libeToken.so` (Fedora/RHEL)
- `/opt/safenet/lib/libeToken.so` (instalador oficial)

Si no encuentras la librería:
```bash
# Usar OpenSC como fallback (compatible con SafeNet)
sudo apt-get install opensc
find /usr -name "opensc-pkcs11.so"
```

---

## 3. Configuración de NSS Database

PDFSigner usa la base de datos NSS (Network Security Services) de Mozilla para gestionar certificados y tokens PKCS#11.

### 3.1 Crear Database NSS

```bash
# Crear directorio
mkdir -p ~/.nss

# Inicializar database (sin contraseña)
certutil -N -d ~/.nss --empty-password

# Verificar creación
ls -lh ~/.nss/
```

**Archivos esperados:**
```
cert9.db  (certificados)
key4.db   (claves privadas)
pkcs11.txt (módulos PKCS#11)
```

### 3.2 Registrar Módulo SafeNet

```bash
# Añadir módulo eToken a NSS
modutil -dbdir ~/.nss -add "SafeNet eToken" -libfile /usr/lib/libeToken.so

# Verificar registro
modutil -dbdir ~/.nss -list
```

**Salida esperada:**
```
Listing of PKCS #11 Modules
-----------------------------------------------------------
  1. NSS Internal PKCS #11 Module
  2. SafeNet eToken
         library name: /usr/lib/libeToken.so
         slots: 2 slots attached
         status: loaded
```

Si usas OpenSC en lugar de eToken:
```bash
modutil -dbdir ~/.nss -add "OpenSC" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### 3.3 Solución: Database Corrupta

Si `modutil` falla con "database corrupted":

```bash
# Respaldar y recrear
mv ~/.nss ~/.nss.backup
mkdir ~/.nss
certutil -N -d ~/.nss --empty-password
modutil -dbdir ~/.nss -add "SafeNet eToken" -libfile /usr/lib/libeToken.so
```

---

## 4. Importación de Certificados

### 4.1 Verificar Certificado en Token

Conecta el token y ejecuta:

```bash
# Listar certificados (pedirá PIN)
certutil -d ~/.nss -L -h "SafeNet eToken"
```

**PIN predeterminado SafeNet:** `1234` (cámbialo inmediatamente)

**Salida esperada:**
```
Certificate Nickname                 Trust Attributes
                                     SSL,S/MIME,JAR/XPI

AFIP - Juan Perez - CUIT 20123456789-1  u,u,u
```

Si no aparecen certificados:
- El token está vacío → contacta a tu proveedor (AFIP, RENAPER, E-CERT, etc.)
- PIN incorrecto → verifica con tu certificadora
- Token no detectado → revisa Sección 2.4

### 4.2 Importar Cadena de Confianza (Opcional)

Para validación completa, importa certificados raíz de tu CA:

```bash
# Ejemplo: AFIP (Argentina)
wget https://www.afip.gob.ar/afipSimulada/AC_AFIP_Simulado.crt
certutil -d ~/.nss -A -t "TC,," -n "AFIP CA Root" -i AC_AFIP_Simulado.crt

# Verificar importación
certutil -d ~/.nss -L | grep AFIP
```

**Certificadoras argentinas comunes:**
- **AFIP:** https://www.afip.gob.ar/certificados/
- **RENAPER:** https://www.argentina.gob.ar/renaper/certificado-digital
- **E-CERT:** https://www.e-certchile.cl/ (opera en Argentina)
- **Andreani:** https://www.andreani.com/certificados-digitales

### 4.3 Verificar Atributos del Certificado

```bash
# Ver detalles completos
certutil -d ~/.nss -L -h "SafeNet eToken" -n "AFIP - Juan Perez - CUIT 20123456789-1"
```

**Campos críticos:**
- **Key Usage:** Digital Signature, Non-Repudiation
- **Extended Key Usage:** Email Protection, Code Signing
- **Valid:** Not Before / Not After (verificar vigencia)

---

## 5. Configuración de PDFSigner

### 5.1 Archivo de Configuración

PDFSigner lee la configuración de `~/.config/pdfsigner/config.toml`:

```bash
# Crear directorio si no existe
mkdir -p ~/.config/pdfsigner

# Editar configuración
nano ~/.config/pdfsigner/config.toml
```

**Configuración mínima:**
```toml
[core]
nss_db_path = "~/.nss"
dry_run = false

[signing]
ltv_enabled = true              # PAdES B-LT (DSS)
archive_ts_enabled = false      # PAdES B-LTA (archivo timestamp)
revocation_check_enabled = false

[timestamp]
tsa_url = "http://time.certisign.com.br"  # Ejemplo TSA público
```

**Configuración avanzada (Argentina/Ley 25.506):**
```toml
[core]
nss_db_path = "~/.nss"
dry_run = false
output_suffix = "_firmado"

[signing]
ltv_enabled = true
ltv_fail_open = true            # No fallar si LTV no está disponible
archive_ts_enabled = true       # Recomendado para cumplimiento
archive_ts_auto = true          # Auto-agregar timestamp de archivo
revocation_check_enabled = false # OCSP/CRL (puede requerir conectividad)

[timestamp]
# TSA certificado por Argentina
tsa_url = "http://tsa.safesign.com.ar:8318/tss"  # SafeSign Argentina
# Alternativa: https://freetsa.org/tsr (público, menor confianza)

[argentina]
# Cumplimiento Ley 25.506
fips_mode_enabled = true        # Requiere token FIPS (5110+ FIPS)
key_size_min = 2048             # RSA mínimo 2048 bits
hash_algorithm = "SHA256"       # SHA-256 o superior
audit_trail_enabled = true      # Registro de firmas
```

### 5.2 Verificar Detección del Token

```bash
# Modo dry-run (sin token)
uv run pdfsigner --dry-run sign test.pdf

# Modo real (detecta token)
uv run pdfsigner list-tokens
```

**Salida esperada:**
```
Available PKCS#11 tokens:
1. SafeNet eToken 5110 (Serial: SAF12345678)
   - Slot: 0
   - Label: eToken
   - Certificate: AFIP - Juan Perez - CUIT 20123456789-1
```

### 5.3 Configurar PIN Seguro

**IMPORTANTE:** Cambia el PIN predeterminado (`1234`) inmediatamente:

```bash
# Con herramienta SafeNet (si instalaste el cliente completo)
/opt/safenet/bin/SACSupportTool

# O con pkcs11-tool (OpenSC)
pkcs11-tool --module /usr/lib/libeToken.so --change-pin
```

**Recomendaciones de PIN:**
- Mínimo 6 dígitos/caracteres
- No usar fechas de nacimiento o secuencias (1234, 0000)
- Guardar en administrador de contraseñas
- **Cuidado:** 3 intentos fallidos bloquean el token

---

## 6. Prueba de Firma

### 6.1 Firma Simple (CLI)

```bash
# Crear PDF de prueba
echo "Documento de prueba" | enscript -B -p - | ps2pdf - prueba.pdf

# Firmar con PDFSigner
uv run pdfsigner sign prueba.pdf

# Verificar firma
uv run pdfsigner validate prueba_firmado.pdf
```

**Salida esperada:**
```
✓ Signature valid
✓ Certificate chain valid
✓ PAdES level: B-LT (Long-Term Validation)
✓ Timestamp present: 2026-02-01 10:30:45 UTC
✓ Compliant with: Ley 25.506 (Argentina)
```

### 6.2 Firma con GUI

```bash
# Iniciar interfaz gráfica
uv run pdfsigner-gui
```

**Pasos:**
1. Clic en **"Seleccionar PDF"** o arrastra archivo
2. Configura opciones:
   - Posición de firma (visible/invisible)
   - Razón: "Aprobación de documento"
   - Ubicación: "Buenos Aires, Argentina"
3. Clic en **"Firmar"**
4. Ingresa PIN del token cuando se solicite
5. Espera validación (DSS embedding, TSA timestamp)

**Tiempo:** 5-15 segundos por documento

### 6.3 Firma por Lotes (Batch)

```bash
# Firmar múltiples PDFs
uv run pdfsigner batch-sign *.pdf
```

**Optimizaciones:**
- Ingresa PIN una sola vez
- Procesamiento paralelo (hasta 4 PDFs simultáneos)
- Progreso en tiempo real

---

## 7. Solución de Problemas

### 7.1 "Token not found"

**Síntomas:**
```
TokenNotFoundError: No PKCS#11 library found
```

**Solución:**
```bash
# 1. Verificar USB
lsusb | grep -i safenet

# 2. Reinstalar driver
sudo apt-get install --reinstall libetoken

# 3. Verificar librería
ls -l /usr/lib/libeToken.so

# 4. Probar con OpenSC como fallback
modutil -dbdir ~/.nss -add "OpenSC" -libfile /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### 7.2 "PIN incorrect" (3 Intentos)

**Síntomas:**
```
TokenAuthenticationError: Incorrect PIN
```

**Solución:**
1. **NO INTENTES 3 VECES** (bloqueará el token)
2. Verifica el PIN con tu certificadora (AFIP, RENAPER, etc.)
3. Si olvidaste el PIN:
   - AFIP: regenerar clave fiscal en portal
   - RENAPER: presencial con DNI
   - Privados (E-CERT, Andreani): contacto soporte

### 7.3 "Token locked" (Bloqueado)

**Síntomas:**
```
TokenAuthenticationError: Token locked due to too many attempts
```

**Solución:**
1. Desbloqueo con **PUK (PIN Unlock Key)**:
   ```bash
   pkcs11-tool --module /usr/lib/libeToken.so --init-pin
   ```
2. Si no tienes PUK: contacta a tu certificadora
3. **Último recurso:** Reinicializar token (BORRA todo, requiere re-emisión)

### 7.4 "Certificate not found"

**Síntomas:**
```
CertificateNotFoundError: No signing certificate found
```

**Diagnóstico:**
```bash
# Listar certificados en token
certutil -d ~/.nss -L -h "SafeNet eToken"

# Verificar Key Usage
pkcs11-tool --module /usr/lib/libeToken.so --list-objects
```

**Solución:**
- El token no tiene certificados → contacta a tu certificadora
- Certificado sin "Digital Signature" → no es válido para firma
- Certificado vencido → renueva con tu CA

### 7.5 Errores de Permisos

**Síntomas:**
```
PermissionError: [Errno 13] Permission denied: '/usr/lib/libeToken.so'
```

**Solución:**
```bash
# Añadir usuario a grupo necesario
sudo usermod -a -G pcscd $USER
sudo usermod -a -G scard $USER

# Reiniciar sesión
logout
```

### 7.6 NSS Database Corrupta

**Síntomas:**
```
certutil: function failed: SEC_ERROR_BAD_DATABASE
```

**Solución:**
```bash
# Respaldar
mv ~/.nss ~/.nss.backup.$(date +%Y%m%d)

# Recrear desde cero (ver Sección 3.1)
mkdir ~/.nss
certutil -N -d ~/.nss --empty-password
modutil -dbdir ~/.nss -add "SafeNet eToken" -libfile /usr/lib/libeToken.so
```

### 7.7 Timestamp Server (TSA) No Responde

**Síntomas:**
```
TimeoutError: TSA server did not respond
```

**Solución:**
```bash
# Probar conectividad
curl -I http://time.certisign.com.br

# Cambiar TSA en config.toml
[timestamp]
tsa_url = "https://freetsa.org/tsr"  # TSA alternativo público
```

**TSAs públicos (Argentina/LATAM):**
- SafeSign Argentina: `http://tsa.safesign.com.ar:8318/tss`
- CertiSign Brasil: `http://time.certisign.com.br`
- FreeTSA (global): `https://freetsa.org/tsr`

### 7.8 LED del Token Parpadeando

**Significado:**
- **Parpadeando lento:** Esperando PIN
- **Parpadeando rápido:** Operación criptográfica en progreso
- **Apagado:** No conectado o sin energía
- **Encendido fijo:** Sesión autenticada activa

**Acción:** Espera hasta 30 segundos antes de desconectar.

---

## 8. FAQ (Preguntas Frecuentes)

### 8.1 General

**P: ¿Puedo usar el mismo token en Windows y Linux?**
R: Sí, los tokens SafeNet son multiplataforma. En Windows usa el cliente oficial SafeNet Authentication Client.

**P: ¿Cuántas firmas puedo hacer con un token?**
R: Ilimitadas. Los tokens no se "gastan", solo almacenan la clave privada.

**P: ¿El token necesita Internet para firmar?**
R: No para la firma básica. Sí para:
- Timestamp (TSA) → PAdES B-T
- Validación de revocación (OCSP/CRL) → PAdES B-LT
- DSS embedding → PAdES B-LT

**P: ¿Puedo tener múltiples certificados en un token?**
R: Sí, los tokens soportan múltiples pares de claves. PDFSigner detecta automáticamente cuáles pueden firmar.

### 8.2 Seguridad

**P: ¿Es seguro usar PDFSigner con mi certificado AFIP?**
R: Sí, PDFSigner:
- Nunca extrae la clave privada del token
- Cumple con Ley 25.506 (firma digital argentina)
- Soporta PAdES B-LT/LTA (estándares europeos eIDAS)
- Código abierto auditado

**P: ¿Qué pasa si pierdo el token?**
R: La clave privada se pierde. Debes:
1. Reportar inmediatamente a tu certificadora
2. Revocar el certificado (lista CRL)
3. Solicitar re-emisión con nuevo token

**P: ¿Puedo hacer backup del token?**
R: **NO.** Los tokens SafeNet no permiten exportar claves privadas (por diseño). Solo puedes:
- Tener múltiples tokens con el mismo certificado (solicitar a tu CA)
- Usar tokens con backup automático (SafeNet Luna HSM, no eToken)

### 8.3 Cumplimiento Argentina

**P: ¿PDFSigner cumple con Ley 25.506?**
R: Sí, cumple todos los requisitos:
- RSA ≥2048 bits
- SHA-256 o superior
- PKCS#11 para tokens hardware
- Timestamps RFC 3161
- PAdES B-LT/LTA (validación de largo plazo)

**P: ¿Qué certificadoras son válidas en Argentina?**
R: Licenciadas por ONTI:
- **Gobierno:** AFIP (contribuyentes), RENAPER (ciudadanos), FDR (firma remota)
- **Privadas:** Andreani, E-CERT, Izenpe, Certisign

Ver lista actualizada: https://www.argentina.gob.ar/onti/infraestructura-digital

**P: ¿Las firmas con PDFSigner tienen validez legal?**
R: Sí, si usas:
- Certificado de certificadora licenciada (AFIP, RENAPER, etc.)
- Token hardware (SafeNet, YubiKey, etc.)
- Nivel PAdES B-LT o superior

**P: ¿Necesito timestamp (TSA) obligatorio?**
R: La ley no lo exige explícitamente, pero es **altamente recomendado** para:
- Probar fecha exacta de firma
- Validación de largo plazo (más allá de vencimiento del certificado)
- Aceptación en trámites judiciales

### 8.4 Comparación con Otras Soluciones

**P: ¿PDFSigner vs Adobe Acrobat?**

| Feature | PDFSigner | Adobe Acrobat Pro |
|---------|-----------|-------------------|
| Precio | Gratis (open source) | USD 240/año |
| PAdES B-LT/LTA | ✅ Sí | ✅ Sí (DC only) |
| Linux nativo | ✅ Sí | ❌ No |
| Firma por lotes | ✅ Sí (CLI) | ⚠️ Limitado |
| Tokens PKCS#11 | ✅ Todos | ⚠️ Solo certificados |
| Cumplimiento Arg. | ✅ Ley 25.506 | ✅ Compatible |

**P: ¿PDFSigner vs firma remota (FDR)?**

| Aspecto | PDFSigner + Token | FDR (Firma Remota) |
|---------|-------------------|---------------------|
| Costo | Inicial alto (~USD 100) | Por firma (~USD 0.50-2) |
| Dependencia Internet | Solo TSA | Siempre |
| Control clave privada | Usuario | Proveedor |
| Velocidad | Instantáneo | 3-10 segundos |
| Privacidad | Total | Metadata enviado |

**Recomendación:** PDFSigner para usuarios con >100 firmas/año. FDR para uso esporádico.

### 8.5 Hardware

**P: ¿Dónde comprar tokens SafeNet en Argentina?**
R: Proveedores oficiales:
- **Andreani Certificados Digitales:** https://www.andreani.com/certificados-digitales
- **E-CERT Argentina:** Distribuidores autorizados
- **Mercado Libre:** Buscar "token SafeNet eToken 5110" (verificar vendedor)

Precio estimado: USD 80-150 (token + certificado 1 año)

**P: ¿SafeNet vs YubiKey?**
R: Ambos compatibles con PDFSigner:
- **SafeNet eToken 5110:** Certificado ONTI (Argentina), mejor soporte local
- **YubiKey 5:** No certificado ONTI, pero más versátil (FIDO2, TOTP, etc.)

Para firma en Argentina: preferir SafeNet (reconocimiento oficial).

**P: ¿Vida útil del token?**
R: SafeNet garantiza:
- **Hardware:** 5-10 años (sin partes móviles)
- **Certificado:** 1-3 años (renovable anualmente)

El token se reutiliza, solo renuevas el certificado.

---

## 9. Comandos de Referencia Rápida

```bash
# === VERIFICACIÓN INICIAL ===
lsusb | grep -i safenet                     # Detectar token USB
find /usr -name "*eToken*.so"               # Buscar librería PKCS#11

# === NSS DATABASE ===
mkdir -p ~/.nss
certutil -N -d ~/.nss --empty-password      # Crear database
modutil -dbdir ~/.nss -add "SafeNet eToken" -libfile /usr/lib/libeToken.so
modutil -dbdir ~/.nss -list                 # Listar módulos
certutil -d ~/.nss -L -h "SafeNet eToken"   # Listar certificados

# === PDFSIGNER ===
uv run pdfsigner list-tokens                # Detectar tokens
uv run pdfsigner sign documento.pdf         # Firmar PDF
uv run pdfsigner validate documento_firmado.pdf  # Validar firma
uv run pdfsigner batch-sign *.pdf           # Firma por lotes

# === DIAGNÓSTICO ===
pkcs11-tool --module /usr/lib/libeToken.so --list-slots   # Listar slots
pkcs11-tool --module /usr/lib/libeToken.so --list-objects # Ver objetos
pkcs11-tool --module /usr/lib/libeToken.so --test          # Test completo

# === EMERGENCIA ===
pkcs11-tool --module /usr/lib/libeToken.so --change-pin    # Cambiar PIN
pkcs11-tool --module /usr/lib/libeToken.so --init-pin      # Desbloquear con PUK
```

---

## 10. Recursos Adicionales

### Documentación Oficial

- **PDFSigner:** `/home/user/projects/pdfsigner/README.md`
- **Compliance Argentina:** `/home/user/projects/pdfsigner/NORMATIVA-ARG.md`
- **Configuración:** `/home/user/projects/pdfsigner/CLAUDE.md`

### SafeNet

- **Drivers Linux:** https://support.thalesgroup.com/ (requiere cuenta)
- **Manuales:** https://cpl.thalesgroup.com/access-management/authenticators/pki-usb-authentication
- **Soporte:** support@safenet-inc.com

### Regulaciones Argentina

- **Ley 25.506:** https://www.argentina.gob.ar/normativa/nacional/ley-25506-70749
- **ONTI:** https://www.argentina.gob.ar/onti
- **Certificadoras:** https://www.argentina.gob.ar/onti/infraestructura-digital
- **Estándares:** PAdES (ETSI TS 102 778), eIDAS (UE)

### Comunidad

- **Issues GitHub:** https://github.com/pdfsigner/pdfsigner/issues
- **Foro:** Sección "Tokens & Hardware"
- **Email soporte:** support@pdfsigner.org

---

## 11. Histórico de Cambios

| Versión | Fecha | Cambios |
|---------|-------|---------|
| 1.0 | 2026-02-01 | Versión inicial |

---

**Autor:** PDFSigner Development Team
**Mantenedor:** Security & Compliance Team
**Licencia:** MIT License
**Idioma:** Español (Argentina)

**Próxima revisión:** 2026-08-01

---

## Apéndice A: Tabla de Compatibilidad

| Token | ONTI Cert. | PKCS#11 Lib | Linux | macOS | Windows | Notas |
|-------|------------|-------------|-------|-------|---------|-------|
| SafeNet eToken 5110 | ✅ Sí | libeToken.so | ✅ | ✅ | ✅ | Más común en ARG |
| SafeNet eToken 5300 | ✅ Sí | libeToken.so | ✅ | ✅ | ✅ | USB-C |
| SafeNet eToken 5110+ FIPS | ✅ Sí | libeToken.so | ✅ | ✅ | ✅ | FIPS 140-2 Level 3 |
| SafeNet eToken PRO | ⚠️ Legacy | libeToken.so | ✅ | ✅ | ✅ | Discontinuado |
| YubiKey 5 (PIV) | ❌ No | libykcs11.so | ✅ | ✅ | ✅ | No certificado ONTI |
| Nitrokey Pro 2 | ❌ No | opensc-pkcs11.so | ✅ | ✅ | ⚠️ | OpenSC |
| OpenSC (genérico) | ❌ No | opensc-pkcs11.so | ✅ | ✅ | ✅ | Fallback universal |

---

## Apéndice B: Checklist de Despliegue

**Para administradores que configuran PDFSigner + SafeNet en múltiples estaciones:**

- [ ] Adquirir tokens SafeNet certificados ONTI
- [ ] Obtener certificados de CA licenciada (AFIP, RENAPER, etc.)
- [ ] Instalar drivers SafeNet en todas las estaciones
- [ ] Configurar NSS database (`~/.nss`)
- [ ] Importar certificados raíz de la CA
- [ ] Configurar TSA en `config.toml`
- [ ] Cambiar PIN predeterminado (1234 → seguro)
- [ ] Probar firma + validación en cada estación
- [ ] Documentar PIN/PUK en lugar seguro
- [ ] Capacitar usuarios (esta guía)
- [ ] Establecer procedimiento de backup de certificados raíz
- [ ] Definir política de renovación (anual)

**Tiempo estimado:** 2-4 horas para 10 estaciones

---

**Fin de la Guía**

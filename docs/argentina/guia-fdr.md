# Guía: Certificados Digitales en Argentina (RENAPER y FDR)

**Última actualización:** 2026-02-01

## Índice

1. [Introducción](#introducción)
2. [Requisitos Previos](#requisitos-previos)
3. [Opción 1: Certificado RENAPER (Token Físico)](#opción-1-certificado-renaper-token-físico)
4. [Opción 2: Firma Digital Remota (FDR)](#opción-2-firma-digital-remota-fdr)
5. [Comparación RENAPER vs FDR](#comparación-renaper-vs-fdr)
6. [Integración con PDFSigner](#integración-con-pdfsigner)
7. [Solución de Problemas](#solución-de-problemas)
8. [Preguntas Frecuentes (FAQ)](#preguntas-frecuentes-faq)
9. [Referencias](#referencias)

---

## Introducción

En Argentina existen dos opciones **gratuitas** para obtener certificados digitales con validez legal según la Ley 25.506:

| Opción | Organismo | Tecnología | Costo | Compatible PDFSigner |
|--------|-----------|------------|-------|----------------------|
| **RENAPER** | Ministerio del Interior | Token físico PKCS#11 | **Gratis** | ✅ **Sí** |
| **FDR** | Jefatura de Gabinete | Firma remota (HSM) | **Gratis** | ⚠️ Solo vía web |

**Recomendación:** Para uso con PDFSigner, utilice **RENAPER** con token físico.

---

## Requisitos Previos

### Para Ambas Opciones

✅ **DNI argentino** (Documento Nacional de Identidad)
✅ **Cuenta Mi Argentina** activa → https://www.argentina.gob.ar/miargentina
✅ **Correo electrónico** verificado
✅ **Teléfono móvil** con número argentino
✅ **Nivel de seguridad 2** en Mi Argentina (verificación biométrica)

### Verificación de Identidad

Para obtener **Nivel 2** en Mi Argentina:

1. Ingresar a https://mi.argentina.gob.ar/
2. Ir a **Perfil** → **Seguridad**
3. Seleccionar **Aumentar nivel de seguridad**
4. Opciones:
   - **Escanear DNI** con cámara (requiere DNI tarjeta con chip)
   - **Videollamada** con operador de RENAPER
   - **Presencial** en oficina RENAPER

---

## Opción 1: Certificado RENAPER (Token Físico)

### ¿Qué es RENAPER?

El **Registro Nacional de las Personas** emite certificados digitales almacenados en tokens USB criptográficos (SafeNet eToken, Feitian, etc.) certificados por ONTI (Oficina Nacional de Tecnologías de la Información).

### Paso 1: Solicitar Turno

1. Ingresar a https://www.argentina.gob.ar/interior/renaper
2. Ir a **Trámites** → **Certificado Digital**
3. Seleccionar **Solicitar turno para emisión de certificado**
4. Elegir oficina RENAPER más cercana
5. Confirmar turno por correo electrónico

**Tiempo de espera:** 7-15 días hábiles (varía según provincia)

### Paso 2: Comprar Token PKCS#11 (Opcional)

RENAPER **puede proveer** un token, pero suele haber demoras. Se recomienda comprar uno certificado:

| Token | Certificación | Precio Aprox. | Dónde Comprar |
|-------|---------------|---------------|---------------|
| **SafeNet eToken 5110** | ✅ ONTI | ARS 15.000-25.000 | MercadoLibre, casas de computación |
| **Feitian ePass2003** | ✅ ONTI | ARS 12.000-20.000 | Importadores oficiales |
| **Gemalto IDPrime** | ✅ ONTI | ARS 18.000-30.000 | Distribuidores Thales |

**Verificar certificación:** Consultar lista oficial ONTI → https://www.argentina.gob.ar/onti/dispositivos-certificados

### Paso 3: Asistir a Oficina RENAPER

**Documentos necesarios:**

- DNI original
- Turno impreso o en celular
- Token PKCS#11 (si lo compró previamente)

**Proceso en oficina (30-45 minutos):**

1. **Verificación de identidad:** Escaneo de DNI + foto + huella dactilar
2. **Firma de solicitud:** Declaración jurada física
3. **Generación de claves:** El operador genera el par de claves en el token
4. **Emisión de certificado:** Se emite certificado X.509 v3 con validez **3 años**
5. **Configuración de PIN:** Se establece PIN de 6-8 dígitos (¡NO olvidar!)

**Entrega:** Inmediata (se retira el token ese mismo día)

### Paso 4: Instalar Drivers en Linux

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install libnss3-tools pcscd libccid libpcsclite1

# Token SafeNet eToken
wget https://www.safenet.com/... # Descargar desde sitio oficial
sudo dpkg -i etoken-driver.deb

# Verificar detección
pcsc_scan
# Debe mostrar: "SafeNet eToken 5110" o similar

# Inicializar base de datos NSS
mkdir -p ~/.nss
certutil -N -d sql:$HOME/.nss
# Establecer contraseña maestra (opcional pero recomendado)

# Configurar PDFSigner
uv run pdfsigner-gui
# Ir a Preferencias → Token → NSS Database: ~/.nss
```

### Paso 5: Importar Certificado a NSS

```bash
# Listar certificados en token
certutil -L -d sql:$HOME/.nss -h all

# Si no aparece, importar manualmente
modutil -add "eToken" -libfile /usr/lib/libeToken.so -dbdir sql:$HOME/.nss

# Verificar importación
certutil -L -d sql:$HOME/.nss
# Debe aparecer: "Nombre Apellido - DNI XXXXXXXX"
```

---

## Opción 2: Firma Digital Remota (FDR)

### ¿Qué es FDR?

**Firma Digital Remota** es un servicio del gobierno argentino que permite firmar documentos sin token físico. Las claves privadas se almacenan en **HSM (Hardware Security Module)** en servidores seguros de la Jefatura de Gabinete.

### ⚠️ Limitación Importante

**FDR NO tiene API pública.** Solo se puede usar a través de su plataforma web oficial:

🌐 https://fdr.psi.gob.ar/

**Implicaciones:**
- ❌ No es compatible con PDFSigner directamente
- ❌ No se puede integrar mediante PKCS#11
- ✅ Solo se puede usar desde el navegador web
- ✅ Requiere autenticación con Mi Argentina cada vez

### Paso 1: Crear Cuenta FDR

1. Ingresar a https://fdr.psi.gob.ar/
2. Click en **Registrarse**
3. Iniciar sesión con **Mi Argentina** (Nivel 2 requerido)
4. Completar datos:
   - CUIL/CUIT
   - Dirección de correo (será certificado en el certificado)
   - Teléfono móvil
5. Aceptar **Términos y Condiciones** (Ley 25.506)
6. Confirmar correo electrónico (recibirá enlace de activación)

**Tiempo de activación:** Inmediato

### Paso 2: Configurar Segundo Factor (2FA)

FDR **requiere obligatoriamente** autenticación de dos factores:

**Opciones:**

1. **SMS:** Código enviado a celular (predeterminado)
2. **TOTP:** Google Authenticator, Authy, etc.
3. **Token físico:** FIDO2/U2F (YubiKey, Titan, etc.)

**Configuración recomendada:**

```
Preferencias → Seguridad → Autenticación de dos factores
- Activar TOTP (más seguro que SMS)
- Configurar códigos de respaldo (imprimir y guardar)
```

### Paso 3: Solicitar Certificado Digital

1. Ir a **Mis Certificados** → **Solicitar Nuevo Certificado**
2. Seleccionar tipo:
   - **Persona Física:** Para uso personal
   - **Persona Jurídica:** Representante legal de empresa (requiere constancia AFIP)
3. Completar datos del certificado:
   - Nombre común (CN): Nombre y Apellido
   - Organización (O): Opcional
   - Correo electrónico
4. Click en **Generar Certificado**
5. **Autenticar con 2FA** (SMS/TOTP)

**Generación:** Inmediata (el certificado se crea en el HSM remoto)

**Validez:** 3 años

### Paso 4: Firmar Documentos con FDR

**Proceso en plataforma web:**

1. Ingresar a https://fdr.psi.gob.ar/firmar
2. **Subir PDF:** Drag & drop o examinar
3. **Seleccionar certificado:** Elegir certificado activo
4. **Configurar firma:**
   - Posición: Visual / Invisible
   - Razón: Texto descriptivo
   - Ubicación: Ciudad/País
5. **Autenticar con 2FA:** Ingresar código SMS/TOTP
6. **Descargar PDF firmado:** Se descarga automáticamente

**Características de la firma:**

- ✅ PAdES B-LT (Long Term Validation)
- ✅ Timestamp automático (TSA de Jefatura de Gabinete)
- ✅ Certificados de cadena embebidos (DSS)
- ✅ Validez legal según Ley 25.506

### Limitaciones de FDR

| Característica | FDR | RENAPER + PDFSigner |
|----------------|-----|---------------------|
| Firma por lotes | ❌ Uno por uno | ✅ Automático |
| Firma offline | ❌ Requiere internet | ✅ Posible |
| Integración apps | ❌ Solo web | ✅ PKCS#11 |
| Personalización | ⚠️ Limitada | ✅ Total |
| Costo | ✅ Gratis | ✅ Gratis |

---

## Comparación RENAPER vs FDR

### Tabla Comparativa Completa

| Aspecto | RENAPER (Token) | FDR (Remoto) |
|---------|-----------------|--------------|
| **Costo inicial** | ARS 15.000-25.000 (token) | **Gratis** |
| **Tiempo de obtención** | 7-15 días (turno) | Inmediato |
| **Requiere hardware** | ✅ Token PKCS#11 | ❌ Solo navegador |
| **Compatible PDFSigner** | ✅ **100%** | ❌ No |
| **Firma offline** | ✅ Sí | ❌ Requiere internet |
| **Firma por lotes** | ✅ Ilimitadas | ❌ Individual |
| **Integración API** | ✅ PKCS#11 estándar | ❌ Sin API pública |
| **Portabilidad** | ✅ Cualquier PC con token | ⚠️ Solo plataforma web |
| **Seguridad clave privada** | 🔐 Token físico | 🔐 HSM gubernamental |
| **2FA obligatorio** | ❌ Solo PIN | ✅ SMS/TOTP |
| **Certificado exportable** | ❌ No (en token) | ❌ No (en HSM) |
| **Respaldo/recuperación** | ⚠️ Token de respaldo | ✅ Regenerable |
| **Validez legal** | ✅ Ley 25.506 | ✅ Ley 25.506 |
| **Nivel PAdES** | ✅ B-LT, B-LTA | ✅ B-LT |
| **Uso en múltiples PCs** | ⚠️ Llevar token | ✅ Desde cualquier navegador |

### Recomendaciones por Caso de Uso

#### Usar RENAPER si

✅ Necesita firmar **muchos documentos** regularmente
✅ Requiere **automatización** (scripts, APIs)
✅ Trabaja con aplicaciones de escritorio (**PDFSigner**)
✅ Necesita firmar **offline** (sin internet)
✅ Quiere **máxima portabilidad** (llevar token)

#### Usar FDR si

✅ Firma **ocasionalmente** (pocos documentos/mes)
✅ Prefiere no comprar hardware adicional
✅ Solo necesita firma **básica** desde navegador
✅ Necesita obtener certificado **rápidamente** (sin turno)
✅ Trabaja desde múltiples ubicaciones

---

## Integración con PDFSigner

### ✅ RENAPER (Soporte Completo)

**Configuración:**

```bash
# 1. Instalar PDFSigner
uv run pdfsigner-gui

# 2. Configurar token
Preferencias → Token
- NSS Database: ~/.nss (predeterminado)
- PKCS#11 Library: /usr/lib/libeToken.so (autodetectado)

# 3. Probar detección
Click en "Detectar Token"
# Debe mostrar: "SafeNet eToken 5110" + certificado

# 4. Firmar documento
Archivo → Abrir PDF → Seleccionar certificado → Firmar
```

**Características disponibles:**

- ✅ Firma individual y por lotes
- ✅ Firma visible con imagen/texto personalizado
- ✅ PAdES B-LT (DSS automático)
- ✅ PAdES B-LTA (archivo timestamps)
- ✅ Verificación de firmas existentes
- ✅ Firma con timestamp (TSA externo)
- ✅ Modo dry-run (simulación sin token)

**Ejemplo CLI:**

```bash
# Firmar un documento
uv run pdfsigner sign documento.pdf \
  --cert "CN=Juan Perez" \
  --tsa https://tsa.argentina.gob.ar/tsa \
  --ltv

# Verificar firma
uv run pdfsigner verify documento_signed.pdf
```

### ⚠️ FDR (Sin Integración Directa)

**Limitaciones técnicas:**

❌ FDR **no expone** API PKCS#11
❌ No hay biblioteca de cliente oficial
❌ No es posible integrar con aplicaciones de escritorio
❌ Solo accesible vía navegador web en https://fdr.psi.gob.ar/

**Workaround manual:**

Si tiene certificado FDR pero necesita usar PDFSigner:

1. **Firmar con FDR primero** (plataforma web)
2. **Descargar PDF firmado**
3. **Validar con PDFSigner** (opcional):

```bash
uv run pdfsigner verify documento_firmado_fdr.pdf
# Debe mostrar: "Firma válida - PAdES B-LT"
```

**NO es posible:**

❌ Usar certificado FDR en PDFSigner directamente
❌ Automatizar firmas FDR desde scripts
❌ Firma por lotes con FDR

### Integración Futura (Roadmap)

**Propuesta teórica** (requeriría colaboración gobierno):

1. **API REST FDR:** Jefatura de Gabinete podría publicar API pública
2. **Plugin PDFSigner:** Integración vía HTTP (similar a TSA)
3. **Flujo:**

```
PDFSigner → HTTP POST /fdr/sign → 2FA del usuario → PDF firmado
```

**Estado actual:** No planificado por el gobierno argentino

---

## Solución de Problemas

### RENAPER

#### Problema 1: Token no detectado

**Síntomas:**
```
Error: No PKCS#11 token detected
```

**Soluciones:**

```bash
# 1. Verificar servicio pcscd
sudo systemctl status pcscd
sudo systemctl start pcscd

# 2. Verificar detección física
lsusb | grep -i "token\|smart"
# Debe aparecer: "SafeNet Token JC"

# 3. Instalar drivers específicos
# SafeNet eToken
wget https://support.safenet.com/... # Consultar sitio oficial
sudo dpkg -i safenet-driver.deb

# 4. Verificar con pcsc_scan
pcsc_scan
# Esperar 5 segundos, debe detectar token

# 5. Reiniciar PDFSigner
uv run pdfsigner-gui
```

#### Problema 2: PIN bloqueado

**Síntomas:**
```
Error: CKR_PIN_LOCKED
```

**Solución:**

1. **Contactar RENAPER:** El PUK solo lo tiene RENAPER
2. **Solicitar desbloqueo:** Presencial en oficina RENAPER con DNI
3. **Alternativa:** Solicitar nuevo certificado (gratis)

**Prevención:**
- Anotar PIN en lugar seguro (no en PC)
- No compartir PIN
- Usar gestor de contraseñas para PIN

#### Problema 3: Certificado expirado

**Verificar expiración:**

```bash
certutil -L -d sql:$HOME/.nss -n "Nombre Apellido" | grep "Not After"
```

**Renovación:**

1. Solicitar nuevo turno RENAPER (3 meses antes de expirar)
2. Llevar DNI + token
3. Se genera nuevo certificado (3 años más)
4. Certificado anterior queda revocado

#### Problema 4: NSS database corrupta

**Síntomas:**
```
Error: SEC_ERROR_BAD_DATABASE
```

**Solución:**

```bash
# Backup
cp -r ~/.nss ~/.nss.backup

# Recrear database
rm -rf ~/.nss
mkdir ~/.nss
certutil -N -d sql:$HOME/.nss

# Reimportar token
modutil -add "eToken" -libfile /usr/lib/libeToken.so -dbdir sql:$HOME/.nss

# Verificar
certutil -L -d sql:$HOME/.nss -h all
```

### FDR

#### Problema 1: Error al subir PDF

**Síntomas:**
```
"El archivo excede el tamaño máximo permitido"
```

**Solución:**

- **Límite FDR:** 10 MB por archivo
- **Comprimir PDF:**

```bash
gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dPDFSETTINGS=/ebook \
   -dNOPAUSE -dQUIET -dBATCH -sOutputFile=output.pdf input.pdf
```

#### Problema 2: 2FA no funciona

**Síntomas:**
```
"Código de verificación inválido"
```

**Soluciones:**

1. **SMS no llega:**
   - Esperar 2-3 minutos
   - Verificar cobertura móvil
   - Solicitar reenvío (máximo 3 veces)

2. **TOTP incorrecto:**
   - Verificar hora del sistema: `timedatectl status`
   - Sincronizar reloj: `sudo timedatectl set-ntp true`
   - Regenerar código en app

3. **Usar códigos de respaldo:**
   - Ir a Preferencias → Seguridad → Códigos de respaldo
   - Usar uno de los 10 códigos de un solo uso

#### Problema 3: Sesión expirada

**Síntomas:**
```
"Su sesión ha expirado. Por favor, inicie sesión nuevamente."
```

**Causa:** Inactividad > 15 minutos

**Solución:**
- Firmar dentro de los 15 minutos de autenticación
- Si está preparando documento, mantener ventana FDR abierta

---

## Preguntas Frecuentes (FAQ)

### General

**¿Cuál es la diferencia legal entre RENAPER y FDR?**

Ninguna. Ambos emiten certificados con **validez legal equivalente** según Ley 25.506. La diferencia es técnica (token físico vs HSM remoto).

**¿Puedo tener ambos certificados (RENAPER + FDR)?**

✅ Sí. Puede obtener ambos sin conflicto. Cada uno tiene su número de serie único.

**¿Los certificados expiran?**

✅ Sí, después de **3 años**. Debe renovarlos antes de la expiración para mantener validez legal.

**¿Las firmas hechas antes de expirar siguen siendo válidas?**

✅ Sí, si tienen **timestamp** (sello de tiempo). PDFSigner lo agrega automáticamente con `-tsa`.

### RENAPER

**¿El token se puede usar en Windows y macOS?**

✅ Sí. Los tokens PKCS#11 son multiplataforma. Debe instalar drivers específicos del fabricante.

**¿Puedo sacar backup del certificado?**

❌ No. El certificado está **no exportable** por seguridad. Recomendado: comprar token de respaldo.

**¿Qué pasa si pierdo el token?**

1. **Reportar a RENAPER** inmediatamente (revocar certificado)
2. Solicitar nuevo turno para emisión de nuevo certificado
3. El certificado anterior queda **revocado** (no válido)

**¿Puedo usar el mismo token en múltiples PCs?**

✅ Sí. El token es portátil. Solo debe instalar drivers en cada PC.

### FDR

**¿Puedo exportar mi certificado FDR?**

❌ No. El certificado **nunca sale del HSM** del gobierno. Es la garantía de seguridad.

**¿FDR funcionará en el futuro con PDFSigner?**

Solo si Jefatura de Gabinete publica una **API pública**. Actualmente no está en sus planes.

**¿FDR funciona en móviles?**

✅ Sí, desde navegador móvil (Chrome/Safari). La experiencia de usuario es limitada.

**¿Puedo firmar documentos de terceros con FDR?**

✅ Sí, siempre que tenga autorización legal. El certificado certifica su identidad, no propiedad del documento.

### PDFSigner

**¿PDFSigner es compatible con certificados de AFIP?**

⚠️ **Parcialmente.** Los certificados fiscales de AFIP (Clave Fiscal) no son tokens PKCS#11, pero si exporta el certificado `.p12` puede importarlo a NSS:

```bash
pk12util -i certificado_afip.p12 -d sql:$HOME/.nss
```

**Limitación:** Certificados AFIP tienen restricciones de uso (solo trámites fiscales).

**¿Puedo firmar con múltiples certificados (RENAPER + privado)?**

✅ Sí. PDFSigner permite seleccionar entre todos los certificados disponibles en NSS.

**¿PDFSigner soporta eIDAS (Europa)?**

✅ Sí. PDFSigner valida certificados **eIDAS** (EU Qualified Electronic Signatures) y argentinos simultáneamente.

**¿Las firmas con PDFSigner son válidas en Europa?**

⚠️ **Depende.** Si el certificado RENAPER está en la **lista de confianza eIDAS** (actualmente no lo está), sería válido. Para documentos internacionales, recomendado usar certificadores privados con reconocimiento eIDAS (Andreani, E-CERT).

---

## Referencias

### Sitios Oficiales

- **RENAPER:** https://www.argentina.gob.ar/interior/renaper
- **FDR:** https://fdr.psi.gob.ar/
- **Mi Argentina:** https://mi.argentina.gob.ar/
- **ONTI (Oficina Nacional TI):** https://www.argentina.gob.ar/onti
- **Jefatura de Gabinete:** https://www.argentina.gob.ar/jefatura

### Normativa

- **Ley 25.506:** Firma Digital (infraestructura PKI)
- **Decreto 2628/2002:** Reglamentación Ley 25.506
- **Resolución ONTI 4/2020:** Estándares técnicos
- **Disposición DNPDP 10/2008:** Protección datos personales

### Documentación Técnica

- **RFC 3161:** Time-Stamp Protocol (TSP)
- **RFC 5280:** X.509 Public Key Infrastructure
- **ETSI EN 319 142-1:** PAdES (PDF Advanced Electronic Signatures)
- **ISO 32000-2:2020:** PDF 2.0 specification

### Soporte

- **RENAPER:** soporte@renaper.gob.ar | 0800-333-3364
- **FDR:** soporte.fdr@jefatura.gob.ar | 0800-222-2348
- **PDFSigner:** https://github.com/vdirienzo/pdfsigner/issues

---

## Notas de Actualización

**2026-02-01:**
- Creación del documento
- Información actualizada con precios 2026
- Verificación de URLs oficiales
- Validación de proceso RENAPER (turno online)
- Confirmación de limitación FDR (sin API pública)

**Mantenimiento:**
- Revisar precios tokens cada 6 meses
- Verificar URLs oficiales trimestralmente
- Actualizar limitaciones FDR si publican API
- Validar drivers PKCS#11 con cada release PDFSigner

---

**⚠️ IMPORTANTE:**

Esta guía es informativa y se basa en información pública disponible en 2026. Los procesos gubernamentales pueden cambiar sin previo aviso. Siempre consulte los sitios oficiales para información actualizada.

**Para soporte técnico de PDFSigner con tokens RENAPER:**
```bash
uv run pdfsigner --help
uv run pdfsigner verify --verbose documento.pdf
```

**Contribuciones:**

Si encuentra información desactualizada, por favor abra un issue en:
https://github.com/vdirienzo/pdfsigner/issues

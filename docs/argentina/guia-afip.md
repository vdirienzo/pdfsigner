# Guía: Certificados Digitales AFIP

Guía completa para obtener y configurar certificados digitales de AFIP (Administración Federal de Ingresos Públicos) para uso con PDFSigner bajo la Ley 25.506.

## Información General

**Organismo:** AFIP - Administración Federal de Ingresos Públicos
**Website:** https://www.afip.gob.ar/cl_fiscal/
**Costo:** Gratuito (solo para contribuyentes con CUIT activo)
**Modalidades:** Token físico o Software (certificado de computadora)
**Validez:** Cumple con Ley 25.506 (firma digital argentina)
**Vigencia:** 2-3 años según modalidad

## 1. Requisitos Previos

### 1.1 Requisitos Obligatorios

- **CUIT activo** (Clave Única de Identificación Tributaria)
- **Clave Fiscal nivel 3 o superior** (con seguridad reforzada)
- **Correo electrónico registrado en AFIP**
- **Número de teléfono celular** (para validación SMS)
- **DNI** (documento de identidad argentino)

### 1.2 Verificar Nivel de Clave Fiscal

1. Ingresar a https://auth.afip.gob.ar/contribuyente_/login.xhtml
2. Iniciar sesión con CUIT y Clave Fiscal
3. Ir a "Administrador de Relaciones de Clave Fiscal"
4. Verificar que el nivel sea **3 o superior**

**Si tienes nivel 1 o 2:**
1. Ve a "Clave Fiscal" > "Aumentar Nivel de Seguridad"
2. Sigue los pasos de verificación (puede requerir validación presencial o digital)

### 1.3 Verificar Habilitación

Verifica que tu CUIT esté habilitado para solicitar certificados digitales:

1. Ingresa a https://www.afip.gob.ar/cl_fiscal/
2. Ve a "Administración de Certificados Digitales"
3. Revisa que tu perfil permita la solicitud

## 2. Solicitar Certificado Digital AFIP

### 2.1 Elegir Modalidad

AFIP ofrece dos modalidades:

| Modalidad | Descripción | Recomendado para |
|-----------|-------------|------------------|
| **Certificado de Computadora** | Software instalado en la PC | Uso personal/ocasional |
| **Token Físico** | Dispositivo USB criptográfico | Uso profesional/frecuente |

**Recomendación:** Token físico para PDFSigner (mayor seguridad y portabilidad).

### 2.2 Pasos para Solicitar Certificado

#### Opción A: Certificado de Computadora (Software)

1. **Acceder al Portal AFIP**
   ```
   https://www.afip.gob.ar/cl_fiscal/
   ```

2. **Iniciar Sesión**
   - Ingresar con CUIT y Clave Fiscal nivel 3+

3. **Solicitar Certificado**
   - Ir a "Administración de Certificados Digitales"
   - Seleccionar "Solicitar Certificado"
   - Elegir "Certificado de Computadora"

4. **Generar Par de Claves**
   - El navegador generará un par de claves RSA (2048 bits mínimo)
   - **IMPORTANTE:** No cerrar el navegador durante este proceso
   - El certificado se instalará automáticamente en el almacén del sistema

5. **Descargar Certificado**
   - Una vez aprobado, descargar el archivo `.p12` o `.pfx`
   - Establecer una **contraseña fuerte** para proteger el archivo
   - Guardar el archivo en lugar seguro

6. **Verificar Instalación**
   - Linux: Importar a NSS con `pk12util`
   - Windows: Importar al almacén de certificados
   - macOS: Importar a Keychain Access

#### Opción B: Token Físico (Recomendado)

1. **Adquirir Token Homologado**
   - SafeNet eToken (certificado ONTI)
   - Gemalto/Thales
   - Comprar en proveedor autorizado AFIP

2. **Instalar Drivers del Token**

   **Linux:**
   ```bash
   # SafeNet eToken
   sudo apt install opensc opensc-pkcs11
   # o instalar drivers del fabricante
   ```

   **Windows:**
   ```
   Descargar desde el sitio del fabricante del token
   ```

3. **Solicitar Certificado en AFIP**
   - Conectar token USB
   - Acceder a https://www.afip.gob.ar/cl_fiscal/
   - Ir a "Administración de Certificados Digitales"
   - Seleccionar "Solicitar Certificado"
   - Elegir "Token Físico"
   - Seleccionar el dispositivo detectado

4. **Generar Claves en Token**
   - Las claves RSA se generan **dentro del token** (no se exportan)
   - Establecer PIN del token (6-8 dígitos)
   - Esperar aprobación de AFIP (inmediato o hasta 24hs)

5. **Verificar Certificado**
   - Usar herramienta del fabricante para listar certificados
   - O verificar con PDFSigner (ver sección 4)

### 2.3 Aprobación y Activación

- **Tiempo de aprobación:** Inmediato a 24 horas hábiles
- **Notificación:** Email registrado en AFIP
- **Vigencia:** 2-3 años (verificar en el certificado)
- **Renovación:** Solicitar nuevo certificado antes del vencimiento

## 3. Configuración del Token/Software

### 3.1 Configurar NSS Database (Linux)

PDFSigner usa NSS (Network Security Services) para PKCS#11.

1. **Crear NSS Database**
   ```bash
   mkdir -p ~/.nss
   certutil -N -d sql:~/.nss
   # Establecer contraseña maestra cuando se solicite
   ```

2. **Importar Certificado de Software (.p12)**
   ```bash
   pk12util -i certificado_afip.p12 -d sql:~/.nss
   # Ingresar contraseña del archivo .p12
   # Ingresar contraseña de NSS database
   ```

3. **Verificar Importación**
   ```bash
   certutil -L -d sql:~/.nss
   # Debería listar tu certificado AFIP
   ```

4. **Verificar Clave Privada**
   ```bash
   certutil -K -d sql:~/.nss
   # Debería mostrar la clave privada asociada
   ```

### 3.2 Configurar Token Físico

1. **Detectar Token**
   ```bash
   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -L
   # o para SafeNet eToken:
   pkcs11-tool --module /usr/lib/libeToken.so -L
   ```

2. **Listar Certificados en Token**
   ```bash
   pkcs11-tool --module /usr/lib/libeToken.so -O
   ```

3. **Configurar Biblioteca PKCS#11 en PDFSigner**

   Editar `~/.config/pdfsigner/config.toml`:
   ```toml
   # Para SafeNet eToken
   pkcs11_library = "/usr/lib/libeToken.so"

   # Para OpenSC genérico
   pkcs11_library = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
   ```

### 3.3 Instalar Certificados Raíz AFIP

Para validación de cadena de certificados:

1. **Descargar Certificados Raíz AFIP**
   ```
   https://www.afip.gob.ar/genericos/certificados/
   ```

2. **Importar a NSS**
   ```bash
   certutil -A -n "AFIP Root CA" -t "C,C,C" -i afip_root.crt -d sql:~/.nss
   certutil -A -n "AFIP Sub CA" -t "C,C,C" -i afip_sub.crt -d sql:~/.nss
   ```

## 4. Uso con PDFSigner

### 4.1 Configuración Inicial

1. **Configurar PDFSigner**

   Editar `~/.config/pdfsigner/config.toml`:
   ```toml
   # Ruta a NSS database
   nss_db_path = "~/.nss"

   # Servidor de sellado de tiempo (TSA)
   tsa_url = "http://tsa.afip.gob.ar/tsa/"

   # Habilitar LTV (PAdES B-LT)
   ltv_enabled = true
   ltv_fail_open = true

   # Habilitar archivo de timestamps (PAdES B-LTA)
   archive_ts_enabled = true
   archive_ts_auto = false

   # Verificación de revocación
   revocation_check_enabled = true
   ```

2. **Verificar Configuración**
   ```bash
   uv run pdfsigner config show
   ```

### 4.2 Firmar PDF con Certificado AFIP

#### Interfaz Gráfica (GUI)

1. **Iniciar PDFSigner**
   ```bash
   uv run pdfsigner-gui
   ```

2. **Seleccionar PDF**
   - Arrastrar archivo o usar botón "Abrir"

3. **Seleccionar Certificado AFIP**
   - Se listará automáticamente desde NSS/token
   - Verificar emisor: "AFIP"

4. **Configurar Firma**
   - Posición: Visual o invisible
   - Motivo: "Ley 25.506 - República Argentina"
   - Ubicación: "Argentina"

5. **Ingresar PIN**
   - Token físico: PIN del dispositivo (6-8 dígitos)
   - Software: Contraseña de NSS database

6. **Firmar**
   - Click "Firmar" y esperar procesamiento

#### Línea de Comandos (CLI)

```bash
# Firma simple
uv run pdfsigner sign documento.pdf --cert "CN=Tu Nombre (AFIP)"

# Firma con timestamp AFIP
uv run pdfsigner sign documento.pdf \
  --cert "CN=Tu Nombre (AFIP)" \
  --tsa-url "http://tsa.afip.gob.ar/tsa/"

# Firma con LTV (PAdES B-LT)
uv run pdfsigner sign documento.pdf \
  --cert "CN=Tu Nombre (AFIP)" \
  --ltv

# Firma con archivo timestamp (PAdES B-LTA)
uv run pdfsigner sign documento.pdf \
  --cert "CN=Tu Nombre (AFIP)" \
  --ltv \
  --archive-ts
```

### 4.3 Validar Firma AFIP

```bash
# Validar firma
uv run pdfsigner validate documento_signed.pdf

# Validar con salida detallada
uv run pdfsigner validate documento_signed.pdf --verbose
```

**Salida esperada:**
```
Signature #1:
  Signer: CN=Tu Nombre, OU=AFIP, O=AFIP, C=AR
  Status: VALID
  PAdES Level: B-LT (Long Term Validation)
  Timestamp: 2026-02-01 10:30:45 UTC (TSA: AFIP)
  OCSP: Valid (no revocation)
```

### 4.4 API REST

```bash
# Iniciar servidor API
uv run pdfsigner-api

# Firmar vía API
curl -X POST "http://localhost:8000/api/v1/sign/" \
  -H "Authorization: Bearer <token>" \
  -F "file=@documento.pdf" \
  -F "certificate_cn=Tu Nombre (AFIP)" \
  -F "reason=Ley 25.506" \
  -F "location=Argentina"
```

## 5. Solución de Problemas Comunes

### 5.1 Error: "No se detecta el certificado"

**Causa:** NSS database no configurada o certificado no importado.

**Solución:**
```bash
# Verificar NSS database
certutil -L -d sql:~/.nss

# Si está vacía, importar certificado
pk12util -i certificado_afip.p12 -d sql:~/.nss
```

### 5.2 Error: "PIN incorrecto"

**Causa:** PIN del token o contraseña NSS incorrecta.

**Solución:**
- Token físico: Verificar PIN del dispositivo (verificar con fabricante)
- Software: Verificar contraseña de NSS database
- Después de 3 intentos fallidos, el token puede bloquearse (requiere PUK)

### 5.3 Error: "Token no detectado"

**Causa:** Drivers no instalados o biblioteca PKCS#11 incorrecta.

**Solución:**
```bash
# Verificar dispositivo USB
lsusb | grep -i token

# Instalar drivers OpenSC
sudo apt install opensc opensc-pkcs11

# Probar detección
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -L
```

### 5.4 Error: "TSA AFIP no responde"

**Causa:** Servidor de sellado de tiempo AFIP puede estar caído o cambió URL.

**Solución:**
1. Verificar conectividad:
   ```bash
   curl -I http://tsa.afip.gob.ar/tsa/
   ```

2. Probar URL alternativa (verificar en AFIP):
   ```toml
   tsa_url = "http://timestamp.afip.gob.ar/tsa/"
   ```

3. Como fallback, usar TSA público:
   ```toml
   tsa_url = "http://timestamp.digicert.com"
   ```

### 5.5 Error: "Certificado expirado"

**Causa:** El certificado AFIP venció (vigencia 2-3 años).

**Solución:**
1. Verificar vigencia:
   ```bash
   certutil -L -d sql:~/.nss -n "Tu Certificado AFIP"
   ```

2. Solicitar renovación en AFIP (antes del vencimiento):
   - Acceder a https://www.afip.gob.ar/cl_fiscal/
   - Ir a "Administración de Certificados Digitales"
   - Renovar certificado existente

### 5.6 Error: "Revocación no verificable"

**Causa:** OCSP/CRL de AFIP no accesible.

**Solución temporal:**
```toml
# Desactivar verificación de revocación
revocation_check_enabled = false
```

**Nota:** Esto no afecta la validez legal pero reduce seguridad.

### 5.7 Error: "Biblioteca PKCS#11 no encontrada"

**Causa:** Ruta incorrecta a biblioteca del token.

**Solución:**
```bash
# Buscar biblioteca
find /usr -name "*pkcs11*.so" 2>/dev/null

# Actualizar config.toml con ruta correcta
# Para SafeNet eToken:
pkcs11_library = "/usr/lib/libeToken.so"

# Para OpenSC:
pkcs11_library = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
```

## 6. FAQ (Preguntas Frecuentes)

### 6.1 ¿Es válido legalmente un PDF firmado con certificado AFIP?

**Sí.** Los certificados AFIP cumplen con la Ley 25.506 de Firma Digital argentina y tienen validez legal equivalente a firma manuscrita para todos los actos públicos y privados.

### 6.2 ¿Puedo usar el certificado AFIP fuera de Argentina?

**Sí**, pero con limitaciones. El certificado es válido internacionalmente bajo estándares X.509, pero:
- Para UE: No es QES (Qualified Electronic Signature) según eIDAS
- Para USA: No es reconocido automáticamente (requiere acuerdos bilaterales)
- Para MERCOSUR: Mayor reconocimiento por acuerdos regionales

### 6.3 ¿Cuánto tiempo tarda la aprobación del certificado?

- **Certificado de computadora:** Inmediato a 2 horas
- **Token físico:** Hasta 24 horas hábiles
- En casos excepcionales, puede requerir validación presencial

### 6.4 ¿Puedo tener múltiples certificados AFIP?

**Sí.** Puedes tener:
- Un certificado por modalidad (computadora + token)
- Certificados para diferentes CUIT (si representas varias empresas)
- Certificados renovados (el anterior sigue válido hasta su vencimiento)

### 6.5 ¿Qué pasa si pierdo mi token físico?

1. **Revocar certificado inmediatamente:**
   - Acceder a https://www.afip.gob.ar/cl_fiscal/
   - Ir a "Administración de Certificados Digitales"
   - Seleccionar "Revocar Certificado"
   - Indicar motivo: "Pérdida de token"

2. **Solicitar nuevo certificado:**
   - Adquirir nuevo token
   - Solicitar certificado nuevamente (mismo proceso)

3. **Firmas previas:** Siguen siendo válidas si no fueron revocadas antes de la firma.

### 6.6 ¿Puedo usar PDFSigner sin conexión a internet?

**Parcialmente:**
- **Firmar:** Sí, no requiere internet
- **Timestamp (TSA):** No, requiere conexión a servidor AFIP
- **LTV (OCSP/CRL):** No, requiere conexión para verificar revocación
- **Validar:** Sí, si el PDF ya tiene LTV embebido

**Modo offline:**
```bash
# Firmar sin timestamp ni LTV
uv run pdfsigner sign documento.pdf \
  --cert "CN=Tu Nombre (AFIP)" \
  --no-tsa \
  --no-ltv
```

### 6.7 ¿Cuántas firmas puedo hacer con un certificado AFIP?

**Ilimitadas** durante la vigencia del certificado (2-3 años). No hay restricción de cantidad por parte de AFIP.

### 6.8 ¿Qué diferencia hay entre PAdES B, B-LT y B-LTA?

| Nivel | Descripción | Validez a largo plazo |
|-------|-------------|----------------------|
| **PAdES B** | Firma básica con timestamp | No (depende de vigencia del cert) |
| **PAdES B-LT** | + Información de validación (OCSP/CRL) | Sí (hasta expiración de OCSP) |
| **PAdES B-LTA** | + Archivo timestamps periódicos | Sí (indefinidamente) |

**Recomendación para documentos legales:** PAdES B-LTA

### 6.9 ¿Puedo firmar PDFs protegidos con contraseña?

**Sí**, pero:
1. Desencriptar primero:
   ```bash
   uv run pdfsigner decrypt documento_protegido.pdf
   ```

2. Firmar el PDF desencriptado:
   ```bash
   uv run pdfsigner sign documento.pdf
   ```

3. Opcionalmente, re-encriptar:
   ```bash
   uv run pdfsigner encrypt documento_signed.pdf
   ```

### 6.10 ¿Dónde encuentro más información sobre AFIP certificados?

**Recursos oficiales:**
- Portal AFIP: https://www.afip.gob.ar/cl_fiscal/
- Guía oficial: https://www.afip.gob.ar/genericos/guiasPasoPaso/
- Soporte técnico: Agencia AFIP más cercana o call center 0810-999-2347
- Normativa: Ley 25.506 - https://www.argentina.gob.ar/normativa/nacional/ley-25506-70749

**Documentación PDFSigner:**
- Normativa Argentina: `docs/argentina/NORMATIVA-ARG.md` (en raíz del proyecto)
- Security: `docs/SECURITY.md`
- Audit Trail: `docs/audit_trail.md`

## 7. Referencias

### 7.1 Normativa

- **Ley 25.506:** Ley de Firma Digital (2001)
- **Decreto 2628/2002:** Reglamentación de Ley 25.506
- **Resolución ONTI 1/2020:** Estándares técnicos para certificadores

### 7.2 Estándares Técnicos

- **RSA:** Mínimo 2048 bits (recomendado 4096)
- **Hash:** SHA-256, SHA-384, SHA-512 (no SHA-1)
- **Formato:** X.509 v3
- **Protocolo timestamp:** RFC 3161
- **PAdES:** ETSI EN 319 142 (ISO 32000-2)

### 7.3 Contacto AFIP

- **Website:** https://www.afip.gob.ar
- **Call Center:** 0810-999-2347 (opción 1 para Clave Fiscal)
- **Email:** certificados@afip.gob.ar
- **Agencias:** https://www.afip.gob.ar/genericos/agencias/

---

**Última actualización:** 2026-02-01
**Versión PDFSigner:** 11.0.0
**Autor:** PDFSigner Team

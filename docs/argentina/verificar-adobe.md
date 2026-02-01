# Verificación de Firmas Digitales Argentinas en Adobe Reader/Acrobat

Guía completa para verificar firmas digitales creadas según la Ley 25.506 de Firma Digital Argentina utilizando Adobe Reader DC o Adobe Acrobat.

---

## 1. Requisitos

### Software Necesario

| Versión | Recomendación | Descarga |
|---------|---------------|----------|
| **Adobe Acrobat Reader DC** | Recomendado (gratuito) | https://get.adobe.com/reader/ |
| **Adobe Acrobat Pro DC** | Opcional (de pago) | https://www.adobe.com/acrobat.html |

**Versión mínima:** Adobe Reader DC 2015 o superior (versiones anteriores pueden no soportar PAdES B-LT/LTA)

**Sistema Operativo:**
- Windows 10/11
- macOS 10.15 o superior
- Linux (mediante Wine, funcionalidad limitada)

### Requisitos Técnicos

- Conexión a Internet (para validación OCSP/CRL y descarga de certificados)
- Permisos de administrador (para importar certificados raíz en el sistema)
- Espacio en disco: ~500 MB (instalación de Adobe Reader DC)

---

## 2. Importar Certificados Raíz Argentinos

Adobe Reader/Acrobat necesita confiar en las Autoridades Certificantes (CAs) argentinas para validar firmas digitales. Este proceso se realiza **una sola vez**.

### 2.1. Descargar Certificados Raíz

Descargue los certificados raíz desde los sitios oficiales:

#### Entidades Gubernamentales

| CA | Tipo | URL Oficial | Formato |
|----|------|-------------|---------|
| **AC AFIP** | Gobierno | https://www.afip.gob.ar/certificates/ | `.crt` o `.cer` |
| **AC RENAPER** | Gobierno | https://www.argentina.gob.ar/interior/renaper/certificados | `.crt` |
| **AC FDR** | Gobierno (remoto) | https://www.argentina.gob.ar/jefatura/innovacion/fdr | `.cer` |

#### Entidades Privadas Licenciadas

| CA | Tipo | URL Oficial | Formato |
|----|------|-------------|---------|
| **Andreani** | Privada | https://www.andreani.com/certificados | `.cer` |
| **E-CERT** | Privada | https://www.ecert.com.ar/descargas | `.crt` |
| **Certant** | Privada | https://www.certant.com.ar/ca-root | `.cer` |

**Nota:** Guarde todos los certificados en una carpeta, por ejemplo `C:\Certificados\Argentina\` o `~/Certificados/Argentina/`

### 2.2. Importar en Adobe Reader/Acrobat (Windows)

**Captura sugerida 1:** _Panel de preferencias de Adobe con menú Firmas abierto_

1. Abra Adobe Reader/Acrobat
2. Vaya a **Edición → Preferencias** (o `Ctrl + K`)
3. En el panel izquierdo, seleccione **Firmas**
4. Haga clic en **Más...** en la sección "Identidades y Certificados de Confianza"
5. Seleccione **Certificados de Confianza** en el panel izquierdo
6. Haga clic en **Importar**
7. Navegue hasta la carpeta con certificados argentinos
8. Seleccione el archivo `.crt` o `.cer` (por ejemplo: `AC_AFIP_ROOT.cer`)
9. Haga clic en **Abrir**

**Captura sugerida 2:** _Diálogo "Configurar Confianza del Certificado" con opciones marcadas_

10. En el diálogo "Configurar Confianza del Certificado":
    - ✅ Marque **"Usar este certificado como raíz de confianza"**
    - ✅ Marque **"Firmas de Documentos"**
    - ✅ Marque **"Identidad Certificada"**
    - ⚠️ Opcional: **"Conexiones web de aplicaciones"** (para OCSP/CRL)
11. Haga clic en **Aceptar**
12. Confirme el diálogo de advertencia haciendo clic en **Aceptar**

**Repita el proceso** para todos los certificados raíz argentinos (AFIP, RENAPER, FDR, etc.)

### 2.3. Importar en Adobe Reader/Acrobat (macOS)

1. Abra Adobe Reader/Acrobat
2. Vaya a **Acrobat Reader → Preferencias** (o `Cmd + ,`)
3. Seleccione **Firmas** en el panel izquierdo
4. Haga clic en **Más...** → **Certificados de Confianza**
5. Haga clic en **Importar** (icono de carpeta con flecha)
6. Seleccione el archivo `.crt` o `.cer`
7. Configure la confianza (igual que Windows, paso 10)
8. Repita para todos los certificados

### 2.4. Verificar Importación Exitosa

**Captura sugerida 3:** _Lista de certificados de confianza mostrando AC AFIP, RENAPER, FDR_

1. Vaya a **Edición → Preferencias → Firmas → Más...**
2. Seleccione **Certificados de Confianza**
3. Verifique que aparezcan los certificados importados:
   - AC AFIP (emisor: AC AFIP)
   - AC RENAPER (emisor: RENAPER)
   - AC FDR (emisor: Jefatura de Gabinete de Ministros)
   - Certificados privados (Andreani, E-CERT, etc.)

**Indicador visual:** Los certificados de confianza deben mostrar un icono de **candado verde** o **marca de verificación azul**

---

## 3. Configurar Confianza en CAs Argentinas

### 3.1. Configuración de Verificación de Firmas

**Captura sugerida 4:** _Panel de Verificación de Firmas con opciones configuradas_

1. Vaya a **Edición → Preferencias → Firmas**
2. En "Verificación", haga clic en **Más...**
3. Configure las siguientes opciones:

#### Pestaña "Verificación"

| Opción | Configuración | Descripción |
|--------|---------------|-------------|
| **Verificar firmas al abrir el documento** | ✅ Activado | Valida automáticamente al abrir |
| **Verificar marcas de tiempo del documento** | ✅ Activado | Valida timestamps (PAdES B-LTA) |
| **Usar información de revocación integrada** | ✅ Activado | Usa OCSP/CRL embedded (PAdES B-LT) |
| **Consultar servidores OCSP** | ✅ Activado | Valida estado de certificados en línea |
| **Consultar listas CRL** | ⚠️ Opcional | Puede ralentizar la verificación |

#### Pestaña "Opciones Avanzadas"

| Opción | Configuración | Descripción |
|--------|---------------|-------------|
| **Requerir información de revocación al validar** | ❌ Desactivado | Permite validación offline con DSS |
| **Modo FIPS 140-2** | ⚠️ Opcional | Solo si su organización lo requiere |
| **Verificar la integridad del documento** | ✅ Activado | Detecta modificaciones |

4. Haga clic en **Aceptar** para guardar

### 3.2. Configuración de Timestamp Authorities (TSA)

Para validar PAdES B-LTA con archive timestamps:

1. En **Preferencias → Firmas → Más... → Verificación**
2. Sección "Servidores de Hora"
3. Agregue las TSA argentinas de confianza:

| TSA | URL | Certificador |
|-----|-----|--------------|
| **TSA AFIP** | `http://tsa.afip.gob.ar/tsa` | AFIP |
| **TSA Certant** | `http://tsa.certant.com.ar` | Certant |
| **TSA E-CERT** | `http://timestamp.ecert.com.ar` | E-CERT |

**Nota:** Adobe Reader confía automáticamente en timestamps si el certificado TSA está en la cadena de confianza.

---

## 4. Verificar Firma PAdES B-LT

**PAdES B-LT** (Long-Term Validation) incluye información de revocación (OCSP/CRL) embebida en el PDF, permitiendo validación offline futura.

### 4.1. Abrir PDF Firmado

1. Abra el PDF firmado en Adobe Reader/Acrobat
2. **Indicador visual:** Aparecerá un banner en la parte superior:
   - **Azul con marca de verificación:** "Firmado y todas las firmas son válidas"
   - **Amarillo con triángulo:** "Firmado, pero no se puede verificar"
   - **Rojo con X:** "Firma inválida o documento modificado"

**Captura sugerida 5:** _Banner azul de verificación exitosa en la parte superior del PDF_

### 4.2. Inspeccionar Detalles de la Firma

**Captura sugerida 6:** _Panel de firmas mostrando información detallada de una firma PAdES B-LT_

1. Haga clic en el **banner de firma** o en el **icono de firma** en el documento
2. Se abrirá el panel "Panel de firmas" a la derecha (o haga clic derecho → **Validar firma**)
3. Haga clic en **Propiedades de la firma** (icono de lupa o clic derecho → Mostrar propiedades)

### 4.3. Verificar Componentes PAdES B-LT

En el diálogo "Propiedades de Firma", verifique:

#### Pestaña "Resumen"

| Campo | Valor Esperado | Descripción |
|-------|----------------|-------------|
| **Estado de la firma** | ✅ "Válida, sin cambios" | Firma criptográficamente correcta |
| **Estado de la identidad del firmante** | ✅ "Válida" | Certificado de confianza |
| **Estado de revocación** | ✅ "Válido en el momento de la firma" | OCSP/CRL OK |
| **Hora de la firma** | Fecha/hora + timestamp | Incluye timestamp RFC 3161 |

#### Pestaña "Firmante"

| Campo | Información |
|-------|-------------|
| **Firmante** | Nombre del titular (CN del certificado) |
| **Organización** | AFIP / RENAPER / Certificador privado |
| **Número de serie** | Serie del certificado X.509 |
| **Algoritmo de firma** | RSA + SHA-256 (o SHA-384/512) |
| **Tamaño de clave** | 2048 bits o superior |

**Verificación Ley 25.506:**
- ✅ Algoritmo SHA-256 o superior (SHA-1 NO cumple)
- ✅ RSA 2048 bits o superior (1024 bits NO cumple)

#### Pestaña "Información de Revocación"

**Captura sugerida 7:** _Pestaña de Información de Revocación mostrando OCSP responses embebidos_

| Campo | Valor Esperado PAdES B-LT |
|-------|---------------------------|
| **Información de revocación incluida** | ✅ "Sí" |
| **Tipo** | OCSP Response o CRL |
| **Estado** | ✅ "Válido" o "Bueno" |
| **Momento de verificación** | Timestamp de la consulta |
| **Próxima actualización** | Fecha de expiración OCSP/CRL |

**Indicador PAdES B-LT:** Si "Información de revocación incluida" = "Sí", el PDF contiene DSS (Document Security Store) y es PAdES B-LT válido.

### 4.4. Validar Cadena de Certificación

1. En "Propiedades de Firma", haga clic en **Mostrar certificado del firmante**
2. Pestaña **Cadena de confianza**:

**Captura sugerida 8:** _Árbol de cadena de confianza desde certificado de usuario hasta AC raíz_

```
✅ AC AFIP (Raíz) - "Este certificado es de confianza"
  └─ ✅ AC AFIP Subordinada (Intermedio)
      └─ ✅ Juan Pérez (DNI 12345678) - Certificado de usuario
```

**Indicadores de confianza:**
- ✅ **Marca verde** en todos los niveles: Cadena completa y válida
- ⚠️ **Triángulo amarillo:** Certificado raíz no importado (ver sección 2)
- ❌ **X roja:** Certificado revocado o expirado

3. Haga clic en cada nivel y verifique:
   - **Válido desde/hasta:** Fechas de validez del certificado
   - **Uso de clave:** Firma digital, No repudio
   - **Emisor:** Coincide con la CA esperada (AFIP/RENAPER/etc.)

---

## 5. Verificar Timestamp (PAdES B-LTA)

**PAdES B-LTA** (Long-Term Archival) extiende B-LT con **archive timestamps** que protegen la firma contra algoritmos criptográficos obsoletos en el futuro.

### 5.1. Identificar PAdES B-LTA

**Captura sugerida 9:** _Propiedades de firma mostrando timestamp de archivo adicional_

1. Abra "Propiedades de Firma" (ver sección 4.2)
2. Verifique la presencia de **múltiples timestamps**:

| Tipo de Timestamp | Descripción | Ubicación |
|-------------------|-------------|-----------|
| **Signature Timestamp** | Timestamp de la firma (PAdES B-T) | Incluido en la firma digital |
| **Archive Timestamp** | Timestamp del documento completo (PAdES B-LTA) | Atributo firmado adicional |

**Indicadores visuales en Adobe:**

```
🔵 Firma de Juan Pérez
  ├─ 📝 Firma digital (RSA 2048 + SHA-256)
  ├─ ⏰ Timestamp de firma (2026-02-01 10:30:00 GMT-3)
  └─ 🏛️ Archive Timestamp (2026-02-01 10:31:00 GMT-3) ← PAdES B-LTA
```

### 5.2. Validar Archive Timestamp

1. En "Propiedades de Firma", pestaña **Timestamps**
2. Verifique cada timestamp:

#### Signature Timestamp (PAdES B-T/B-LT)

| Campo | Valor Esperado |
|-------|----------------|
| **Estado** | ✅ "Válido" |
| **Autoridad de timestamp** | TSA AFIP / TSA Certant / etc. |
| **Algoritmo** | SHA-256 o superior |
| **Hora del timestamp** | Coincide con hora de firma |
| **Incluido en la firma** | ✅ Sí |

#### Archive Timestamp (PAdES B-LTA)

**Captura sugerida 10:** _Detalles del Archive Timestamp con estado válido_

| Campo | Valor Esperado |
|-------|----------------|
| **Estado** | ✅ "Válido" |
| **Autoridad de timestamp** | TSA AFIP / TSA Certant / etc. |
| **Algoritmo** | SHA-256 o superior |
| **Hora del timestamp** | Posterior a la firma original |
| **Ámbito** | "Todo el documento" (incluye DSS) |
| **Tipo** | "Archive Timestamp" o "Document Timestamp" |

**Verificación crítica:** El archive timestamp debe cubrir:
- ✅ Firma digital original
- ✅ Signature timestamp
- ✅ DSS (OCSP/CRL embebidos)
- ✅ Contenido del PDF

3. Haga clic en **Mostrar certificado del timestamp** para validar la cadena TSA

### 5.3. Interpretar Resultados de Timestamp

| Resultado | Significado | Nivel PAdES |
|-----------|-------------|-------------|
| ✅ Signature timestamp válido | Firma con timestamp básico | **PAdES B-T** |
| ✅ Signature timestamp + DSS | Validación a largo plazo | **PAdES B-LT** |
| ✅ Archive timestamp válido | Archivo seguro contra obsolescencia | **PAdES B-LTA** |
| ⚠️ Timestamp expirado | Renovar con nuevo archive timestamp | Migrar a B-LTA |
| ❌ Timestamp inválido | Posible manipulación del documento | Investigar |

---

## 6. Interpretar Resultados de Validación

### 6.1. Estados de Firma en Adobe

**Captura sugerida 11:** _Comparación de banners de diferentes estados de validación_

#### ✅ Firma Válida (Verde/Azul)

**Banner:** "Firmado y todas las firmas son válidas"

**Significado:**
- Firma criptográficamente correcta
- Certificado de confianza (CA importada)
- Sin modificaciones post-firma
- Revocación verificada (OCSP/CRL OK)
- Timestamps válidos (si aplica)

**Nivel de confianza:** ALTO - El documento cumple Ley 25.506

#### ⚠️ Firma con Advertencias (Amarillo)

**Banner:** "Firmado, pero no se puede verificar completamente"

**Causas comunes:**
1. **Certificado raíz no importado**
   - Solución: Importar CA argentina (ver sección 2)
2. **Información de revocación no disponible**
   - Causa: Sin conexión a Internet + sin DSS embedded
   - PAdES B-LT evita este problema
3. **Timestamp expirado**
   - Solución: Agregar nuevo archive timestamp
4. **Algoritmo débil** (SHA-1, RSA 1024)
   - No cumple Ley 25.506 desde 2015

**Nivel de confianza:** MEDIO - Verificar causa específica

#### ❌ Firma Inválida (Rojo)

**Banner:** "Firma inválida" o "El documento ha sido alterado"

**Causas:**
1. **Documento modificado post-firma**
   - Detectado por hash mismatch
   - Violación de integridad
2. **Certificado revocado**
   - Verificar en OCSP/CRL del emisor
3. **Firma corrupta**
   - Archivo dañado o manipulado

**Nivel de confianza:** NULO - NO aceptar el documento

### 6.2. Detalles de Validación

**Captura sugerida 12:** _Diálogo de propiedades mostrando todos los checks en verde_

| Verificación | ✅ OK | ⚠️ Advertencia | ❌ Fallo |
|--------------|-------|----------------|----------|
| **Integridad del documento** | Sin cambios | Cambios permitidos* | Modificación no autorizada |
| **Validez del certificado** | Válido en fecha firma | Cerca de expiración | Expirado o revocado |
| **Cadena de confianza** | CA importada y válida | CA no reconocida | Cadena rota |
| **Información de revocación** | OCSP/CRL OK | No disponible | Certificado revocado |
| **Timestamp** | Válido y actual | Cercano a expiración | Expirado o inválido |
| **Algoritmos** | SHA-256+, RSA 2048+ | SHA-1 (obsoleto) | MD5 (inseguro) |

\* **Cambios permitidos:** Adobe permite ciertos cambios post-firma si el firmante lo autorizó:
- Agregar campos de formulario
- Agregar anotaciones/comentarios
- Agregar nuevas firmas (contrafirma)
- Agregar archive timestamps

**Verificación en Adobe:** Panel de firmas muestra "Documento certificado, cambios permitidos: ..."

### 6.3. Validación Avanzada (Adobe Acrobat Pro)

Solo disponible en versión Pro (no Reader):

1. **Análisis forense:**
   - Herramientas → Producción de impresión → Análisis preliminar
   - Detecta objetos ocultos, capas, scripts

2. **Comparación de versiones:**
   - Ver → Comparar documentos
   - Muestra diferencias entre versión firmada y actual

3. **Informe de validación:**
   - Panel de firmas → Validar todas las firmas → Generar informe
   - Exporta PDF con resumen de verificación

---

## 7. Solución de Problemas Comunes

### 7.1. "Certificado no es de confianza" (Triángulo Amarillo)

**Problema:** Banner amarillo con mensaje "Firmante desconocido" o "Certificado no es de confianza"

**Causa:** El certificado raíz de la CA argentina no está importado en Adobe

**Solución:**
1. Identifique la CA emisora:
   - Abra "Propiedades de Firma"
   - Pestaña "Firmante" → "Emisor" (ejemplo: "AC AFIP")
2. Descargue e importe el certificado raíz correspondiente (ver sección 2)
3. Cierre y reabra el PDF para re-validar

**Verificación:** El banner debe cambiar a azul/verde

---

### 7.2. "No se puede verificar la información de revocación"

**Problema:** Advertencia sobre OCSP/CRL no disponible

**Causas y Soluciones:**

#### Causa 1: Sin conexión a Internet

- **Solución temporal:** Activar validación offline:
  1. Preferencias → Firmas → Verificación
  2. Desmarque "Requerir información de revocación al validar"
  3. Re-valide la firma

- **Solución permanente:** Si el PDF es PAdES B-LT (con DSS), Adobe usará OCSP/CRL embebido automáticamente

#### Causa 2: Servidor OCSP/CRL caído

- **Solución:** Esperar restauración del servicio o contactar al certificador
- **Verificación alternativa:** Usar herramienta `pdfsigner` de este proyecto:
  ```bash
  uv run pdfsigner validate documento_firmado.pdf --detailed
  ```

#### Causa 3: PDF no es PAdES B-LT (sin DSS)

- **Solución:** Re-firmar el documento con PDFSigner habilitando LTV:
  ```bash
  uv run pdfsigner sign --ltv documento.pdf
  ```

---

### 7.3. "El algoritmo de firma es obsoleto" (SHA-1)

**Problema:** Advertencia sobre algoritmo débil (SHA-1, MD5, RSA 1024)

**Causa:** Firma creada con algoritmos no conformes a Ley 25.506 (requisito: SHA-256+, RSA 2048+)

**Impacto:**
- ⚠️ Firmas con SHA-1 creadas **antes de 2015:** Generalmente aceptadas (transición)
- ❌ Firmas con SHA-1 creadas **después de 2015:** NO VÁLIDAS según normativa argentina
- ❌ Firmas con MD5 o RSA 1024: **NUNCA VÁLIDAS**

**Solución:**
1. **Si es un documento antiguo (pre-2015):**
   - Considerar válido por contexto histórico
   - Agregar contrafirma con algoritmos actuales

2. **Si es un documento reciente:**
   - Rechazar la firma
   - Solicitar re-firma con algoritmos conformes
   - Usar PDFSigner para re-firmar:
     ```bash
     uv run pdfsigner sign --digest-algorithm sha256 documento.pdf
     ```

**Configuración recomendada en PDFSigner:**
```toml
# ~/.config/pdfsigner/config.toml
[signature]
digest_algorithm = "sha256"  # o sha384, sha512
rsa_key_size = 2048          # mínimo legal
```

---

### 7.4. "Timestamp expirado o no válido"

**Problema:** Advertencia sobre timestamp caducado

**Causa:** Timestamp de firma tiene fecha de expiración vencida (típicamente 10-15 años)

**Impacto:**
- ⚠️ La firma principal sigue siendo válida
- ⚠️ Reducción de confianza a largo plazo
- ❌ Riesgo de invalidación futura por algoritmos obsoletos

**Solución - Agregar Archive Timestamp (PAdES B-LTA):**

```bash
# Opción 1: Agregar archive timestamp inmediatamente
uv run pdfsigner archive-ts documento_firmado.pdf

# Opción 2: Programar renovación automática
uv run pdfsigner schedule-ts documento_firmado.pdf --interval 90d
```

**Resultado:** El PDF tendrá múltiples capas temporales protegiendo la firma original

**Configuración preventiva:**
```toml
# ~/.config/pdfsigner/config.toml
[ltv]
archive_ts_enabled = true
archive_ts_auto = true  # Agrega automáticamente después de firmar
```

---

### 7.5. "El documento ha sido alterado después de firmarse"

**Problema:** Banner rojo indicando modificación post-firma

**Causa:** El hash del contenido no coincide con el firmado originalmente

**Investigación:**

1. **Verificar tipo de cambios:**
   - Panel de firmas → Clic en firma → "Comparar versiones firmadas"
   - Adobe muestra diferencias visuales

2. **Cambios permitidos vs no permitidos:**

   **✅ Cambios permitidos** (si el firmante lo autorizó):
   - Agregar firmas adicionales (contrafirma)
   - Agregar comentarios/anotaciones
   - Agregar archive timestamps
   - Rellenar campos de formulario (si fue certificado con permisos)

   **❌ Cambios NO permitidos:**
   - Modificación de texto/imágenes
   - Eliminación de contenido
   - Cambio de metadatos (autor, título)
   - Manipulación de estructuras PDF

3. **Solución:**
   - **Si son cambios autorizados:** Verificar en "Propiedades de firma" → "Derechos del documento"
   - **Si son cambios NO autorizados:** Rechazar el documento y solicitar original

**Herramienta forense (Acrobat Pro):**
```
Herramientas → Producción de impresión → Análisis preliminar
  → Revisar objetos ocultos
  → Verificar capas de contenido
  → Detectar scripts embebidos
```

---

### 7.6. Adobe Reader se congela al validar

**Problema:** Adobe Reader no responde al abrir PDF firmado

**Causa:** Verificación OCSP/CRL bloqueada por timeout de red

**Solución inmediata:**
1. Cerrar Adobe Reader (forzar cierre si es necesario)
2. Desactivar verificación en línea:
   - Preferencias → Firmas → Verificación
   - Desmarque "Consultar servidores OCSP"
   - Desmarque "Consultar listas CRL"
3. Reabrir el PDF

**Solución permanente:**
- Configurar timeout más corto:
  - Preferencias → Firmas → Verificación → Configuración de red
  - Timeout de OCSP: 10 segundos (default: 60)
  - Timeout de CRL: 15 segundos (default: 120)

**Prevención:** Usar PAdES B-LT con DSS embebido (no requiere conexión en línea)

---

## 8. FAQ (Preguntas Frecuentes)

### 8.1. Sobre Validación

**P: ¿Adobe Reader puede validar firmas PAdES B-LT/LTA offline?**
R: Sí, si el PDF incluye DSS (Document Security Store) con información OCSP/CRL embebida. PAdES B-LT permite validación completa sin conexión a Internet.

**P: ¿Necesito importar certificados cada vez que abro un PDF?**
R: No. Los certificados raíz se importan una sola vez en Adobe Reader y se aplican a todos los PDFs futuros.

**P: ¿Adobe Reader valida automáticamente al abrir el PDF?**
R: Sí, si está activado en Preferencias → Firmas → "Verificar firmas al abrir el documento" (recomendado).

**P: ¿Puedo validar múltiples firmas en un mismo PDF?**
R: Sí. Adobe muestra todas las firmas en el panel lateral. Cada firma se valida independientemente. Para PAdES B-LT/LTA, todas las firmas comparten el DSS y timestamps.

---

### 8.2. Sobre Certificados Argentinos

**P: ¿Todos los certificados argentinos son compatibles con Adobe?**
R: Sí, siempre que:
- Sean certificados X.509 v3
- Usen algoritmos conformes (RSA 2048+, SHA-256+)
- La CA raíz esté importada en Adobe

**P: ¿Los certificados de AFIP/RENAPER son gratuitos?**
R: Sí. Los certificados gubernamentales (AFIP, RENAPER, FDR) son gratuitos para ciudadanos y contribuyentes argentinos.

**P: ¿Cuánto dura la validez de un certificado argentino?**
R: Típicamente:
- **AFIP:** 2 años (renovable)
- **RENAPER:** 3 años (renovable)
- **Certificadores privados:** 1-3 años según contrato

**P: ¿Qué pasa si mi certificado expira después de firmar?**
R: La firma sigue siendo válida si:
- El certificado estaba vigente **al momento de firmar**
- El PDF incluye timestamp (PAdES B-T o superior)
- La información de revocación está embebida (PAdES B-LT)

Adobe valida la firma contra la fecha del timestamp, no la fecha actual.

---

### 8.3. Sobre PAdES B-LT/LTA

**P: ¿Cuál es la diferencia entre PAdES B-LT y B-LTA?**
R:
- **PAdES B-LT:** Incluye OCSP/CRL embebidos (DSS) → validación a largo plazo
- **PAdES B-LTA:** B-LT + archive timestamps → protección contra algoritmos obsoletos

**Recomendación:** Usar B-LTA para documentos con retención >10 años (legales, históricos, médicos)

**P: ¿Adobe Reader muestra el nivel PAdES de un documento?**
R: No directamente, pero puede inferirse:
- Timestamp de firma presente → **PAdES B-T**
- + "Información de revocación incluida" → **PAdES B-LT**
- + Archive timestamp adicional → **PAdES B-LTA**

**P: ¿Puedo convertir un PDF PAdES B-T a B-LTA?**
R: Sí, usando PDFSigner:
```bash
# 1. Agregar DSS (B-T → B-LT)
uv run pdfsigner sign --ltv documento_B-T.pdf

# 2. Agregar archive timestamp (B-LT → B-LTA)
uv run pdfsigner archive-ts documento_B-LT_signed.pdf
```

Adobe validará correctamente el resultado.

**P: ¿Los archive timestamps tienen vencimiento?**
R: Sí, típicamente 10-15 años. Solución: Agregar nuevos archive timestamps periódicamente (renovación de cadena temporal).

**Automatización con PDFSigner:**
```bash
uv run pdfsigner schedule-ts documento.pdf --interval 5y
```

---

### 8.4. Sobre Conformidad Legal

**P: ¿Adobe Reader valida conformidad con Ley 25.506?**
R: Parcialmente. Adobe valida:
- ✅ Algoritmos criptográficos (RSA, SHA)
- ✅ Certificados X.509 y cadena de confianza
- ✅ Timestamps RFC 3161
- ✅ Información de revocación (OCSP/CRL)

Pero **NO** valida:
- ❌ Tamaño de clave mínimo (2048 bits) - debe verificarse manualmente
- ❌ Certificadores licenciados en Argentina - debe verificarse en ONTI
- ❌ Requisitos legales de archivo (7 años mínimo)

**Recomendación:** Usar PDFSigner para garantizar conformidad total:
```bash
uv run pdfsigner validate documento.pdf --regulatory ar-25506
```

**P: ¿Es válido un PDF firmado solo con PAdES B-T (sin B-LT)?**
R: Legalmente **sí**, siempre que:
- Tenga timestamp válido
- Certificado conforme a Ley 25.506
- Se archive el PDF y la información de revocación por separado

Pero **no es recomendable** para archivo a largo plazo. PAdES B-LT/LTA es la mejor práctica.

**P: ¿Adobe Reader cumple requisitos HIPAA/GDPR?**
R: Adobe Reader **valida** firmas, pero no proporciona funcionalidades de:
- Audit trail (PDFSigner Core Audit)
- Cifrado AES-256 (PDFSigner Core Encryption)
- Control de acceso (PDFSigner Core Users)
- Breach notification (PDFSigner Core Breach)

Para cumplimiento completo en salud/privacidad, usar PDFSigner con `healthcare_mode = true`.

---

### 8.5. Sobre Troubleshooting

**P: ¿Por qué Adobe no reconoce mi firma si está firmada correctamente?**
R: Causas comunes (en orden de frecuencia):
1. **Certificado raíz no importado** (80%) → Ver sección 2
2. **PDF corrupto/dañado** (10%) → Verificar integridad con `uv run pdfsigner validate`
3. **Algoritmo obsoleto** (5%) → Verificar SHA-256+ y RSA 2048+
4. **Adobe Reader desactualizado** (<5%) → Actualizar a versión DC más reciente

**P: ¿Adobe Reader puede validar firmas de otros países (UE, USA)?**
R: Sí, si:
- El certificado raíz está en el Adobe Approved Trust List (AATL), o
- Se importa manualmente el certificado raíz extranjero (mismo proceso que sección 2)

**P: ¿Cómo exporto un reporte de validación desde Adobe Reader?**
R: Solo disponible en Adobe Acrobat Pro:
1. Panel de firmas → Opciones → Validar todas las firmas
2. Clic derecho en resultado → Generar informe de validación
3. Guardar como PDF

**Alternativa con Adobe Reader (gratuito):**
- Captura de pantalla del panel de propiedades de firma
- Exportar detalles del certificado (botón "Exportar")

**Alternativa con PDFSigner:**
```bash
uv run pdfsigner validate documento.pdf --format json > reporte.json
uv run pdfsigner validate documento.pdf --format html > reporte.html
```

---

## Recursos Adicionales

### Documentación Oficial

- **Ley 25.506 (Firma Digital Argentina):** https://www.argentina.gob.ar/normativa/nacional/ley-25506-70749
- **ONTI (Infraestructura PKI Argentina):** https://www.argentina.gob.ar/jefatura/innovacion/onti
- **Adobe Digital Signatures Guide:** https://helpx.adobe.com/acrobat/using/validating-digital-signatures.html
- **ETSI PAdES Standards:** https://www.etsi.org/standards/pades

### Certificadores Argentinos

| Certificador | Sitio Web | Soporte |
|--------------|-----------|---------|
| **AFIP** | https://www.afip.gob.ar/certificado/ | 0800-999-2347 |
| **RENAPER** | https://www.argentina.gob.ar/interior/renaper | 0800-122-2736 |
| **FDR** | https://www.argentina.gob.ar/jefatura/innovacion/fdr | fdr@jefatura.gob.ar |
| **Andreani** | https://www.andreani.com/certificados | soporte@andreani.com |
| **E-CERT** | https://www.ecert.com.ar | soporte@ecert.com.ar |

### Herramientas Complementarias

- **PDFSigner:** https://github.com/pdfsigner (esta herramienta)
- **Adobe Trust Services:** https://www.adobe.com/trust.html
- **EU DSS (Digital Signature Service):** https://ec.europa.eu/digital-building-blocks/DSS

---

## Changelog

### v1.0.0 - 2026-02-01

- Versión inicial de la guía de verificación en Adobe Reader/Acrobat
- Cobertura completa de PAdES B-LT y B-LTA
- Instrucciones específicas para certificadores argentinos
- Troubleshooting y FAQ

---

**Autor:** PDFSigner Project
**Licencia:** CC BY-SA 4.0
**Última actualización:** 2026-02-01

# Ejemplo de Integración: RevocationChecker con CertificateSelector

## Resumen de Cambios

Se ha integrado el sistema de verificación de revocación OCSP/CRL en `CertificateSelector` para permitir la validación del estado de revocación de certificados durante la selección.

### Archivos Modificados

- **`src/pdfsigner/core/token/cert_selector.py`**
  - Agregado parámetro opcional `revocation_checker` en `__init__()`
  - Nuevo parámetro `check_revocation` en `validate_certificate()`
  - Soporte para verificación OCSP/CRL con manejo graceful de errores

## Uso Básico

### Sin verificación de revocación (comportamiento actual)

```python
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.token.cert_selector import CertificateSelector

nss_handler = NSSHandler(db_path="~/.nss")
nss_handler.login(pin="1234")

selector = CertificateSelector(nss_handler)
cert = selector.get_default_certificate()
selector.validate_certificate(cert)  # Solo valida expiración y keyUsage
```

### Con verificación de revocación (nueva funcionalidad)

```python
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.token.cert_selector import CertificateSelector
from pdfsigner.core.certificate.revocation_checker import RevocationChecker
from cryptography import x509

# Inicializar componentes
nss_handler = NSSHandler(db_path="~/.nss")
nss_handler.login(pin="1234")

# Crear checker con configuración personalizada
revocation_checker = RevocationChecker(
    ocsp_timeout=10,      # 10 segundos para OCSP
    crl_timeout=30,       # 30 segundos para CRL
    ocsp_cache_ttl=3600,  # Cache OCSP por 1 hora
    prefer_ocsp=True      # Intentar OCSP primero
)

# Crear selector con checker
selector = CertificateSelector(nss_handler, revocation_checker=revocation_checker)

# Obtener certificado
cert = selector.get_default_certificate()

# Validar con verificación de revocación
# NOTA: Requiere convertir el certificado a x509.Certificate de cryptography
# Esto debe ser implementado en NSSHandler para obtener el certificado raw
cert_x509 = ...  # x509.Certificate del certificado
issuer_x509 = ...  # x509.Certificate del emisor (opcional para OCSP)

selector.validate_certificate(
    cert,
    check_revocation=True,
    cert_x509=cert_x509,
    issuer_cert_x509=issuer_x509  # Opcional, pero recomendado para OCSP
)
```

## Comportamiento

### Estado de Revocación

La verificación puede retornar los siguientes estados:

- **GOOD**: Certificado válido y no revocado
- **REVOKED**: Certificado revocado (lanza `CertificateNotFoundError`)
- **UNKNOWN**: No se pudo determinar el estado (continúa con warning)
- **ERROR**: Error durante la verificación (continúa con warning)

### Manejo de Errores

La implementación es robusta y maneja los siguientes casos:

1. **No hay RevocationChecker configurado**: Log warning y continúa
2. **No hay certificado x509 disponible**: Log warning y continúa
3. **No hay certificado emisor**: Intenta CRL (no requiere emisor)
4. **Timeout de red**: Log warning y continúa (no bloquea la firma)
5. **Certificado REVOCADO**: Lanza excepción (bloquea la firma)

### Logging

Todos los eventos de verificación se registran:

```
INFO: Checking revocation status for 'John Doe'...
INFO: Certificate 'John Doe' revocation status: GOOD (checked via OCSP)
```

O en caso de revocación:

```
ERROR: Certificate 'John Doe' has been revoked on 2026-01-15 10:30:00+00:00 (reason: KEY_COMPROMISE)
```

## Próximos Pasos

Para completar la integración, se necesita:

1. **Extender NSSHandler** para obtener certificados en formato `x509.Certificate`
2. **Configuración global** para habilitar/deshabilitar verificación de revocación
3. **Integrar en GUI** para mostrar estado de revocación en el selector de certificados
4. **Tests** para validar la integración con RevocationChecker

## Consideraciones de Performance

- La verificación de revocación es **costosa en red** (OCSP: ~1-2s, CRL: ~5-10s)
- Se recomienda usar **caché OCSP** (1 hora por defecto)
- Considerar hacer la verificación **opcional y configurable**
- Para batch signing, verificar solo una vez al inicio

## Ejemplo Completo con Configuración

```python
from pdfsigner.core.config import get_settings

settings = get_settings()

# Crear checker solo si está habilitado en configuración
revocation_checker = None
if settings.revocation_check_enabled:
    revocation_checker = RevocationChecker(
        ocsp_timeout=settings.ocsp_timeout,
        crl_timeout=settings.crl_timeout,
        ocsp_cache_ttl=settings.ocsp_cache_ttl,
    )

# Usar en selector
selector = CertificateSelector(nss_handler, revocation_checker=revocation_checker)

# La verificación se hace automáticamente si está configurada
cert = selector.get_default_certificate()
selector.validate_certificate(
    cert,
    check_revocation=settings.revocation_check_enabled,
    cert_x509=cert_x509,
    issuer_cert_x509=issuer_x509,
)
```

## Testing

Todos los tests existentes pasan sin cambios:

```bash
$ uv run pytest tests/unit/test_cert_selector.py -v
======================== 24 passed in 1.06s =========================
```

Los tests actuales no cubren la nueva funcionalidad de revocación (requiere certificados reales con OCSP/CRL configurados).

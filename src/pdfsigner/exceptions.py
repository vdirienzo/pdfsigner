"""
exceptions.py - Excepciones personalizadas para PDFSigner

Autor: Homero Thompson del Lago del Terror

Define la jerarquía de excepciones para manejo de errores
en todo el sistema de firma digital.
"""


class PDFSignerError(Exception):
    """Excepción base para todos los errores de PDFSigner."""

    pass


class TokenError(PDFSignerError):
    """Errores relacionados con el token USB/NSS."""

    pass


class TokenNotFoundError(TokenError):
    """Token USB no detectado o no disponible."""

    def __init__(self, message: str = "Token USB no detectado"):
        super().__init__(message)


class TokenAuthenticationError(TokenError):
    """Error de autenticación con el token (PIN incorrecto)."""

    def __init__(self, message: str = "PIN incorrecto o autenticación fallida"):
        super().__init__(message)


class CertificateError(PDFSignerError):
    """Errores relacionados con certificados."""

    pass


class CertificateNotFoundError(CertificateError):
    """Certificado de firma no encontrado en el token."""

    def __init__(self, message: str = "No se encontró certificado de firma válido"):
        super().__init__(message)


class CertificateExpiredError(CertificateError):
    """Certificado expirado."""

    def __init__(self, cert_name: str, expiry_date: str):
        super().__init__(f"Certificado '{cert_name}' expiró el {expiry_date}")


class SigningError(PDFSignerError):
    """Errores durante el proceso de firma."""

    pass


class PDFError(SigningError):
    """Errores relacionados con el archivo PDF."""

    pass


class PDFProtectedError(PDFError):
    """PDF está protegido y no se puede firmar."""

    def __init__(self, filename: str):
        super().__init__(f"El archivo '{filename}' está protegido contra modificaciones")


class PDFCorruptedError(PDFError):
    """PDF corrupto o inválido."""

    def __init__(self, filename: str):
        super().__init__(f"El archivo '{filename}' está corrupto o no es un PDF válido")


class TimestampError(SigningError):
    """Errores con el servidor de timestamp (TSA)."""

    pass


class TSAConnectionError(TimestampError):
    """No se puede conectar al servidor TSA."""

    def __init__(self, tsa_url: str):
        super().__init__(f"No se puede conectar al servidor de timestamp: {tsa_url}")


class TSAResponseError(TimestampError):
    """Respuesta inválida del servidor TSA."""

    def __init__(self, message: str = "Respuesta inválida del servidor de timestamp"):
        super().__init__(message)


class ConfigurationError(PDFSignerError):
    """Errores de configuración."""

    pass


class NSSConfigError(ConfigurationError):
    """Error en la configuración de NSS."""

    def __init__(self, nss_path: str):
        super().__init__(f"Base de datos NSS no válida en: {nss_path}")

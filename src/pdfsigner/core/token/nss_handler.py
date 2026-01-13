"""
nss_handler.py - Manejador de conexión con NSS/PKCS#11

Autor: Homero Thompson del Lago del Terror

Maneja la comunicación con el token USB SafeNet 5110
a través de la base de datos NSS usando python-pkcs11.
"""

from dataclasses import dataclass
from pathlib import Path

import pkcs11
from cryptography import x509
from loguru import logger
from pkcs11 import ObjectClass, lib

from pdfsigner.config.settings import get_settings
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    NSSConfigError,
    TokenAuthenticationError,
    TokenNotFoundError,
)


@dataclass
class CertificateInfo:
    """Información de un certificado en el token."""

    label: str
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    can_sign: bool
    pkcs11_id: bytes


class NSSHandler:
    """
    Manejador de conexión con NSS/PKCS#11.

    Gestiona la comunicación con el token USB a través de NSS.
    """

    # Rutas comunes de la librería NSS
    NSS_LIB_PATHS = [
        "/usr/lib/x86_64-linux-gnu/libnssckbi.so",
        "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
        "/usr/lib/libnssckbi.so",
        "/usr/lib/libsoftokn3.so",
    ]

    # Ruta del módulo SafeNet (si está instalado)
    SAFENET_LIB_PATHS = [
        "/usr/lib/libeToken.so",
        "/usr/lib/x86_64-linux-gnu/libeToken.so",
        "/opt/safenet/lunaclient/lib/libCryptoki2_64.so",
    ]

    def __init__(self, nss_db_path: Path | None = None):
        """
        Inicializa el handler de NSS.

        Args:
            nss_db_path: Ruta a la base de datos NSS (default: desde settings)
        """
        settings = get_settings()
        self.nss_db_path = nss_db_path or settings.nss_db_path
        self._lib: pkcs11.lib | None = None
        self._token: pkcs11.Token | None = None
        self._session: pkcs11.Session | None = None

    def _find_pkcs11_lib(self) -> str:
        """
        Encuentra la librería PKCS#11 disponible.

        Returns:
            Ruta a la librería encontrada

        Raises:
            TokenNotFoundError: Si no se encuentra librería
        """
        # Primero intentar SafeNet
        for path in self.SAFENET_LIB_PATHS:
            if Path(path).exists():
                logger.debug(f"Usando librería SafeNet: {path}")
                return path

        # Luego NSS
        for path in self.NSS_LIB_PATHS:
            if Path(path).exists():
                logger.debug(f"Usando librería NSS: {path}")
                return path

        raise TokenNotFoundError(
            "No se encontró librería PKCS#11 (NSS o SafeNet). "
            "Verifica que el driver del token esté instalado."
        )

    def initialize(self) -> None:
        """
        Inicializa la conexión con PKCS#11.

        Raises:
            NSSConfigError: Si la configuración de NSS es inválida
            TokenNotFoundError: Si no se detecta el token
        """
        if not self.nss_db_path.exists():
            raise NSSConfigError(str(self.nss_db_path))

        lib_path = self._find_pkcs11_lib()

        try:
            self._lib = lib(lib_path)
            logger.info(f"Librería PKCS#11 cargada: {lib_path}")
        except Exception as e:
            raise TokenNotFoundError(f"Error cargando librería PKCS#11: {e}")

    def get_available_tokens(self) -> list[str]:
        """
        Lista los tokens disponibles.

        Returns:
            Lista de nombres de tokens
        """
        if self._lib is None:
            self.initialize()

        tokens = []
        for slot in self._lib.get_slots(token_present=True):
            token = slot.get_token()
            tokens.append(token.label.strip())
            logger.debug(f"Token encontrado: {token.label}")

        return tokens

    def connect_token(self, token_label: str | None = None) -> None:
        """
        Conecta con un token específico.

        Args:
            token_label: Etiqueta del token (None = primer token disponible)

        Raises:
            TokenNotFoundError: Si no se encuentra el token
        """
        if self._lib is None:
            self.initialize()

        for slot in self._lib.get_slots(token_present=True):
            token = slot.get_token()
            if token_label is None or token.label.strip() == token_label:
                self._token = token
                logger.info(f"Conectado al token: {token.label.strip()}")
                return

        raise TokenNotFoundError(
            f"Token '{token_label}' no encontrado" if token_label else "No hay tokens disponibles"
        )

    def authenticate(self, pin: str) -> None:
        """
        Autentica con el token usando el PIN.

        Args:
            pin: PIN del token

        Raises:
            TokenAuthenticationError: Si el PIN es incorrecto
        """
        if self._token is None:
            raise TokenNotFoundError("Primero debe conectar un token")

        try:
            self._session = self._token.open(user_pin=pin)
            logger.info("Autenticación exitosa con el token")
        except pkcs11.exceptions.PinIncorrect:
            raise TokenAuthenticationError("PIN incorrecto")
        except pkcs11.exceptions.PinLocked:
            raise TokenAuthenticationError("Token bloqueado por demasiados intentos")
        except Exception as e:
            raise TokenAuthenticationError(f"Error de autenticación: {e}")

    def list_certificates(self) -> list[CertificateInfo]:
        """
        Lista los certificados disponibles en el token.

        Returns:
            Lista de información de certificados
        """
        if self._session is None:
            raise TokenAuthenticationError("Debe autenticarse primero")

        certs = []
        for obj in self._session.get_objects({ObjectClass.CERTIFICATE}):
            try:
                cert_der = obj[pkcs11.Attribute.VALUE]
                cert = x509.load_der_x509_certificate(cert_der)

                # Verificar si tiene key usage para firma
                can_sign = False
                try:
                    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    can_sign = key_usage.value.digital_signature or key_usage.value.non_repudiation
                except x509.ExtensionNotFound:
                    can_sign = True  # Si no tiene extensión, asumir que puede firmar

                cert_info = CertificateInfo(
                    label=obj[pkcs11.Attribute.LABEL],
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    serial_number=format(cert.serial_number, "x"),
                    not_before=cert.not_valid_before_utc.isoformat(),
                    not_after=cert.not_valid_after_utc.isoformat(),
                    can_sign=can_sign,
                    pkcs11_id=obj[pkcs11.Attribute.ID],
                )
                certs.append(cert_info)
                logger.debug(f"Certificado encontrado: {cert_info.label}")

            except Exception as e:
                logger.warning(f"Error leyendo certificado: {e}")
                continue

        return certs

    def get_signing_key_and_cert(
        self, cert_id: bytes | None = None
    ) -> tuple[pkcs11.PrivateKey, bytes]:
        """
        Obtiene la clave privada y certificado para firmar.

        Args:
            cert_id: ID del certificado (None = primer certificado de firma)

        Returns:
            Tupla (clave_privada, certificado_der)

        Raises:
            CertificateNotFoundError: Si no se encuentra certificado de firma
        """
        if self._session is None:
            raise TokenAuthenticationError("Debe autenticarse primero")

        # Buscar certificados que pueden firmar
        certs = [c for c in self.list_certificates() if c.can_sign]
        if not certs:
            raise CertificateNotFoundError()

        # Seleccionar certificado
        selected = None
        if cert_id:
            selected = next((c for c in certs if c.pkcs11_id == cert_id), None)
        if selected is None:
            selected = certs[0]

        # Obtener clave privada asociada
        try:
            priv_key = self._session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                id=selected.pkcs11_id,
            )
        except Exception as e:
            raise CertificateNotFoundError(f"No se encontró clave privada: {e}")

        # Obtener certificado DER
        cert_obj = list(
            self._session.get_objects(
                {
                    pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE,
                    pkcs11.Attribute.ID: selected.pkcs11_id,
                }
            )
        )[0]
        cert_der = cert_obj[pkcs11.Attribute.VALUE]

        return priv_key, cert_der

    def close(self) -> None:
        """Cierra la sesión con el token."""
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None
        self._token = None
        logger.debug("Sesión con token cerrada")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

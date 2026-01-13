"""
lta_handler.py - Manejador de Long Term Archival (LTV)

Autor: Homero Thompson del Lago del Terror

Gestiona los componentes necesarios para firma PAdES-LTV:
- Timestamp de TSA
- Respuestas OCSP
- Listas CRL
"""

from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from loguru import logger
from pyhanko.sign.timestamps import HTTPTimeStamper

from pdfsigner.config.settings import get_settings
from pdfsigner.exceptions import TSAConnectionError


@dataclass
class TSAConfig:
    """Configuración del servidor de timestamp."""

    url: str
    username: str | None = None
    password: str | None = None
    timeout: int = 30


class LTAHandler:
    """
    Manejador de Long Term Archival.

    Configura y gestiona los servicios necesarios para
    crear firmas PAdES-LTV con validez a largo plazo.
    """

    def __init__(self, tsa_config: TSAConfig | None = None):
        """
        Inicializa el handler LTA.

        Args:
            tsa_config: Configuración TSA (None = desde settings)
        """
        if tsa_config is None:
            settings = get_settings()
            tsa_config = TSAConfig(
                url=settings.tsa_url,
                username=settings.tsa_username,
                password=settings.tsa_password,
            )
        self.tsa_config = tsa_config
        self._timestamper: HTTPTimeStamper | None = None

    def validate_tsa_connection(self) -> bool:
        """
        Valida la conexión con el servidor TSA.

        Returns:
            True si la conexión es válida

        Raises:
            TSAConnectionError: Si no se puede conectar
        """
        if not self.tsa_config.url:
            raise TSAConnectionError("URL de TSA no configurada")

        try:
            # Verificar que la URL es válida
            parsed = urlparse(self.tsa_config.url)
            if not parsed.scheme or not parsed.netloc:
                raise TSAConnectionError(f"URL inválida: {self.tsa_config.url}")

            # Hacer request de prueba (HEAD o GET)
            auth = None
            if self.tsa_config.username and self.tsa_config.password:
                auth = (self.tsa_config.username, self.tsa_config.password)

            response = requests.head(
                self.tsa_config.url,
                auth=auth,
                timeout=self.tsa_config.timeout,
                allow_redirects=True,
            )

            # TSA puede devolver 405 (Method Not Allowed) para HEAD, eso está ok
            if response.status_code not in (200, 405, 400):
                logger.warning(f"TSA respondió con código: {response.status_code}")

            logger.info(f"Conexión TSA validada: {self.tsa_config.url}")
            return True

        except requests.exceptions.ConnectionError as e:
            raise TSAConnectionError(self.tsa_config.url) from e
        except requests.exceptions.Timeout as e:
            raise TSAConnectionError(f"Timeout conectando a TSA: {self.tsa_config.url}") from e

    def get_timestamper(self) -> HTTPTimeStamper:
        """
        Obtiene el timestamper configurado.

        Returns:
            HTTPTimeStamper configurado para el TSA

        Raises:
            TSAConnectionError: Si no hay TSA configurado
        """
        if not self.tsa_config.url:
            raise TSAConnectionError("URL de TSA no configurada")

        if self._timestamper is None:
            auth = None
            if self.tsa_config.username and self.tsa_config.password:
                auth = requests.auth.HTTPBasicAuth(
                    self.tsa_config.username,
                    self.tsa_config.password,
                )

            self._timestamper = HTTPTimeStamper(
                url=self.tsa_config.url,
                https_timeout=self.tsa_config.timeout,
            )

            # Si hay autenticación, configurarla en la sesión
            if auth:
                self._timestamper.session.auth = auth

        return self._timestamper

    def get_validation_context_kwargs(self) -> dict:
        """
        Obtiene kwargs para configurar validación LTV.

        Returns:
            Dict con configuración para ValidationContext
        """
        return {
            "revocation_mode": "require",
            "allow_fetching": True,
        }

    def get_signature_kwargs(self) -> dict:
        """
        Obtiene kwargs para configurar firma PAdES-LTV.

        Returns:
            Dict con configuración para sign_pdf
        """
        kwargs = {}

        # Agregar timestamper si está configurado
        if self.tsa_config.url:
            kwargs["timestamper"] = self.get_timestamper()

        # Configurar embebido de información de revocación
        kwargs["embed_validation_info"] = True

        return kwargs

    @staticmethod
    def get_ltv_profile() -> str:
        """
        Obtiene el perfil de firma para PAdES-LTV.

        Returns:
            Nombre del perfil de firma
        """
        return "PAdES-LTV"

    @staticmethod
    def get_subfilter() -> str:
        """
        Obtiene el subfilter para firma PAdES.

        Returns:
            SubFilter para el campo de firma
        """
        return "ETSI.CAdES.detached"


def create_lta_handler_from_settings() -> LTAHandler:
    """
    Crea un LTAHandler desde la configuración.

    Returns:
        LTAHandler configurado

    Raises:
        TSAConnectionError: Si la configuración es inválida
    """
    settings = get_settings()

    if not settings.tsa_url:
        logger.warning("TSA no configurado, las firmas no incluirán timestamp")
        return LTAHandler(TSAConfig(url=""))

    config = TSAConfig(
        url=settings.tsa_url,
        username=settings.tsa_username,
        password=settings.tsa_password,
    )

    handler = LTAHandler(config)

    # Validar conexión
    try:
        handler.validate_tsa_connection()
    except TSAConnectionError:
        logger.error(f"No se puede conectar al TSA: {settings.tsa_url}")
        raise

    return handler

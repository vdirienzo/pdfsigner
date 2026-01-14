"""
lta_handler.py - Long Term Archival (LTV) handler

Author: Homero Thompson del Lago del Terror

Manages the components necessary for PAdES-LTV signing:
- TSA Timestamp
- OCSP responses
- CRL lists
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
    """Timestamp server configuration."""

    url: str
    username: str | None = None
    password: str | None = None
    timeout: int = 30


class LTAHandler:
    """
    Long Term Archival handler.

    Configures and manages the services necessary to
    create PAdES-LTV signatures with long-term validity.
    """

    def __init__(self, tsa_config: TSAConfig | None = None):
        """
        Initializes the LTA handler.

        Args:
            tsa_config: TSA configuration (None = from settings)
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
        Validates connection to the TSA server.

        Returns:
            True if the connection is valid

        Raises:
            TSAConnectionError: If connection cannot be established
        """
        if not self.tsa_config.url:
            raise TSAConnectionError("TSA URL not configured")

        try:
            # Verify URL is valid
            parsed = urlparse(self.tsa_config.url)
            if not parsed.scheme or not parsed.netloc:
                raise TSAConnectionError(f"Invalid URL: {self.tsa_config.url}")

            # Make test request (HEAD or GET)
            auth = None
            if self.tsa_config.username and self.tsa_config.password:
                auth = (self.tsa_config.username, self.tsa_config.password)

            response = requests.head(
                self.tsa_config.url,
                auth=auth,
                timeout=self.tsa_config.timeout,
                allow_redirects=True,
            )

            # TSA may return 405 (Method Not Allowed) for HEAD, that's ok
            if response.status_code not in (200, 405, 400):
                logger.warning(f"TSA responded with code: {response.status_code}")

            logger.info(f"TSA connection validated: {self.tsa_config.url}")
            return True

        except requests.exceptions.ConnectionError as e:
            raise TSAConnectionError(self.tsa_config.url) from e
        except requests.exceptions.Timeout as e:
            raise TSAConnectionError(f"Timeout connecting to TSA: {self.tsa_config.url}") from e

    def get_timestamper(self) -> HTTPTimeStamper:
        """
        Gets the configured timestamper.

        Returns:
            HTTPTimeStamper configured for the TSA

        Raises:
            TSAConnectionError: If TSA is not configured
        """
        if not self.tsa_config.url:
            raise TSAConnectionError("TSA URL not configured")

        if self._timestamper is None:
            auth = None
            if self.tsa_config.username and self.tsa_config.password:
                auth = requests.auth.HTTPBasicAuth(
                    self.tsa_config.username,
                    self.tsa_config.password,
                )

            self._timestamper = HTTPTimeStamper(
                url=self.tsa_config.url,
                timeout=self.tsa_config.timeout,
                auth=auth,
            )

        return self._timestamper

    def get_validation_context_kwargs(self) -> dict:
        """
        Gets kwargs to configure LTV validation.

        Returns:
            Dict with configuration for ValidationContext
        """
        return {
            "revocation_mode": "require",
            "allow_fetching": True,
        }

    def get_signature_kwargs(self) -> dict:
        """
        Gets kwargs to configure PAdES-LTV signing.

        Returns:
            Dict with configuration for sign_pdf
        """
        kwargs = {}

        # Add timestamper if configured
        if self.tsa_config.url:
            kwargs["timestamper"] = self.get_timestamper()

        # Configure embedding of revocation information
        kwargs["embed_validation_info"] = True

        return kwargs

    @staticmethod
    def get_ltv_profile() -> str:
        """
        Gets the signature profile for PAdES-LTV.

        Returns:
            Signature profile name
        """
        return "PAdES-LTV"

    @staticmethod
    def get_subfilter() -> str:
        """
        Gets the subfilter for PAdES signature.

        Returns:
            SubFilter for the signature field
        """
        return "ETSI.CAdES.detached"


def create_lta_handler_from_settings() -> LTAHandler:
    """
    Creates an LTAHandler from configuration.

    Returns:
        Configured LTAHandler

    Raises:
        TSAConnectionError: If configuration is invalid
    """
    settings = get_settings()

    if not settings.tsa_url:
        logger.warning("TSA not configured, signatures will not include timestamp")
        return LTAHandler(TSAConfig(url=""))

    config = TSAConfig(
        url=settings.tsa_url,
        username=settings.tsa_username,
        password=settings.tsa_password,
    )

    handler = LTAHandler(config)

    # Validate connection
    try:
        handler.validate_tsa_connection()
    except TSAConnectionError:
        logger.error(f"Cannot connect to TSA: {settings.tsa_url}")
        raise

    return handler

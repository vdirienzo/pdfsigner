"""
dss_manager.py - Document Security Store manager for PAdES-LTV signatures

Author: Homero Thompson del Lago del Terror

Manages the embedding of validation information (OCSP responses and CRLs)
into signed PDFs to create PAdES-LTV signatures with long-term validation support.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext

from pdfsigner.core.certificate.revocation_checker import (
    CRLChecker,
    OCSPChecker,
    RevocationStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class ValidationInfo:
    """
    Información de validación recopilada para LTV.

    Attributes:
        ocsp_responses: Lista de respuestas OCSP en formato DER
        crls: Lista de CRLs en formato DER
        certificates: Lista de certificados en formato DER
    """

    ocsp_responses: list[bytes] = field(default_factory=list)
    crls: list[bytes] = field(default_factory=list)
    certificates: list[bytes] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Verifica si no hay información de validación."""
        return not (self.ocsp_responses or self.crls or self.certificates)


class DSSManager:
    """
    Gestor del Document Security Store para firmas PAdES-LTV.

    Recopila y embebe información de validación (OCSP, CRL, certificados)
    en PDFs firmados para permitir la validación a largo plazo.
    """

    # Cache TTL in seconds (5 minutes) - enough for a batch operation
    _CACHE_TTL = 300

    def __init__(
        self,
        ocsp_timeout: int = 10,
        crl_timeout: int = 30,
        prefer_ocsp: bool = True,
    ):
        """
        Inicializa el gestor DSS.

        Args:
            ocsp_timeout: Timeout para peticiones OCSP en segundos
            crl_timeout: Timeout para descarga de CRLs en segundos
            prefer_ocsp: Preferir OCSP sobre CRL (por defecto True)
        """
        self.ocsp_checker = OCSPChecker(timeout=ocsp_timeout)
        self.crl_checker = CRLChecker(timeout=crl_timeout)
        self.prefer_ocsp = prefer_ocsp
        # In-memory caches for batch operations: {key: (response_bytes, timestamp)}
        self._ocsp_cache: dict[str, tuple[bytes, float]] = {}
        self._crl_cache: dict[str, tuple[bytes, float]] = {}

    def collect_validation_info(
        self,
        cert_chain: list[x509.Certificate],
    ) -> ValidationInfo:
        """
        Recopila información de validación para toda la cadena de certificados.

        Obtiene respuestas OCSP y CRLs para cada certificado en la cadena,
        permitiendo la validación a largo plazo del PDF firmado.

        Args:
            cert_chain: Lista de certificados (del certificado de firma al root)

        Returns:
            ValidationInfo con respuestas OCSP, CRLs y certificados
        """
        validation_info = ValidationInfo()

        logger.info(f"Recopilando información de validación para {len(cert_chain)} certificados")

        # Agregar certificados en formato DER
        for cert in cert_chain:
            try:
                cert_der = cert.public_bytes(Encoding.DER)
                validation_info.certificates.append(cert_der)
            except Exception as e:
                logger.warning(f"Error serializando certificado: {e}")

        # Obtener información de revocación para cada certificado
        for i, cert in enumerate(cert_chain[:-1]):  # Excluir root
            issuer_cert = cert_chain[i + 1] if i + 1 < len(cert_chain) else None

            if self.prefer_ocsp and issuer_cert:
                # Intentar OCSP primero
                ocsp_response = self._get_ocsp_response_bytes(cert, issuer_cert)
                if ocsp_response:
                    validation_info.ocsp_responses.append(ocsp_response)
                    logger.debug(f"Respuesta OCSP obtenida para certificado {i}")
                    continue

            # Fallback a CRL o si OCSP no está disponible
            crl_bytes = self._get_crl_bytes(cert)
            if crl_bytes:
                validation_info.crls.append(crl_bytes)
                logger.debug(f"CRL obtenida para certificado {i}")
            else:
                logger.warning(f"No se pudo obtener información de revocación para certificado {i}")

        logger.info(
            f"Información recopilada: {len(validation_info.ocsp_responses)} OCSP, "
            f"{len(validation_info.crls)} CRLs, {len(validation_info.certificates)} certs"
        )

        return validation_info

    def _get_ocsp_response_bytes(
        self, cert: x509.Certificate, issuer_cert: x509.Certificate
    ) -> bytes | None:
        """
        Obtiene respuesta OCSP en formato DER, with in-memory caching.

        Uses a TTL cache keyed by (cert_serial_hash, responder_url) to avoid
        repeated network requests during batch signing operations.

        Args:
            cert: Certificado a verificar
            issuer_cert: Certificado emisor

        Returns:
            Respuesta OCSP en bytes DER o None si falla
        """
        try:
            # Obtener URL del responder OCSP
            responder_url = self._get_ocsp_responder_url(cert)
            if not responder_url:
                logger.debug("No se encontró URL de responder OCSP en el certificado")
                return None

            # Check cache before making network request
            cache_key = self._ocsp_cache_key(cert, responder_url)
            cached = self._ocsp_cache.get(cache_key)
            if cached is not None:
                response_bytes, cached_at = cached
                if (time.monotonic() - cached_at) < self._CACHE_TTL:
                    logger.debug(f"OCSP cache hit for {cache_key[:16]}...")
                    return response_bytes
                del self._ocsp_cache[cache_key]

            # Construir petición OCSP
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
            ocsp_request = builder.build()

            # Enviar petición
            ocsp_request_der = ocsp_request.public_bytes(Encoding.DER)
            headers = {"Content-Type": "application/ocsp-request"}

            response = requests.post(
                responder_url,
                data=ocsp_request_der,
                headers=headers,
                timeout=self.ocsp_checker.timeout,
            )
            response.raise_for_status()

            # Validar respuesta
            ocsp_response = ocsp.load_der_ocsp_response(response.content)
            if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                self._ocsp_cache[cache_key] = (response.content, time.monotonic())
                return response.content

            logger.warning(f"Respuesta OCSP no exitosa: {ocsp_response.response_status.name}")
            return None

        except Exception as e:
            logger.warning(f"Error obteniendo respuesta OCSP: {e}")
            return None

    def _get_crl_bytes(self, cert: x509.Certificate) -> bytes | None:
        """
        Obtiene CRL en formato DER, with in-memory caching.

        Uses a TTL cache keyed by CRL URL to avoid repeated downloads
        during batch signing operations.

        Args:
            cert: Certificado del cual obtener la CRL

        Returns:
            CRL en bytes DER o None si falla
        """
        try:
            # Obtener URLs de distribución de CRL
            crl_urls = self._get_crl_urls(cert)
            if not crl_urls:
                logger.debug("No se encontraron puntos de distribución de CRL")
                return None

            # Intentar descargar de cada URL
            for crl_url in crl_urls:
                try:
                    # Check cache before downloading
                    cached = self._crl_cache.get(crl_url)
                    if cached is not None:
                        crl_bytes, cached_at = cached
                        if (time.monotonic() - cached_at) < self._CACHE_TTL:
                            logger.debug(f"CRL cache hit for {crl_url}")
                            return crl_bytes
                        del self._crl_cache[crl_url]

                    logger.debug(f"Descargando CRL desde {crl_url}")
                    response = requests.get(crl_url, timeout=self.crl_checker.timeout)
                    response.raise_for_status()

                    # Validar que es una CRL válida
                    x509.load_der_x509_crl(response.content)
                    self._crl_cache[crl_url] = (response.content, time.monotonic())
                    return response.content

                except Exception as e:
                    logger.warning(f"Error descargando CRL desde {crl_url}: {e}")
                    continue

            logger.warning("Todas las URLs de distribución de CRL fallaron")
            return None

        except Exception as e:
            logger.warning(f"Error obteniendo CRL: {e}")
            return None

    @staticmethod
    def _ocsp_cache_key(cert: x509.Certificate, responder_url: str) -> str:
        """Generate a cache key for OCSP responses from cert serial + responder URL."""
        serial = str(cert.serial_number).encode()
        return hashlib.sha256(serial + responder_url.encode()).hexdigest()

    def _get_ocsp_responder_url(self, cert: x509.Certificate) -> str | None:
        """
        Extrae URL del responder OCSP del certificado.

        Args:
            cert: Certificado

        Returns:
            URL del responder OCSP o None
        """
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            aia = aia_ext.value

            for access_description in aia:  # type: ignore[attr-defined]
                if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                    return access_description.access_location.value

        except x509.ExtensionNotFound:
            logger.debug("No se encontró extensión Authority Information Access")
        except Exception as e:
            logger.error(f"Error extrayendo URL OCSP: {e}")

        return None

    def _get_crl_urls(self, cert: x509.Certificate) -> list[str]:
        """
        Extrae URLs de puntos de distribución de CRL del certificado.

        Args:
            cert: Certificado

        Returns:
            Lista de URLs de CRL
        """
        urls: list[str] = []
        try:
            crl_dist_points_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            crl_dist_points = crl_dist_points_ext.value

            for dist_point in crl_dist_points:  # type: ignore[attr-defined]
                if dist_point.full_name:
                    for general_name in dist_point.full_name:
                        if isinstance(general_name, x509.UniformResourceIdentifier):
                            urls.append(general_name.value)

        except x509.ExtensionNotFound:
            logger.debug("No se encontró extensión CRL Distribution Points")
        except Exception as e:
            logger.error(f"Error extrayendo URLs de CRL: {e}")

        return urls

    def embed_dss(
        self,
        pdf_path: Path,
        validation_info: ValidationInfo,
        output_path: Path | None = None,
    ) -> Path:
        """
        Embebe el DSS dictionary en un PDF firmado.

        Agrega la información de validación (OCSP, CRL, certificados) al PDF
        para permitir la validación LTV (Long Term Validation).

        Args:
            pdf_path: Ruta al PDF firmado
            validation_info: Información de validación a embeber
            output_path: Ruta de salida (por defecto sobrescribe el original)

        Returns:
            Ruta al PDF con DSS embebido

        Raises:
            ValueError: Si validation_info está vacío
            FileNotFoundError: Si el PDF no existe
            RuntimeError: Si falla el proceso de embedding
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF no encontrado: {pdf_path}")

        if validation_info.is_empty():
            raise ValueError("ValidationInfo está vacío, no hay nada que embeber")

        if output_path is None:
            output_path = pdf_path

        logger.info(f"Embebiendo DSS en {pdf_path}")

        try:
            import shutil
            import tempfile

            from asn1crypto import x509 as asn1_x509

            # Convertir bytes DER a objetos asn1crypto.x509.Certificate
            certs_as_objects = [
                asn1_x509.Certificate.load(cert_der) for cert_der in validation_info.certificates
            ]

            # Usar archivo temporal para evitar corrupción por escritura in-place
            # Esto previene problemas de xref cuando se modifica el archivo original
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
                tmp_path = Path(tmp_file.name)

            # Copiar el PDF original al temporal
            shutil.copy2(pdf_path, tmp_path)

            # Aplicar DSS al archivo temporal
            with open(tmp_path, "rb+") as f:
                DocumentSecurityStore.add_dss(
                    output_stream=f,
                    sig_contents=None,  # Sin VRI específico por firma
                    certs=certs_as_objects,
                    ocsps=validation_info.ocsp_responses,
                    crls=validation_info.crls,
                    force_write=True,
                    strict=False,
                )

            # Reemplazar el archivo original con el temporal
            shutil.move(str(tmp_path), str(output_path))

            logger.info(f"DSS embebido exitosamente en {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error embebiendo DSS: {e}")
            raise RuntimeError(f"Fallo al embeber DSS: {str(e)}") from e

    def build_validation_context(
        self,
        trust_roots: list[x509.Certificate] | None = None,
        validation_info: ValidationInfo | None = None,
    ) -> ValidationContext:
        """
        Construye un ValidationContext para firma con LTV.

        Configura el contexto de validación con información de revocación
        y certificados de confianza para pyHanko.

        Args:
            trust_roots: Lista de certificados raíz de confianza
            validation_info: Información de validación pre-recopilada

        Returns:
            ValidationContext configurado para LTV
        """
        # Convertir certificados cryptography a DER para ValidationContext
        trust_roots_der = None
        if trust_roots:
            trust_roots_der = [cert.public_bytes(Encoding.DER) for cert in trust_roots]

        kwargs = {
            "trust_roots": trust_roots_der,
            "allow_fetching": True,  # Permitir descarga de OCSP/CRL si es necesario
            "revocation_mode": "require",  # Requiere verificación de revocación
        }

        # Agregar información de validación si está disponible
        if validation_info:
            if validation_info.ocsp_responses:
                kwargs["ocsps"] = validation_info.ocsp_responses
            if validation_info.crls:
                kwargs["crls"] = validation_info.crls
            if validation_info.certificates:
                kwargs["other_certs"] = validation_info.certificates

        try:
            context = ValidationContext(**kwargs)
            logger.debug("ValidationContext creado para LTV")
            return context
        except Exception as e:
            logger.error(f"Error creando ValidationContext: {e}")
            raise

    def verify_revocation_status(
        self,
        cert_chain: list[x509.Certificate],
    ) -> bool:
        """
        Verifica el estado de revocación de toda la cadena de certificados.

        Args:
            cert_chain: Lista de certificados a verificar

        Returns:
            True si todos los certificados son válidos (no revocados)
        """
        logger.info(f"Verificando estado de revocación para {len(cert_chain)} certificados")

        for i, cert in enumerate(cert_chain[:-1]):  # Excluir root
            issuer_cert = cert_chain[i + 1] if i + 1 < len(cert_chain) else None

            # Usar RevocationChecker interno
            if self.prefer_ocsp and issuer_cert:
                result = self.ocsp_checker.check(cert, issuer_cert)
                if result.status == RevocationStatus.REVOKED:
                    logger.error(f"Certificado {i} está REVOCADO: {result.revocation_reason}")
                    return False
                elif result.status == RevocationStatus.GOOD:
                    logger.debug(f"Certificado {i} es válido (OCSP)")
                    continue

            # Fallback a CRL
            result = self.crl_checker.check(cert)
            if result.status == RevocationStatus.REVOKED:
                logger.error(f"Certificado {i} está REVOCADO: {result.revocation_reason}")
                return False
            elif result.status == RevocationStatus.GOOD:
                logger.debug(f"Certificado {i} es válido (CRL)")
            else:
                logger.warning(f"No se pudo verificar certificado {i}: {result.error_message}")

        logger.info("Todos los certificados son válidos (no revocados)")
        return True

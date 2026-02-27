"""
dss_manager.py - Document Security Store manager for PAdES-LTV signatures

Author: Homero Thompson del Lago del Terror

Manages the embedding of validation information (OCSP responses and CRLs)
into signed PDFs to create PAdES-LTV signatures with long-term validation support.
"""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from loguru import logger
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext

from pdfsigner.core.certificate.revocation_checker import (
    CRLChecker,
    OCSPChecker,
    RevocationStatus,
)

# Re-export for backward compatibility
from pdfsigner.core.signer.dss_types import ValidationInfo  # noqa: F401


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
                cert_subject = getattr(cert, "subject", "unknown")
                logger.warning(
                    f"Failed to serialize certificate (subject={cert_subject}): {e}. "
                    "Skipping this certificate in DSS embedding."
                )

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
        """Obtiene respuesta OCSP en formato DER, with in-memory caching.

        Args:
            cert: Certificado a verificar
            issuer_cert: Certificado emisor

        Returns:
            Respuesta OCSP en bytes DER o None si falla
        """
        from pdfsigner.core.signer.dss_helpers import (
            check_ocsp_cache,
            fetch_ocsp_response,
            get_ocsp_responder_url,
            ocsp_cache_key,
        )

        try:
            responder_url = get_ocsp_responder_url(cert)
            if not responder_url:
                logger.debug("No se encontro URL de responder OCSP en el certificado")
                return None

            cache_key = ocsp_cache_key(cert, responder_url)
            cached = check_ocsp_cache(self._ocsp_cache, cache_key, self._CACHE_TTL)
            if cached is not None:
                return cached

            return fetch_ocsp_response(
                cert,
                issuer_cert,
                responder_url,
                self.ocsp_checker.timeout,
                self._ocsp_cache,
                cache_key,
            )

        except Exception as e:
            logger.warning(f"Error obteniendo respuesta OCSP: {e}")
            return None

    def _get_crl_bytes(self, cert: x509.Certificate) -> bytes | None:
        """Obtiene CRL en formato DER, with in-memory caching.

        Args:
            cert: Certificado del cual obtener la CRL

        Returns:
            CRL en bytes DER o None si falla
        """
        from pdfsigner.core.signer.dss_helpers import get_crl_bytes

        return get_crl_bytes(cert, self.crl_checker.timeout, self._crl_cache, self._CACHE_TTL)

    def embed_dss(
        self,
        pdf_path: Path,
        validation_info: ValidationInfo,
        output_path: Path | None = None,
    ) -> Path:
        """Embebe el DSS dictionary en un PDF firmado.

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
        self._validate_embed_inputs(pdf_path, validation_info)
        if output_path is None:
            output_path = pdf_path

        logger.info(f"Embebiendo DSS en {pdf_path}")

        try:
            tmp_path = self._prepare_temp_pdf(pdf_path)
            self._apply_dss_to_file(tmp_path, validation_info)
            self._finalize_output(tmp_path, output_path)

            logger.info(f"DSS embebido exitosamente en {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error embebiendo DSS: {e}")
            raise RuntimeError(f"Fallo al embeber DSS: {str(e)}") from e

    @staticmethod
    def _validate_embed_inputs(pdf_path: Path, validation_info: ValidationInfo) -> None:
        """Validate inputs for embed_dss."""
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF no encontrado: {pdf_path}")
        if validation_info.is_empty():
            raise ValueError("ValidationInfo está vacío, no hay nada que embeber")

    @staticmethod
    def _prepare_temp_pdf(pdf_path: Path) -> Path:
        """Copy PDF to a temporary file for safe in-place modification."""
        import shutil
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            tmp_path = Path(tmp_file.name)
        shutil.copy2(pdf_path, tmp_path)
        return tmp_path

    @staticmethod
    def _apply_dss_to_file(tmp_path: Path, validation_info: ValidationInfo) -> None:
        """Apply DSS dictionary to the temporary PDF file."""
        from asn1crypto import x509 as asn1_x509

        certs_as_objects = [
            asn1_x509.Certificate.load(cert_der) for cert_der in validation_info.certificates
        ]

        with open(tmp_path, "rb+") as f:
            DocumentSecurityStore.add_dss(
                output_stream=f,
                sig_contents=None,
                certs=certs_as_objects,
                ocsps=validation_info.ocsp_responses,
                crls=validation_info.crls,
                force_write=True,
                strict=False,
            )

    @staticmethod
    def _finalize_output(tmp_path: Path, output_path: Path) -> None:
        """Move temporary file to final output path."""
        import shutil

        shutil.move(str(tmp_path), str(output_path))

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

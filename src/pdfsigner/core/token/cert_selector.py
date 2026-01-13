"""
cert_selector.py - Selector de certificados del token

Autor: Homero Thompson del Lago del Terror

Filtra y selecciona certificados válidos para firma digital
del token USB SafeNet.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import CertificateExpiredError, CertificateNotFoundError


@dataclass
class ValidCertificate:
    """Certificado validado y listo para usar."""

    info: CertificateInfo
    days_until_expiry: int
    is_expiring_soon: bool  # Menos de 30 días

    @property
    def display_name(self) -> str:
        """Nombre para mostrar al usuario."""
        # Extraer CN del subject
        subject = self.info.subject
        cn_parts = [p for p in subject.split(",") if p.strip().startswith("CN=")]
        if cn_parts:
            return cn_parts[0].split("=")[1].strip()
        return self.info.label


class CertificateSelector:
    """
    Selector de certificados para firma.

    Filtra certificados válidos (no expirados, con keyUsage correcto)
    y permite selección por el usuario si hay múltiples.
    """

    EXPIRING_SOON_DAYS = 30

    def __init__(self, nss_handler: NSSHandler):
        """
        Inicializa el selector.

        Args:
            nss_handler: Handler de NSS autenticado
        """
        self.nss_handler = nss_handler

    def get_valid_certificates(self) -> list[ValidCertificate]:
        """
        Obtiene certificados válidos para firma.

        Returns:
            Lista de certificados válidos ordenados por fecha de expiración

        Raises:
            CertificateNotFoundError: Si no hay certificados válidos
        """
        all_certs = self.nss_handler.list_certificates()
        valid_certs = []
        now = datetime.now(UTC)

        for cert_info in all_certs:
            # Filtrar solo certificados de firma
            if not cert_info.can_sign:
                logger.debug(f"Certificado '{cert_info.label}' no puede firmar, ignorado")
                continue

            # Verificar expiración
            try:
                not_after = datetime.fromisoformat(cert_info.not_after)
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=UTC)

                if not_after < now:
                    logger.warning(f"Certificado '{cert_info.label}' expirado")
                    continue

                days_until_expiry = (not_after - now).days
                is_expiring_soon = days_until_expiry <= self.EXPIRING_SOON_DAYS

                if is_expiring_soon:
                    logger.warning(
                        f"Certificado '{cert_info.label}' expira en {days_until_expiry} días"
                    )

                valid_cert = ValidCertificate(
                    info=cert_info,
                    days_until_expiry=days_until_expiry,
                    is_expiring_soon=is_expiring_soon,
                )
                valid_certs.append(valid_cert)

            except (ValueError, TypeError) as e:
                logger.warning(f"Error procesando fecha de certificado: {e}")
                continue

        if not valid_certs:
            raise CertificateNotFoundError("No hay certificados válidos para firma")

        # Ordenar por fecha de expiración (más lejana primero)
        valid_certs.sort(key=lambda c: c.days_until_expiry, reverse=True)

        logger.info(f"Encontrados {len(valid_certs)} certificados válidos para firma")
        return valid_certs

    def get_default_certificate(self) -> ValidCertificate:
        """
        Obtiene el certificado por defecto (el de mayor validez).

        Returns:
            Certificado por defecto

        Raises:
            CertificateNotFoundError: Si no hay certificados válidos
        """
        valid_certs = self.get_valid_certificates()
        return valid_certs[0]

    def select_by_label(self, label: str) -> ValidCertificate:
        """
        Selecciona un certificado por su etiqueta.

        Args:
            label: Etiqueta del certificado

        Returns:
            Certificado seleccionado

        Raises:
            CertificateNotFoundError: Si no se encuentra el certificado
        """
        valid_certs = self.get_valid_certificates()

        for cert in valid_certs:
            if cert.info.label == label:
                return cert

        raise CertificateNotFoundError(f"Certificado '{label}' no encontrado o no válido")

    def validate_certificate(self, cert: ValidCertificate, allow_expiring: bool = True) -> None:
        """
        Valida un certificado antes de usarlo.

        Args:
            cert: Certificado a validar
            allow_expiring: Permitir certificados próximos a expirar

        Raises:
            CertificateExpiredError: Si el certificado expiró
            CertificateNotFoundError: Si el certificado no es válido para firma
        """
        if cert.days_until_expiry <= 0:
            raise CertificateExpiredError(cert.display_name, cert.info.not_after)

        if not allow_expiring and cert.is_expiring_soon:
            raise CertificateExpiredError(
                cert.display_name,
                f"expira en {cert.days_until_expiry} días ({cert.info.not_after})",
            )

        if not cert.info.can_sign:
            raise CertificateNotFoundError(
                f"Certificado '{cert.display_name}' no tiene permiso de firma"
            )

        logger.debug(f"Certificado '{cert.display_name}' validado correctamente")
